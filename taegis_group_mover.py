#!/usr/bin/env python3
"""
taegis_group_mover.py

Move a list of Taegis XDR endpoint assets (identified by hostname) into a
chosen endpoint (host) group.

Only uses the Python standard library (urllib, json, argparse, getpass) -
no third-party packages required.

WORKFLOW
--------
1. Authenticate to the Taegis XDR GraphQL API using client credentials
   supplied on the command line or via a JSON config file.
   - If credentials were supplied on the command line and auth succeeds,
     you'll be asked whether to save them to a config file for next time.
2. Read a text file of hostnames (one per line, blank lines ignored,
   ASCII only).
3. Look up each hostname individually against the Assets API, showing its
   current endpoint group (or "NOT FOUND" if no asset matches).
4. List the endpoint groups currently known to the tenant and let you pick
   one as the destination (or cancel).
5. Move every host that was found into the chosen group with a single
   bulk API call, then poll for the job result.
6. Print a summary.

AUTHENTICATION
--------------
You need a Taegis API client_id/client_secret (Tenant Settings -> Manage
API Credentials in the XDR UI). See:
https://docs.taegis.secureworks.com/apis/api_authenticate/

Command line:
    python taegis_group_mover.py --client-id XXX --client-secret YYY \
        --region us1 --hosts-file hosts.txt

Config file (JSON):
    {
        "client_id": "XXX",
        "client_secret": "YYY",
        "region": "us1",
        "tenant_id": "optional tenant id"
    }

    python taegis_group_mover.py --config taegis_config.json --hosts-file hosts.txt

Regions: us1 (default), us2, us3, eu1, eu2. Use --base-url instead of
--region if you need to point at a non-standard endpoint.
"""

import argparse
import base64
import getpass
import json
import os
import stat
import sys
import time
import urllib.error
import urllib.request

REGIONS = {
    "us1": "https://api.ctpx.secureworks.com",
    "us2": "https://api.delta.taegis.secureworks.com",
    "us3": "https://api.foxtrot.taegis.secureworks.com",
    "eu1": "https://api.echo.taegis.secureworks.com",
    "eu2": "https://api.golf.taegis.secureworks.com",
}

REQUEST_TIMEOUT = 30
POLL_INTERVAL_SECONDS = 2
POLL_MAX_ATTEMPTS = 20
TERMINAL_STATUS_HINTS = ("pending", "progress", "queue", "running", "start")

CHECK_ASSET_QUERY = """
query CheckAsset($hostname: String!) {
  assetsV2(first: 5, filter: { where: { hostname: $hostname } }) {
    totalCount
    assets {
      id
      hostId
      endpointType
      endpointGroup { id name }
      hostnames { hostname }
    }
  }
}
"""

# Maps the raw endpointType value returned by the API to a friendly sensor
# name. Unrecognized values are shown as-is (see sensor_label()).
SENSOR_TYPE_LABELS = {
    "ENDPOINT_REDCLOAK": "Taegis",
    "ENDPOINT_CARBON_BLACK": "Carbon Black",
    "ENDPOINT_CARBON_BLACK_PSC": "Carbon Black",
    "ENDPOINT_CROWD_STRIKE": "CrowdStrike",
    "ENDPOINT_MICROSOFT_ATP": "Microsoft Defender",
    "ENDPOINT_SENTINEL_ONE": "SentinelOne",
    "ENDPOINT_SOPHOS": "Sophos",
}

# Substrings (checked case-insensitively) that identify a native Taegis
# agent. Only these assets can be moved between endpoint groups; other
# sensor types are reported but skipped.
TAEGIS_SENSOR_HINTS = ("redcloak", "taegis")


def sensor_label(endpoint_type):
    if not endpoint_type:
        return "unknown"
    return SENSOR_TYPE_LABELS.get(endpoint_type, endpoint_type)


def is_taegis_sensor(endpoint_type):
    if not endpoint_type:
        return False
    lowered = endpoint_type.lower()
    return any(hint in lowered for hint in TAEGIS_SENSOR_HINTS)

GROUP_FACET_QUERY = """
query GroupFacets($facets: [String!]!) {
  facetInfoV2(facets: $facets) {
    facet
    fields { field count }
  }
}
"""

RESOLVE_GROUP_QUERY = """
query ResolveGroup($groupName: String!) {
  assetsV2(first: 1, filter: { where: { groupName: $groupName } }) {
    assets { endpointGroup { id name } }
  }
}
"""

ASSIGN_MUTATION = """
mutation AssignAssetsToGroup($input: AssignBulkAssetsToGroupInput!) {
  assignBulkAssetsToGroup(input: $input) {
    id
    status
  }
}
"""

ASSIGN_STATUS_QUERY = """
query AssignStatus($id: ID!) {
  assignBulkAssetsToGroupStatus(id: $id) {
    id
    status
    metadata {
      numEndpoints
      numSucceeded
      numFailed
      syncSucceeded
    }
  }
}
"""


class TaegisError(Exception):
    pass


# ---------------------------------------------------------------------------
# HTTP / GraphQL helpers
# ---------------------------------------------------------------------------

def authenticate(base_url, client_id, client_secret):
    """Exchange client_id/client_secret for a bearer access token."""
    url = base_url.rstrip("/") + "/auth/api/v2/auth/token"
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
    headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/json"}
    body = json.dumps({"grant_type": "client_credentials"}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise TaegisError(f"Authentication failed (HTTP {e.code}): {err_body}")
    except urllib.error.URLError as e:
        raise TaegisError(f"Network error during authentication: {e}")

    token = payload.get("access_token")
    if not token:
        raise TaegisError(f"Authentication response did not include an access_token: {payload}")
    return token


def graphql_request(base_url, token, query, variables=None, tenant_id=None):
    url = base_url.rstrip("/") + "/graphql"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    if tenant_id:
        headers["X-Tenant-Context"] = tenant_id
    body = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise TaegisError(f"HTTP {e.code} calling Taegis API: {err_body}")
    except urllib.error.URLError as e:
        raise TaegisError(f"Network error calling Taegis API: {e}")

    if payload.get("errors"):
        raise TaegisError("Taegis API returned errors: " + json.dumps(payload["errors"]))
    return payload.get("data") or {}


# ---------------------------------------------------------------------------
# Config file handling
# ---------------------------------------------------------------------------

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(path, client_id, client_secret, region, base_url, tenant_id):
    data = {"client_id": client_id, "client_secret": client_secret}
    if region:
        data["region"] = region
    if base_url:
        data["base_url"] = base_url
    if tenant_id:
        data["tenant_id"] = tenant_id
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass  # best effort; not all platforms support chmod semantics


# ---------------------------------------------------------------------------
# Hostname file handling
# ---------------------------------------------------------------------------

def read_hostnames_file(path):
    hostnames = []
    with open(path, "r", encoding="utf-8", errors="strict") as f:
        for lineno, raw_line in enumerate(f, start=1):
            if any(ord(c) > 127 for c in raw_line):
                print(f"  [skip] line {lineno}: contains non-ASCII characters")
                continue
            line = raw_line.strip()
            if not line:
                continue
            hostnames.append(line)
    return hostnames


# ---------------------------------------------------------------------------
# Taegis operations
# ---------------------------------------------------------------------------

def check_asset(base_url, token, tenant_id, hostname):
    data = graphql_request(base_url, token, CHECK_ASSET_QUERY, {"hostname": hostname}, tenant_id)
    block = data.get("assetsV2") or {}
    assets = block.get("assets") or []
    if not assets:
        return None
    if len(assets) > 1:
        print(f"  [note] {hostname}: {len(assets)} assets matched, using the first one")
    asset = assets[0]
    group = asset.get("endpointGroup")
    endpoint_type = asset.get("endpointType")
    return {
        "hostname": hostname,
        "asset_id": asset.get("id"),
        "host_id": asset.get("hostId"),
        "group_id": group.get("id") if group else None,
        "group_name": group.get("name") if group else None,
        "endpoint_type": endpoint_type,
        "is_taegis": is_taegis_sensor(endpoint_type),
    }


def list_groups(base_url, token, tenant_id):
    data = graphql_request(base_url, token, GROUP_FACET_QUERY, {"facets": ["groupName"]}, tenant_id)
    facet_info = data.get("facetInfoV2")
    # The API may return either a single facet-info object or a list of them
    # depending on backend version; handle both shapes defensively.
    if isinstance(facet_info, list):
        facet_infos = facet_info
    elif facet_info:
        facet_infos = [facet_info]
    else:
        facet_infos = []

    fields = []
    for info in facet_infos:
        if info and info.get("facet") in (None, "groupName"):
            fields.extend(info.get("fields") or [])

    groups = [(f["field"], f.get("count", 0)) for f in fields if f.get("field")]
    groups.sort(key=lambda g: g[0].lower())
    return groups


def resolve_group_id(base_url, token, tenant_id, group_name):
    data = graphql_request(base_url, token, RESOLVE_GROUP_QUERY, {"groupName": group_name}, tenant_id)
    assets = (data.get("assetsV2") or {}).get("assets") or []
    if not assets:
        return None
    group = assets[0].get("endpointGroup")
    return group.get("id") if group else None


def assign_assets_to_group(base_url, token, tenant_id, asset_ids, group_id):
    filter_input = {"where": {"or": [{"id": aid} for aid in asset_ids]}}
    variables = {"input": {"groupId": group_id, "filter": filter_input}}
    data = graphql_request(base_url, token, ASSIGN_MUTATION, variables, tenant_id)
    return data["assignBulkAssetsToGroup"]


def poll_assignment_status(base_url, token, tenant_id, task_id):
    last = None
    for _ in range(POLL_MAX_ATTEMPTS):
        time.sleep(POLL_INTERVAL_SECONDS)
        data = graphql_request(base_url, token, ASSIGN_STATUS_QUERY, {"id": task_id}, tenant_id)
        last = data.get("assignBulkAssetsToGroupStatus") or {}
        status_text = (last.get("status") or "").lower()
        if status_text and not any(hint in status_text for hint in TERMINAL_STATUS_HINTS):
            return last
    return last


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Move Taegis XDR assets (by hostname) into an endpoint group.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", help="Path to a JSON config file with Taegis API credentials")
    parser.add_argument("--client-id", help="Taegis API client_id")
    parser.add_argument("--client-secret", help="Taegis API client_secret (omit to be prompted)")
    parser.add_argument("--region", choices=sorted(REGIONS.keys()), help="Taegis region shortcut")
    parser.add_argument("--base-url", help="Explicit Taegis API base URL (overrides --region)")
    parser.add_argument("--tenant-id", help="Optional tenant ID (sent as X-Tenant-Context)")
    parser.add_argument("--hosts-file", required=True, help="Path to a text file of hostnames, one per line")
    parser.add_argument(
        "--save-config-path",
        default="taegis_config.json",
        help="Default path offered when saving credentials (default: taegis_config.json)",
    )
    return parser.parse_args()


def prompt_yes_no(question, default_no=True):
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    answer = input(question + suffix).strip().lower()
    if not answer:
        return not default_no
    return answer in ("y", "yes")


def main():
    args = parse_args()

    cfg = {}
    if args.config:
        try:
            cfg = load_config(args.config)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Could not read config file {args.config}: {e}", file=sys.stderr)
            return 1

    creds_from_cli = not args.config

    client_id = args.client_id or cfg.get("client_id")
    client_secret = args.client_secret or cfg.get("client_secret")
    region = args.region or cfg.get("region")
    base_url = args.base_url or cfg.get("base_url") or (REGIONS.get(region) if region else None)
    tenant_id = args.tenant_id or cfg.get("tenant_id")

    if not client_id:
        print("Error: no client_id provided (--client-id or config file).", file=sys.stderr)
        return 1
    if not client_secret:
        client_secret = getpass.getpass("Taegis client_secret: ")
    if not base_url:
        print("Error: no region/base URL provided (--region or --base-url or config file).", file=sys.stderr)
        return 1

    print(f"Authenticating to {base_url} ...")
    try:
        token = authenticate(base_url, client_id, client_secret)
    except TaegisError as e:
        print(f"Authentication failed: {e}", file=sys.stderr)
        return 1
    print("Authentication succeeded.")

    if creds_from_cli:
        if prompt_yes_no("Save these credentials to a config file for next time?"):
            path = input(f"Config file path [{args.save_config_path}]: ").strip() or args.save_config_path
            save_config(path, client_id, client_secret, region, args.base_url, tenant_id)
            print(f"Saved credentials to {path} (keep this file secure).")

    try:
        hostnames = read_hostnames_file(args.hosts_file)
    except OSError as e:
        print(f"Could not read hosts file {args.hosts_file}: {e}", file=sys.stderr)
        return 1

    print(f"\nLoaded {len(hostnames)} hostname(s) from {args.hosts_file}.\n")
    if not hostnames:
        print("Nothing to do.")
        return 0

    print("Checking assets...")
    print("Note: only native Taegis agents can be moved between endpoint groups.")
    print("Assets on other sensors (Sophos, CrowdStrike, SentinelOne, Defender, etc.) will be listed but skipped.\n")

    found = []          # Taegis assets - eligible to move
    skipped_sensor = []  # found, but not a Taegis agent - not eligible
    not_found = []
    for hostname in hostnames:
        try:
            result = check_asset(base_url, token, tenant_id, hostname)
        except TaegisError as e:
            print(f"  [error] {hostname}: {e}")
            not_found.append(hostname)
            continue

        if result is None:
            print(f"  {hostname}: NOT FOUND")
            not_found.append(hostname)
        else:
            group_label = result["group_name"] or "(no group assigned)"
            sensor = sensor_label(result["endpoint_type"])
            line = (
                f"  {hostname}: asset {result['host_id']}, current group: {group_label}, "
                f"sensor: {sensor}"
            )
            if result["is_taegis"]:
                print(line)
                found.append(result)
            else:
                print(line + "  [not Taegis - will NOT be moved]")
                skipped_sensor.append(result)

    print(
        f"\nSummary of lookup: {len(hostnames)} input, "
        f"{len(found) + len(skipped_sensor)} found, {len(not_found)} not found "
        f"({len(skipped_sensor)} found but skipped - non-Taegis sensor)."
    )

    if not found:
        print("No Taegis assets to move. Exiting.")
        return 0

    print("\nFetching available endpoint groups...")
    try:
        groups = list_groups(base_url, token, tenant_id)
    except TaegisError as e:
        print(f"Could not list endpoint groups: {e}", file=sys.stderr)
        return 1

    if not groups:
        print("No endpoint groups were found for this tenant. Exiting.")
        return 1

    print("\nAvailable endpoint groups:")
    for idx, (name, count) in enumerate(groups, start=1):
        print(f"  {idx}) {name}  ({count} asset(s))")
    print("  0) Cancel")

    choice = None
    while choice is None:
        raw = input(f"\nSelect target group [0-{len(groups)}]: ").strip()
        if not raw.isdigit():
            print("Please enter a number.")
            continue
        num = int(raw)
        if num == 0:
            print("Cancelled. No assets were moved.")
            print(
                f"\nFinal summary: {len(hostnames)} input, {len(not_found)} not found, "
                f"{len(skipped_sensor)} skipped (non-Taegis sensor), "
                f"{len(found)} Taegis assets found but NOT moved (cancelled)."
            )
            return 0
        if 1 <= num <= len(groups):
            choice = num
        else:
            print("Out of range.")

    target_group_name = groups[choice - 1][0]

    if not prompt_yes_no(
        f"Move {len(found)} Taegis host(s) into group '{target_group_name}'?", default_no=True
    ):
        print("Cancelled. No assets were moved.")
        print(
            f"\nFinal summary: {len(hostnames)} input, {len(not_found)} not found, "
            f"{len(skipped_sensor)} skipped (non-Taegis sensor), "
            f"{len(found)} Taegis assets found but NOT moved (cancelled)."
        )
        return 0

    target_group_id = resolve_group_id(base_url, token, tenant_id, target_group_name)
    if not target_group_id:
        print(f"Could not resolve group ID for '{target_group_name}'.", file=sys.stderr)
        return 1

    asset_ids = [r["asset_id"] for r in found]
    print(f"\nSubmitting move of {len(asset_ids)} asset(s) to group '{target_group_name}'...")
    try:
        job = assign_assets_to_group(base_url, token, tenant_id, asset_ids, target_group_id)
    except TaegisError as e:
        print(f"Move request failed: {e}", file=sys.stderr)
        return 1

    task_id = job.get("id")
    print(f"Job submitted (task id: {task_id}). Waiting for result...")

    final = poll_assignment_status(base_url, token, tenant_id, task_id) if task_id else None
    moved_count = len(found)
    failed_count = 0
    status_text = "unknown (check task manually)"
    if final:
        status_text = final.get("status") or status_text
        metadata = final.get("metadata") or {}
        if metadata.get("numSucceeded") is not None:
            moved_count = metadata["numSucceeded"]
            failed_count = metadata.get("numFailed") or 0

    print(f"\nJob status: {status_text}")
    print(
        f"\nFinal summary: {len(hostnames)} host(s) input, {len(not_found)} not found, "
        f"{len(skipped_sensor)} skipped (non-Taegis sensor), "
        f"{len(found)} Taegis assets found, {moved_count} moved to group '{target_group_name}'"
        + (f", {failed_count} failed" if failed_count else "")
        + "."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
