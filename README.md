# taegis-group-mover

A small, dependency-free Python script to bulk-move Taegis XDR endpoint assets into a different endpoint (host) group, based on a plain list of hostnames.

Built for manual, occasional maintenance work — not a long-running automation tool.

## Features

- Authenticate to the Taegis XDR GraphQL API with client credentials (CLI flags or a JSON config file).
- Look up each hostname individually and show its current endpoint group **and sensor type** (Taegis, Sophos, CrowdStrike, SentinelOne, Microsoft Defender, Carbon Black, etc.).
- Only native **Taegis** agents can be moved between endpoint groups — other sensor types are shown but automatically skipped.
- Pick the destination group from a live list, or cancel.
- Confirms before making any change, then moves matching assets in a single bulk API call and polls for the job result.
- Prints a final summary: hosts input, not found, skipped (non-Taegis), and moved.

## Requirements

- Python 3.8+ (standard library only — no `pip install` needed: uses `urllib`, `json`, `argparse`, `getpass`).
- A Taegis XDR API client credential (`client_id` / `client_secret`).

### API credential role

Taegis API credentials default to the **Tenant Analyst** role, which is **not** sufficient to move assets between groups (the API will reject the move with `not authorized to perform Agent:update ... access denied (role)`).

You need a credential with an elevated role — **Administrator** is the safest choice; **Responder** may also work if your org restricts full Admin credentials:

| Role | Role ID |
|---|---|
| Administrator | `ba0fdcbd-e87d-4bdd-ae7d-ca6118b25068` |
| Responder | `a72dace7-4536-4dbc-947d-015a8eb65f4d` |
| Analyst (default) | `a4903f9f-465b-478f-a24e-82fa2e129d2e` |
| Auditor | `ace1cae4-59fd-4fd1-9500-40077dc529a7` |

The Taegis UI (**Tenant Settings → Manage API Credentials**) only issues Analyst-role credentials. To create a privileged credential, call the `createClient` GraphQL mutation directly with the desired `roles`, using a user access token copied from the browser console (`copy(localStorage.access_token)`) — see [XDR GraphQL APIs Authentication](https://docs.taegis.secureworks.com/apis/api_authenticate/) for the full steps and example `curl` commands.

## Installation

Just download `taegis_group_mover.py` — there's nothing to install.

```bash
git clone https://github.com/<your-org>/taegis-group-mover.git
cd taegis-group-mover
python3 taegis_group_mover.py --help
```

## Usage

### 1. Prepare a hosts file

Plain text, one hostname per line, pure ASCII. Blank lines are ignored; lines containing non-ASCII characters are skipped with a warning.

```
webserver01
webserver02
db-node-03
```

### 2. Run it

**With command-line credentials:**

```bash
python3 taegis_group_mover.py \
  --client-id <CLIENT_ID> \
  --client-secret <CLIENT_SECRET> \
  --region us1 \
  --hosts-file hosts.txt
```

If authentication succeeds, you'll be offered the option to save those credentials to a JSON config file for next time.

**With a config file:**

```bash
python3 taegis_group_mover.py --config taegis_config.json --hosts-file hosts.txt
```

`taegis_config.json`:

```json
{
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "region": "us1",
  "tenant_id": "optional tenant id"
}
```

Keep this file private — it's saved with owner-only read/write permissions where the OS supports it, but treat it like any other credential file (don't commit it, add it to `.gitignore`).

### Command-line options

| Flag | Description |
|---|---|
| `--config PATH` | JSON config file with credentials (see above) |
| `--client-id ID` | Taegis API client_id |
| `--client-secret SECRET` | Taegis API client_secret (omit to be prompted securely) |
| `--region {us1,us2,us3,eu1,eu2}` | Region shortcut (default endpoint mapping below) |
| `--base-url URL` | Explicit API base URL, overrides `--region` |
| `--tenant-id ID` | Optional tenant ID, sent as `X-Tenant-Context` |
| `--hosts-file PATH` | **Required.** Text file of hostnames, one per line |
| `--save-config-path PATH` | Default path offered when saving credentials (default: `taegis_config.json`) |

### Regions

| Region | Base URL |
|---|---|
| `us1` | `https://api.ctpx.secureworks.com` |
| `us2` | `https://api.delta.taegis.secureworks.com` |
| `us3` | `https://api.foxtrot.taegis.secureworks.com` |
| `eu1` | `https://api.echo.taegis.secureworks.com` |
| `eu2` | `https://api.golf.taegis.secureworks.com` |

Use `--base-url` instead if your tenant lives on a different endpoint.

## Example run

```
Authenticating to https://api.ctpx.secureworks.com ...
Authentication succeeded.
Save these credentials to a config file for next time? [y/N]: n

Loaded 3 hostname(s) from hosts.txt.

Checking assets...
Note: only native Taegis agents can be moved between endpoint groups.
Assets on other sensors (Sophos, CrowdStrike, SentinelOne, Defender, etc.) will be listed but skipped.

  webserver01: asset 85983eaa-c751-4235-b64b-04c54a922ff0, current group: (no group assigned), sensor: Taegis
  webserver02: asset 04da92f2-129f-5849-aa36-6890eb001175, current group: Production, sensor: Taegis
  db-node-03: asset 9eba0326-4b86-f1fd-53dd-ff7d6d7dec77, current group: (no group assigned), sensor: CrowdStrike  [not Taegis - will NOT be moved]

Summary of lookup: 3 input, 3 found, 0 not found (1 found but skipped - non-Taegis sensor).

Fetching available endpoint groups...

Available endpoint groups:
  1) cloudsharetest  (12 asset(s))
  2) Production  (48 asset(s))
  0) Cancel

Select target group [0-2]: 1
Move 2 Taegis host(s) into group 'cloudsharetest'? [y/N]: y

Submitting move of 2 asset(s) to group 'cloudsharetest'...
Job submitted (task id: 3f1c...). Waiting for result...

Job status: Succeeded

Final summary: 3 host(s) input, 0 not found, 1 skipped (non-Taegis sensor), 2 Taegis assets found, 2 moved to group 'cloudsharetest'.
```

## Known limitations

- Taegis doesn't expose a documented "list all endpoint groups" query. Group discovery works by scanning the `groupName` facet across existing assets, so an endpoint group only appears as a selectable destination once it has at least one asset in it. Brand-new, empty groups won't show up until they have a member.
- Sensor-type detection (`endpointType`) is not a strictly documented enum, so "is this a Taegis agent" is determined by a case-insensitive match on `redcloak`/`taegis` in that field. This is reliable for the standard native agent but flag it if you see a Taegis host misclassified.
- Hostname lookups use an exact match; if the same hostname resolves to multiple assets, the first match is used and a note is printed.

## License

Add your preferred license here (e.g. MIT) before publishing.
