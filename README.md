# README

## Prerequisites

### Required Environment Variables

The application uses the following environment variables, which can be configured using a `.env` file or the `export` command:

- `MORPHEUS_API_URL` *(required)* - The API endpoint for Morpheus.
- `MORPHEUS_TOKEN` *(required)* - The authentication token retrieved from the OpenShift console.
- `GOOGLE_SPREADSHEET_ID` *(required)* - Google Sheet Spreadsheet ID.
- `GOOGLE_WORKSHEET_ID` *(required)* - Google Sheet Worksheet ID.
- `GOOGLE_CREDENTIALS_FILE` *(optional, default: account.json)* - Google service account credentials file path.
- `MAX_RETRIES` *(optional, default: 60)* - Maximum number of requests retries before timing out.
- `RETRY_INTERVAL` *(optional, default: 30)* - The interval in seconds between request retries.
- `PROCESS_ITERATIONS` *(optional, default: 10)* - Defines how many times items should be processed in each cycle.
- `SKIP_PROCESSED_ITEMS` *(optional, default: true)* - Skip already processed items when running the script again.

### Credentials

- A credentials file named `account.json` is required for Google Sheet parsing.

## Setup

### Create Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Flow Overview

The workflow consists of two main steps:

1. **Run the Google Sheet parser** - Generates SBOM files.
2. **Run the SBOM processor** - Sends SBOM data to Morpheus and retrieves reports.

## Step 1: Run Google Sheet Parser

```bash
python generate_sboms.py
```

### Expected Output

- **Logs:**

  ```text
  Intermediate data saved to cves.json
  Processing table1: CVE-2024-0406
  Successfully generated SBOM for registry.redhat.io/openshift4/oc-mirror-plugin-rhel8@sha256:...
  Processing table2: CVE-2024-1485
  Successfully generated SBOM for registry.redhat.io/openshift4/ose-console:v4.15.0-...
  ```

- **Generated Files:**
  - `sboms/` - folder containing SBOM JSON files.
  - `cves.json` - intermediate file storing SBOM references

  ```json
  {
    "table1": [
      {
        "cve": "CVE-2024-0406",
        "image": "registry.redhat.io/...",
        "sbom_file": "sboms/..."
      }
    ],
    "table2": [
      {
        "cve": "CVE-2024-1485",
        "image": "registry.redhat.io/...",
        "sbom_file": "sboms/..."
      }
    ]
  }
  ```

## Step 2: Run SBOM Processor

```bash
python process_reports.py
```

### Expected Output

- **Logs:**

  ```text
  Processing table1 with batch mp-xxxxx
  Checking batch mp-xxxxx
  Downloading report for id: 67b490148788114dd8df4c98
  Successfully saved report 67b490148788114dd8df4c98 -> outputs/67b490148788114dd8df4c98.json
  ```

- **Generated Files:**
  - `requests/` folder containing JSON request files.
  - `outputs/` folder containing processed Morpheus reports.
