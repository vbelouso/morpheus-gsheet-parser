# README

## Prerequisites

### Required Environment Variables

The application uses the following environment variables, which can be configured using a `.env` file or the `export`
command:

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
  INFO - Intermediate data saved to cves.json
  INFO - Processing CVE-2024-29180
  INFO - Successfully generated SBOM for registry.redhat.io/openshift4/ose-monitoring-plugin-rhel9@sha256:ba11e2b3b1c0543adc06d851e773fdf156ffb19c8bed6fa0feb8ac15f0c4b3ee
  INFO - Processing CVE-2024-28863
  INFO - Successfully generated SBOM for registry.redhat.io/openshift4/ose-console-rhel9@sha256:2c4607db175cd663c27fad6a300a6a4947c08725b10f1034c9f313f966bfcbe3
  ```

- **Generated Files:**
  - `sboms/` - folder containing SBOM JSON files.
  - `cves.json` - intermediate file storing SBOM references

  ```json
    [
      {
        "cve": "CVE-2024-29180",
        "image": "registry.redhat.io/openshift4/ose-monitoring-plugin-rhel9@sha256:ba11e2b3b1c0543adc06d851e773fdf156ffb19c8bed6fa0feb8ac15f0c4b3ee",
        "sbom_file": "sboms/registry.redhat.io_openshift4_ose_monitoring_plugin_rhel9_sha256_ba11e2b3b1c0543adc06d851e773fdf156ffb19c8bed6fa0feb8ac15f0c4b3ee.sbom.json"
      },
      {
        "cve": "CVE-2024-28863",
        "image": "registry.redhat.io/openshift4/ose-console-rhel9@sha256:2c4607db175cd663c27fad6a300a6a4947c08725b10f1034c9f313f966bfcbe3",
        "sbom_file": "sboms/registry.redhat.io_openshift4_ose_console_rhel9_sha256_2c4607db175cd663c27fad6a300a6a4947c08725b10f1034c9f313f966bfcbe3.sbom.json"
      }
    ]
  ```

## Step 2: Run SBOM Processor

```bash
python process_reports.py
```

### Expected Output

- **Logs:**

  ```text
  INFO - Starting iteration 1 of 1
  INFO - Processing CVE-2024-29180 with batch mp-745i5h
  INFO - Processing CVE-2024-28863 with batch mp-745i5h
  INFO - Updated CVE data saved after processing
  INFO - Checking batch mp-745i5h
  INFO - Downloading report for id: 67e921d7fced9a53db7713b7
  INFO - Successfully saved report 67e921d7fced9a53db7713b7 -> outputs/67e921d7fced9a53db7713b7.json
  INFO - Completed 1 iterations successfully

  ```

- **Generated Files:**
  - `requests/` folder containing JSON request files.
  - `outputs/` folder containing processed Morpheus reports.
