# Overview

## Prerequisites

Credentials file `account.json`

## Create virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run GSheet parser

```bash
python main_json.py
```

Logs:

```text
Intermediate data saved to cves.json
Processing table1: CVE-2024-0406
Successfully generated SBOM for registry.redhat.io/openshift4/oc-mirror-plugin-rhel8@sha256:ee166a7a362c2144f088413cc8cccaded88913e80c2db11ab5e291a69485f91a
Processing table2: CVE-2024-1485
Successfully generated SBOM for registry.redhat.io/openshift4/ose-console:v4.15.0-202409180905.p0.gf6f61ca.assembly.stream.el8
```

Expected output:

* The `sboms` folder with SBOM files.
* The `cves.json` intermediate file.

```json
{
  "table1": [
    {
      "cve": "CVE-2024-0406",
      "image": "registry.redhat.io/openshift4/oc-mirror-plugin-rhel8@sha256:ee166a7a362c2144f088413cc8cccaded88913e80c2db11ab5e291a69485f91a",
      "sbom_file": "sboms/registry.redhat.io_openshift4_oc_mirror_plugin_rhel8_sha256_ee166a7a362c2144f088413cc8cccaded88913e80c2db11ab5e291a69485f91a.sbom.json"
    }
  ],
  "table2": [
    {
      "cve": "CVE-2024-1485",
      "image": "registry.redhat.io/openshift4/ose-console:v4.15.0-202409180905.p0.gf6f61ca.assembly.stream.el8",
      "sbom_file": "sboms/registry.redhat.io_openshift4_ose_console_v4.15.0_202409180905.p0.gf6f61ca.assembly.stream.el8.sbom.json"
    }
  ]
}
```

## Run SBOM generator

```bash
python sbom_json.py
```

Expected output:

* The `requests` folder with JSON requests files.

## Run reports parser

```bash
python reports_parser.py
```

Expected output:

* The `outputs` folder with Morpheus reports.

Logs:

```text
Processing report ID: c16503ed-90c2-4624-bc18-b4b09c79f122
Report c16503ed-90c2-4624-bc18-b4b09c79f122 is available
Report saved: outputs/c16503ed-90c2-4624-bc18-b4b09c79f122.json
Successfully processed report c16503ed-90c2-4624-bc18-b4b09c79f122
Processing report ID: f1f356c3-4e3b-4b4a-a3d8-2687c04219ed
Report f1f356c3-4e3b-4b4a-a3d8-2687c04219ed is available
Report saved: outputs/f1f356c3-4e3b-4b4a-a3d8-2687c04219ed.json
Successfully processed report f1f356c3-4e3b-4b4a-a3d8-2687c04219ed
```
