import json
import os
import time
from http import HTTPStatus

import requests

MORPHEUS_CONSOLE_URL = "https://agent-morpheus-client-shared-morpheus.apps.ai-dev03.kni.syseng.devcluster.openshift.com"
MAX_RETRIES = 180
RETRY_INTERVAL = 30


def get_all_reports():
    url = f"{MORPHEUS_CONSOLE_URL}/reports"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching reports: {e}")


def get_morpheus_id_by_report_id(report_id):
    # First get all reports
    all_reports = get_all_reports()
    if not all_reports:
        return None

    # Find the report where name matches our report_id
    for report in all_reports:
        if report.get('name') == report_id:
            return report.get('id')
    return None


def get_report_by_id(report_id):
    url = f"{MORPHEUS_CONSOLE_URL}/reports/{report_id}"
    try:
        response = requests.get(url)
        # Our UI client returns 500 for some reason, instead fo 404
        if response.status_code in (HTTPStatus.NOT_FOUND, HTTPStatus.INTERNAL_SERVER_ERROR):
            return None
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching report {report_id}: {e}")
        return None


def save_report(report, report_id):
    os.makedirs("outputs", exist_ok=True)
    output_file = os.path.join("outputs", f"{report_id}.json")
    with open(output_file, 'w') as file:
        json.dump(report, file, indent=2)
    print(f"Report saved: {output_file}")


def wait_for_report(report_id):
    for attempt in range(MAX_RETRIES):
        # First get the Morpheus ID for our report_id
        morpheus_id = get_morpheus_id_by_report_id(report_id)
        if morpheus_id:
            # Then get the actual report using Morpheus ID
            report = get_report_by_id(morpheus_id)
            if report:
                print(f"Report {report_id} is available")
                return report

        print(f"Report {report_id} not ready. Retrying in {RETRY_INTERVAL} seconds... ({attempt + 1}/{MAX_RETRIES})")
        time.sleep(RETRY_INTERVAL)

    print(f"Timeout waiting for report {report_id}")
    return None


def process_all_reports():
    with open("cves.json", 'r') as f:
        cves_data = json.load(f)

    for table_name, entries in cves_data.items():
        for entry in entries:
            report_id = entry.get('report_id')
            if not report_id:
                print(f"No report_id found in {table_name}")
                continue

            print(f"Processing report ID: {report_id}")
            report = wait_for_report(report_id)

            if report:
                save_report(report, report_id)
                print(f"Successfully processed report {report_id}")
            else:
                print(f"Failed to get report {report_id}, moving to next entry")

def process_report(report_id):
    print(f"Processing report ID: {report_id}")
    report = wait_for_report(report_id)

    if report:
        save_report(report, report_id)
        print(f"Successfully processed report {report_id}")
    else:
        print(f"Failed to get report {report_id}, moving to next entry")

# def main():
#     try:
#         process_reports()
#     except Exception as e:
#         print(f"Error: {e}")
#         raise
#
#
# if __name__ == "__main__":
#     main()
