import json
import logging
import os
import random
import string
import sys
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from rich.live import Live
from rich.table import Table
from urllib3.util import Retry

import requests
from requests.adapters import HTTPAdapter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("process_reports.log")],
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

OUTPUTS_DIR = Path("outputs")
REQUESTS_DIR = Path("requests")


@dataclass
class MorpheusConfig:
    """Configuration for the Morpheus client."""

    # Authentication token for API requests
    token: str
    # Base URL of the API
    api_url: str
    # Maximum number of retry attempts in case of failures
    max_retries: int
    # Time interval (in seconds) between retry attempts
    retry_interval: int = 30
    # Defines how many times items should be processed in each cycle.
    # For instance, if 3 requests are made per iteration and process_iterations is set to 3,
    # a total of 9 requests will be sent to the backend.
    process_iterations: int = 10
    # Skip already processed items
    skip_processed_items: bool = True

    @classmethod
    def from_env(cls) -> "MorpheusConfig":
        # Validate required environment variables
        required_vars = ["MORPHEUS_TOKEN", "MORPHEUS_API_URL"]
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            logger.error(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )
            sys.exit(1)

        return cls(
            token=os.getenv("MORPHEUS_TOKEN"),
            api_url=os.getenv("MORPHEUS_API_URL"),
            max_retries=int(os.getenv("MAX_RETRIES", "60")),
            retry_interval=int(os.getenv("RETRY_INTERVAL", "30")),
            process_iterations=int(os.getenv("PROCESS_ITERATIONS"), 10),
            skip_processed_items=os.getenv("SKIP_PROCESSED_ITEMS", "true").lower()
            == "true",
        )


class ReportStatus(Enum):
    """Status of a report and its display information."""

    PROCESSING = ("[yellow]⧖ PROCESSING[/yellow]", False)
    COMPLETE = ("[green]✓ COMPLETE[/green]", True)
    TIMEOUT = ("[red]TIMEOUT[/red]", True)
    EXPIRED = ("[red]⚠ EXPIRED[/red]", True)

    def __init__(self, display: str, is_final: bool):
        self.display = display
        self.is_final = is_final


class MorpheusClient:
    """Client for interacting with the Morpheus API."""

    def __init__(self, config: MorpheusConfig):
        """
        Initialize the Morpheus client.

        Args:
            config: Configuration for the client
        """
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Initialize retry strategy
        self.retry_strategy = Retry(
            total=config.max_retries,
            backoff_factor=config.retry_interval,
            # 429?
            status_forcelist=[500, 502, 503, 504],
        )

        # Create session with retry strategy
        self.session = requests.Session()
        self.session.mount("http://", HTTPAdapter(max_retries=self.retry_strategy))
        self.session.mount("https://", HTTPAdapter(max_retries=self.retry_strategy))

    def _get_headers(self) -> Dict[str, str]:
        """
        Get headers for API requests.

        Returns:
            Dict[str, str]: Headers with authorization
        """
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.token}",
        }

    def _get_report_status(
        self, report: Dict[str, Any], retry_count: int
    ) -> ReportStatus:
        """
        Determine the status of a report.

        Args:
            report: Report data
            retry_count: Number of retries performed

        Returns:
            ReportStatus: Current status of the report
        """
        if report.get("state") == "expired":
            return ReportStatus.EXPIRED
        if not report.get("completedAt"):
            if retry_count > self.config.max_retries:
                return ReportStatus.TIMEOUT
            return ReportStatus.PROCESSING
        return ReportStatus.COMPLETE

    def _generate_table(self) -> Table:
        """
        Create a table for displaying report status.

        Returns:
            Table: Formatted rich Table
        """
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Report ID")
        table.add_column("Status")
        table.add_column("Retry")
        return table

    def send_request(self, payload: Dict) -> Optional[Dict]:
        """
        Send a request to the Morpheus API.

        Args:
            payload: Request payload

        Returns:
            RequestResult: Result of the request operation
        """
        try:
            url = f"{self.config.api_url}/reports/new"
            response = self.session.post(
                url=url, json=payload, headers=self._get_headers()
            )
            if response.status_code == HTTPStatus.UNAUTHORIZED:
                self.logger.error("Unauthorized request: invalid or missing token.")
                sys.exit(1)

            response.raise_for_status()

            response_data = response.json()
            if "id" in response_data and "reportId" in response_data:
                return response_data
            else:
                self.logger.error(
                    "Response did not contain expected 'id' and 'reportId'."
                )
                return None
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error: {e}")
        except requests.exceptions.Timeout as e:
            self.logger.error(f"Request timed out: {e}")
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {e}")

        return None

    def get_batch_reports(self, batch_id: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get and monitor reports for a batch.

        Args:
            batch_id: Batch identifier

        Returns:
            Optional[List[Dict[str, Any]]]: List of reports if successful, None otherwise
        """
        retries: Dict[str, int] = {}
        self.logger.info(f"Checking batch {batch_id}")

        with Live(self._generate_table(), refresh_per_second=5) as live:
            while True:
                try:
                    response = self.session.get(
                        url=f"{self.config.api_url}/reports?batch_id={batch_id}",
                        headers=self._get_headers(),
                    )
                    response.raise_for_status()
                    reports = response.json()

                    table = self._generate_table()
                    incomplete = False

                    for report in reports:
                        report_id = report["id"]
                        retry_count = retries.get(report_id, 0)

                        status = self._get_report_status(report, retry_count)
                        if status == ReportStatus.PROCESSING:
                            retries[report_id] = retry_count + 1
                            incomplete = True
                        elif status == ReportStatus.COMPLETE:
                            retries[report_id] = 0

                        table.add_row(
                            report_id, status.display, str(retries.get(report_id, 0))
                        )

                    live.update(table)

                    if not incomplete:
                        all_complete = all(
                            report.get("completedAt") for report in reports
                        )
                        if all_complete:
                            self.logger.info("All reports completed successfully!")
                        else:
                            self.logger.warning(
                                "Not all reports completed successfully"
                            )
                        return reports

                    if all(
                        retries.get(r["id"], 0) > self.config.max_retries
                        for r in reports
                        if not r.get("completedAt")
                    ):
                        self.logger.warning(
                            f"Timeout reached after {self.config.max_retries} retries!"
                        )
                        return reports

                    time.sleep(self.config.retry_interval)

                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Error fetching batch reports: {e}")
                    return None

    def download_successful_reports(
        self, cves_data: Dict[str, List[Dict[str, Any]]]
    ) -> int:
        """
        Download reports for successful requests.

        Args:
            cves_data: Data containing report IDs

        Returns:
            int: Number of successfully downloaded reports
        """
        download_count = 0

        for table_name, entries in cves_data.items():
            for entry in entries:
                report_id = entry.get("id")
                if not report_id:
                    self.logger.warning(
                        f"Skipping entry in {table_name}, no 'id' found."
                    )
                    continue

                self.logger.info(f"Downloading report for id: {report_id}")
                report = self.get_report_by_id(report_id)

                if report:
                    output_file = OUTPUTS_DIR / f"{report_id}.json"
                    try:
                        with open(output_file, "w") as file:
                            json.dump(report, file, indent=2)
                        self.logger.info(
                            f"Successfully saved report {report_id} -> {output_file}"
                        )
                        download_count += 1
                    except Exception as e:
                        self.logger.error(f"Error saving report {report_id}: {e}")
                else:
                    self.logger.error(f"Failed to download report {report_id}")

        return download_count

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a specific report by ID.

        Args:
            report_id: Report identifier

        Returns:
            Optional[Dict[str, Any]]: Report data if successful, None otherwise
        """
        url = f"{self.config.api_url}/reports/{report_id}"
        try:
            response = self.session.get(url, headers=self._get_headers(), timeout=60)
            if response.status_code in (
                HTTPStatus.NOT_FOUND,
                HTTPStatus.INTERNAL_SERVER_ERROR,
            ):
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching report {report_id}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error fetching report {report_id}: {e}")

        return None


def generate_id() -> str:
    """
    Generate a unique identifier.

    Returns:
        str: UUID string
    """
    return str(uuid.uuid4())


def generate_batch_id() -> str:
    """
    Generate a unique batch identifier.

    Returns:
        str: Formatted batch ID
    """
    chars = string.ascii_lowercase + string.digits
    unique_string = "".join(random.choices(chars, k=6))
    return f"mp-{unique_string}"


def build_request_json(
    data: Dict[str, Any], vulns: List[str], batch_id: str
) -> Dict[str, Any]:
    """
    Build request JSON for the API.

    Args:
        data: SBOM data
        vulns: Vulnerability information
        batch_id: Batch identifier

    Returns:
        Dict[str, Any]: Formatted request data
    """
    request_id = generate_id()
    return {
        "id": request_id,
        "vulnerabilities": [vulns],
        "metadata": {"source": "morpheus-parser", "batch_id": batch_id},
        "sbom_info_type": "manual",
        "sbom": data,
    }


def process_requests_from_cves(client: MorpheusClient, cves_file: str) -> bool:
    """
    Process requests from CVE data file.

    Args:
        client: Morpheus client for API interactions
        cves_file: Path to CVE data file

    Returns:
        bool: True if successful, False otherwise
    """
    logger = logging.getLogger(__name__)

    try:
        with open(cves_file, "r") as f:
            try:
                cves_data = json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON format in CVEs file: {cves_file}")
                return False
    except FileNotFoundError:
        logger.error(f"CVEs file not found: {cves_file}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error reading CVEs file: {e}")
        return False

    sent_requests = []

    for table_name, entries in cves_data.items():
        batch_id = generate_batch_id()
        logger.info(f"Processing table {table_name} with batch {batch_id}")

        table_requests = []

        for entry in entries:
            if (
                client.config.skip_processed_items
                and "id" in entry
                and "report_id" in entry
            ):
                logger.info(f"Skipping {entry['cve']} - already processed.")
                continue

            try:
                with open(entry["sbom_file"], "r") as sbom:
                    sbom_data = json.load(sbom)

                vulns = entry["cve"]
                request_json = build_request_json(
                    data=sbom_data, vulns=vulns, batch_id=batch_id
                )

                request_file = REQUESTS_DIR / f"{request_json['id']}.json"
                with open(request_file, "w") as f:
                    json.dump(request_json, f, indent=2)

                response_data = client.send_request(request_json)
                if response_data:
                    sent_requests.append(response_data["id"])
                    table_requests.append(response_data["id"])

                    entry["id"] = response_data["id"]
                    entry["report_id"] = response_data["reportId"]
                else:
                    logger.error(f"Failed to send request for {entry['cve']}")
            except FileNotFoundError:
                logger.error(f"SBOM file not found: {entry['sbom_file']}")
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON format in SBOM file: {entry['sbom_file']}")
            except Exception as e:
                logger.error(f"Unexpected error processing {entry['sbom_file']}: {e}")
        try:
            with open(cves_file, "w") as file:
                json.dump(cves_data, file, indent=2)
            logger.info(f"Updated CVE data saved after processing {table_name}")
        except Exception as e:
            logger.error(f"Error saving updated CVE data: {e}")

        # Get batch reports
        if table_requests:
            client.get_batch_reports(batch_id)

    # Download reports
    client.download_successful_reports(cves_data)
    return True


def main():
    try:
        OUTPUTS_DIR.mkdir(exist_ok=True)
        REQUESTS_DIR.mkdir(exist_ok=True)
        config = MorpheusConfig.from_env()
        client = MorpheusClient(config)
        # Run the process the specified number of times
        for iteration in range(1, config.process_iterations + 1):
            logger.info(
                f"Starting iteration {iteration} of {config.process_iterations}"
            )
            process_requests_from_cves(client, cves_file="cves.json")

            # Sleep between iterations to avoid overwhelming the server
            if iteration < config.process_iterations:
                time.sleep(5)

        logger.info(f"Completed {config.process_iterations} iterations successfully")

    except Exception as e:
        logger.error(f"Application failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
