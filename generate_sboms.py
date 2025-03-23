import json
import logging
import os
import subprocess
import sys

import gspread
import pandas as pd
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def configure_google_sheet():
    required_vars = ["GOOGLE_SPREADSHEET_ID", "GOOGLE_WORKSHEET_ID"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]

    if missing_vars:
        logger.error(
            f"Missing required environment variables: {', '.join(missing_vars)}"
        )
        sys.exit(1)

    credentials_file = os.getenv("GOOGLE_CREDENTIALS_FILE", "account.json")

    if not os.path.isfile(credentials_file):
        logger.error(f"Google Credentials file '{credentials_file}' not found.")
        sys.exit(1)

    try:
        gc = gspread.service_account(filename=credentials_file)
        sh = gc.open_by_key(os.getenv("GOOGLE_SPREADSHEET_ID"))
        worksheet = sh.worksheet(os.getenv("GOOGLE_WORKSHEET_ID"))
        return worksheet.get_all_values()
    except PermissionError:
        with open(credentials_file) as f:
            service_email = json.load(f).get("client_email", "unknown")
        logger.error(
            f"Permission denied: share the spreadsheet with the service account '{service_email}'"
        )
        sys.exit(1)
    except Exception as e:
        logger.error(
            f"Failed to configure Google Sheets: {e}",
            exc_info=True,
        )
        sys.exit(1)


# Function to extract a table starting from a specific header keyword
def extract_table(rows, start_keyword):
    header_row_index = None

    # Locate the header dynamically based on the keyword
    for i, row in enumerate(rows):
        if start_keyword in row:  # Look for the keyword in the row
            header_row_index = i
            break

    if header_row_index is None:
        raise ValueError(f"Header '{start_keyword}' not found in the sheet!")

    # Extract the header and data starting from the next row
    header = rows[header_row_index]
    data = []

    for row in rows[header_row_index + 1 :]:
        if not any(row):  # Stop at the first empty row
            break
        data.append(row)

    # Convert to a DataFrame
    df = pd.DataFrame(data, columns=header)

    # Filter rows where CVE starts with "CVE-" using regex
    df = df[df["CVE"].str.match(r"^CVE-", na=False)]

    return df


def sanitize_filename(image):
    return image.replace("/", "_").replace(":", "_").replace("@", "_").replace("-", "_")


# Function to generate JSON structure for a single table
def generate_table_json(table):
    json_data = []
    for _, row in table.iterrows():
        separator = "@" if row["Tag"].startswith("sha256") else ":"
        image = f"registry.redhat.io/{row['Component']}{separator}{row['Tag']}"
        sbom_file = os.path.join("sboms", f"{sanitize_filename(image)}.sbom.json")
        json_data.append({"cve": row["CVE"], "image": image, "sbom_file": sbom_file})
    return json_data


def run_syft(image, output_format="cyclonedx-json"):
    output_file = os.path.join("sboms", f"{sanitize_filename(image)}.sbom.json")
    command = [
        "syft",
        image,
        "--scope",
        "all-layers",
        "-o",
        f"{output_format}={output_file}",
    ]

    try:
        subprocess.run(
            command, check=True, text=True, timeout=300, stderr=subprocess.PIPE
        )
        logger.info(f"Successfully generated SBOM for {image}")
        return output_file
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running Syft for {image}: {e}")
        return None


# Main logic
def process_data(all_rows):
    if not all_rows:
        logger.error("No data found in the Google Sheet.")
        sys.exit(1)
    # Extract tables from Google Sheets
    table1 = extract_table(all_rows, "CVE")  # First table
    table2 = extract_table(all_rows[4:], "CVE")  # Second table

    # Generate JSON for each table
    table1_json = generate_table_json(table1)
    table2_json = generate_table_json(table2)

    # Combine into the required structure
    combined_json = {"table1": table1_json, "table2": table2_json}

    # Save to a JSON file
    json_file = "cves.json"
    with open(json_file, "w") as f:
        json.dump(combined_json, f, indent=2)
    logger.info(f"Intermediate data saved to {json_file}")

    # Process each table
    for table_name, entries in combined_json.items():
        for entry in entries:
            logger.info(f"Processing {table_name}: {entry['cve']}")
            run_syft(entry["image"])


def main():
    # Ensure the sboms folder exists
    os.makedirs("sboms", exist_ok=True)
    all_rows = configure_google_sheet()
    process_data(all_rows)


if __name__ == "__main__":
    main()
