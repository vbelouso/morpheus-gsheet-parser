import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional

import gspread
import pandas as pd
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("generate_sboms.log")
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

@dataclass
class GoogleSheetConfig:
    spreadsheet_id: str
    worksheet_id: str
    credentials_file: str

    @classmethod
    def from_env(cls) -> 'GoogleSheetConfig':
        required_vars = ["GOOGLE_SPREADSHEET_ID", "GOOGLE_WORKSHEET_ID"]
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
            
        return cls(
            spreadsheet_id=os.getenv("GOOGLE_SPREADSHEET_ID"),
            worksheet_id=os.getenv("GOOGLE_WORKSHEET_ID"),
            credentials_file=os.getenv("GOOGLE_CREDENTIALS_FILE", "account.json")
        )

def configure_google_sheet(config: GoogleSheetConfig) -> List[List[str]]:
    """Configure and connect to Google Sheets.
    
    Args:
        config: Google Sheets configuration
        
    Returns:
        List of rows from the worksheet
        
    Raises:
        FileNotFoundError: If credentials file is not found
        PermissionError: If service account lacks permissions
        Exception: For other Google Sheets API errors
    """
    if not os.path.isfile(config.credentials_file):
        raise FileNotFoundError(f"Google Credentials file '{config.credentials_file}' not found.")

    try:
        gc = gspread.service_account(filename=config.credentials_file)
        sh = gc.open_by_key(config.spreadsheet_id)
        worksheet = sh.worksheet(config.worksheet_id)
        return worksheet.get_all_values()
    except PermissionError as e:
        with open(config.credentials_file) as f:
            service_email = json.load(f).get("client_email", "unknown")
        raise PermissionError(
            f"Permission denied: share the spreadsheet with the service account '{service_email}'"
        ) from e
    except Exception as e:
        raise Exception(f"Failed to configure Google Sheets: {e}") from e

def extract_table(rows: List[List[str]], start_keyword: str) -> pd.DataFrame:
    """Extract a table starting from a specific header keyword.
    
    Args:
        rows: List of rows from the worksheet
        start_keyword: Keyword to identify the header row
        
    Returns:
        DataFrame containing the extracted table
        
    Raises:
        ValueError: If header keyword is not found
    """
    header_row_index = None

    for i, row in enumerate(rows):
        if start_keyword in row:
            header_row_index = i
            break

    if header_row_index is None:
        raise ValueError(f"Header '{start_keyword}' not found in the sheet!")

    header = rows[header_row_index]
    data = []

    for row in rows[header_row_index + 1:]:
        if not any(row):  # Stop at the first empty row
            break
        data.append(row)

    df = pd.DataFrame(data, columns=header)
    df = df[df["CVE"].str.match(r"^CVE-", na=False)]

    return df

def sanitize_filename(image: str) -> str:
    """Sanitize image name for use as filename.
    
    Args:
        image: Docker image name
        
    Returns:
        Sanitized filename
    """
    return image.replace("/", "_").replace(":", "_").replace("@", "_").replace("-", "_")

def generate_table_json(table: pd.DataFrame) -> List[Dict[str, str]]:
    """Generate JSON structure for a single table.
    
    Args:
        table: DataFrame containing the table data
        
    Returns:
        List of dictionaries with CVE, image and SBOM file information
    """
    json_data = []
    for _, row in table.iterrows():
        separator = "@" if row["Tag"].startswith("sha256") else ":"
        image = f"registry.redhat.io/{row['Component']}{separator}{row['Tag']}"
        sbom_file = os.path.join("sboms", f"{sanitize_filename(image)}.sbom.json")
        json_data.append({"cve": row["CVE"], "image": image, "sbom_file": sbom_file})
    return json_data

def run_syft(image: str, output_format: str = "cyclonedx-json") -> Optional[str]:
    """Run Syft to generate SBOM for an image.
    
    Args:
        image: Docker image to analyze
        output_format: Output format for SBOM
        
    Returns:
        Path to generated SBOM file or None if generation failed
    """
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

def process_data(all_rows: List[List[str]]) -> None:
    """Process data from Google Sheets and generate SBOMs.
    
    Args:
        all_rows: List of rows from the worksheet
        
    Raises:
        ValueError: If no data is found in the sheet
    """
    if not all_rows:
        raise ValueError("No data found in the Google Sheet.")
        
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

def main() -> None:
    """Main entry point."""
    try:
        # Ensure the sboms folder exists
        os.makedirs("sboms", exist_ok=True)
        
        # Configure and process data
        config = GoogleSheetConfig.from_env()
        all_rows = configure_google_sheet(config)
        process_data(all_rows)
        
    except Exception as e:
        logger.error(f"Failed to process data: {e}", exc_info=False)
        sys.exit(1)

if __name__ == "__main__":
    main()
