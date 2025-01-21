import json
import gspread
import pandas as pd
import subprocess
import os

# Ensure the sboms folder exists
os.makedirs("sboms", exist_ok=True)

# Google Sheets Setup
gc = gspread.service_account(filename="account.json")
sh = gc.open_by_key("1SUTbTVTEaF7H5t3qQ6d9ftIjNx-eRjMDTArEBto_niw")
worksheet = sh.worksheet("Categorized Data")
all_rows = worksheet.get_all_values()

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
        sbom_file = os.path.join(
            "sboms",
            f"{sanitize_filename(image)}.sbom.json"
        )
        json_data.append({
            "cve": row["CVE"],
            "image": image,
            "sbom_file": sbom_file
        })
    return json_data

def run_syft(image, output_format="cyclonedx-json"):
    output_file = os.path.join(
        "sboms",
        f"{sanitize_filename(image)}.sbom.json"
    )
    command = [
        "syft",
        image,
        "--scope",
        "all-layers",
        "-o",
        f"{output_format}={output_file}",
    ]

    try:
        subprocess.run(command, check=True, text=True, timeout=300)
        print(f"Successfully generated SBOM for {image}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"Error running Syft for {image}: {e}")
        return None


# Main logic
def process_data():
    # Extract tables from Google Sheets
    table1 = extract_table(all_rows, "CVE")  # First table
    table2 = extract_table(all_rows[4:], "CVE")  # Second table

    # Generate JSON for each table
    table1_json = generate_table_json(table1)
    table2_json = generate_table_json(table2)

    # Combine into the required structure
    combined_json = {
        "table1": table1_json,
        "table2": table2_json
    }

    # Save to a JSON file
    json_file = "cves.json"
    with open(json_file, "w") as f:
        json.dump(combined_json, f, indent=2)
    print(f"Intermediate data saved to {json_file}")

    # Process each table
    for table_name, entries in combined_json.items():
        for entry in entries:
            print(f"Processing {table_name}: {entry['cve']}")
            run_syft(entry["image"])

# Run the main process
process_data()