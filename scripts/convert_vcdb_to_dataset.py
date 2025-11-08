import json
import os
import csv
from pathlib import Path

VCDB_DIR = Path("data/dbir/vcdb_raw/VCDB-master/data/json/validated")
OUTPUT_FILE = Path("data/dbir/vcdb_cases.csv")

def extract_case_data(file_path):
    """Extract key information from one VCDB JSON file."""
    with open(file_path, "r") as f:
        data = json.load(f)

    return {
        "incident_id": data.get("incident_id", "N/A"),
        "industry": data.get("victim", {}).get("industry", "Unknown"),
        "country": data.get("victim", {}).get("country", "Unknown"),
        "actor": ", ".join(list(data.get("actor", {}).keys())),
        "action": ", ".join(list(data.get("action", {}).keys())),
        "asset": ", ".join(list(data.get("asset", {}).keys())),
        "impact_overall_rating": data.get("impact", {}).get("overall_rating", "N/A"),
        "summary": data.get("summary", "").replace("\n", " ").strip(),
    }

def main():
    print("📦 Converting VCDB JSON to structured dataset...")
    records = []
    count = 0

    for file in VCDB_DIR.glob("*.json"):
        try:
            record = extract_case_data(file)
            records.append(record)
            count += 1
        except Exception as e:
            print(f"⚠️ Skipped {file.name}: {e}")

    # Write to CSV
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)

    print(f"✅ Extracted {count} case studies → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()