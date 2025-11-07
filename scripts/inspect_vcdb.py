import json
import os
from pathlib import Path

# Path to your extracted VCDB dataset
VCDB_DIR = Path("data/dbir/vcdb_raw/VCDB-master/data/json/validated")

def load_sample_cases(limit=5):
    """Load a few VCDB case study files and extract key information."""
    cases = []
    count = 0

    for file in VCDB_DIR.glob("*.json"):
        try:
            with open(file, "r") as f:
                data = json.load(f)

            case = {
                "incident_id": data.get("incident_id", "N/A"),
                "industry": data.get("victim", {}).get("industry", "Unknown"),
                "country": data.get("victim", {}).get("country", "Unknown"),
                "actor": list(data.get("actor", {}).keys()) if data.get("actor") else [],
                "action": list(data.get("action", {}).keys()) if data.get("action") else [],
                "asset": list(data.get("asset", {}).keys()) if data.get("asset") else [],
                "impact": data.get("impact", {}),
                "summary": data.get("summary", "No summary provided.")
            }

            cases.append(case)
            count += 1
            if count >= limit:
                break

        except Exception as e:
            print(f"Error reading {file}: {e}")

    return cases


def main():
    print("🔍 Inspecting VCDB case studies...\n")
    cases = load_sample_cases(limit=5)

    for i, case in enumerate(cases, 1):
        print(f"===== Case {i} =====")
        print(f"Incident ID: {case['incident_id']}")
        print(f"Industry: {case['industry']}")
        print(f"Country: {case['country']}")
        print(f"Actors: {', '.join(case['actor']) or 'Unknown'}")
        print(f"Actions: {', '.join(case['action']) or 'Unknown'}")
        print(f"Assets: {', '.join(case['asset']) or 'Unknown'}")
        print(f"Impact Summary: {case['impact']}")
        print(f"Description: {case['summary']}\n")

if __name__ == "__main__":
    main()