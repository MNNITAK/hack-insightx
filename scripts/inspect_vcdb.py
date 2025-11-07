import os
import json

# Path to your VCDB dataset
vcdb_path = "data/dbir/vcdb_raw/VCDB-master/data/json/validated"

# Just take a few samples
files = [f for f in os.listdir(vcdb_path) if f.endswith(".json")]
print(f"Found {len(files)} validated incidents.")

# Read first 3 incidents
for file in files[:3]:
    path = os.path.join(vcdb_path, file)
    with open(path, "r") as f:
        data = json.load(f)
        print("\n--- Incident:", file, "---")
        print("Summary:", data.get("summary", "No summary"))
        print("Industry:", data.get("victim", {}).get("industry", "Unknown"))
        print("Actor:", data.get("actor", {}).get("external", {}).get("variety", "Unknown"))
        print("Attack vector:", data.get("action", {}).get("hacking", {}).get("variety", "Unknown"))