# scripts/download_dbir_and_vcdb.py
"""
Downloads Verizon DBIR PDF and the VERIS/VCDB dataset into data/dbir/.
Usage:
  python3 scripts/download_dbir_and_vcdb.py
Edit DBIR_PDF_URL and VCDB_ZIP_URL before running.
"""
import os
import requests
import sys
import zipfile
from pathlib import Path

# ====== EDIT THESE BEFORE RUNNING ======
DBIR_PDF_URL = "https://example.com/verizon_dbir_latest.pdf"   # <- replace with official DBIR PDF URL
VCDB_ZIP_URL = "https://github.com/example/VCDB/archive/refs/heads/main.zip"  # <- replace with repo zip URL or raw dataset URL
# ======================================

OUT_DIR = Path("data/dbir")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def download(url: str, dest: Path):
    print(f"Downloading: {url}")
    r = requests.get(url, stream=True, timeout=60)
    r.raise_for_status()
    with open(dest, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
    print(f"Saved to: {dest}")

def safe_unzip(zip_path: Path, extract_to: Path):
    print(f"Unzipping {zip_path} -> {extract_to}")
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(extract_to)
    print("Unzip complete.")

def main():
    pdf_dest = OUT_DIR / "verizon_dbir_latest.pdf"
    zip_dest = OUT_DIR / "vcdb.zip"

    try:
        download(DBIR_PDF_URL, pdf_dest)
    except Exception as e:
        print("Failed to download DBIR PDF:", e, file=sys.stderr)

    try:
        download(VCDB_ZIP_URL, zip_dest)
        # attempt to unzip
        try:
            safe_unzip(zip_dest, OUT_DIR / "vcdb_raw")
        except Exception as e:
            print("Unzip failed (maybe input wasn't a zip):", e)
    except Exception as e:
        print("Failed to download VCDB dataset:", e, file=sys.stderr)

    print("Step 1 complete: check the data/dbir directory for the downloaded files.")

if __name__ == "__main__":
    main()