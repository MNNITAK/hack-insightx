import pandas as pd
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
from pathlib import Path
from tqdm import tqdm
import pickle

DATA_PATH = Path("data/dbir/vcdb_cases.csv")
INDEX_DIR = Path("data/dbir/index")
INDEX_DIR.mkdir(parents=True, exist_ok=True)

def load_data():
    print("📄 Loading dataset...")
    df = pd.read_csv(DATA_PATH)
    df = df.fillna("")
    df["text"] = (
        "Industry: " + df["industry"].astype(str)
        + " | Country: " + df["country"].astype(str)
        + " | Actor: " + df["actor"].astype(str)
        + " | Action: " + df["action"].astype(str)
        + " | Asset: " + df["asset"].astype(str)
        + " | Summary: " + df["summary"].astype(str)
    )
    return df

def build_index(df):
    print("🔢 Generating embeddings...")
    model = SentenceTransformer("all-MiniLM-L6-v2")
    embeddings = model.encode(df["text"].tolist(), show_progress_bar=True)
    embeddings = np.array(embeddings).astype("float32")

    print("📦 Building FAISS index...")
    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)

    # Save index and metadata
    faiss.write_index(index, str(INDEX_DIR / "vcdb_faiss.index"))
    with open(INDEX_DIR / "vcdb_metadata.pkl", "wb") as f:
        pickle.dump(df.to_dict(orient="records"), f)

    print(f"✅ Index built and saved to {INDEX_DIR}")

def main():
    df = load_data()
    build_index(df)

if __name__ == "__main__":
    main()