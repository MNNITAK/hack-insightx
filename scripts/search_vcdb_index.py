import faiss
import pickle
from pathlib import Path
from sentence_transformers import SentenceTransformer
import numpy as np

INDEX_DIR = Path("data/dbir/index")
INDEX_FILE = INDEX_DIR / "vcdb_faiss.index"
METADATA_FILE = INDEX_DIR / "vcdb_metadata.pkl"

# Load the FAISS index
index = faiss.read_index(str(INDEX_FILE))

# Load metadata
with open(METADATA_FILE, "rb") as f:
    metadata = pickle.load(f)

# Load embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")

def search(query, top_k=5):
    """Search the VCDB index for the most similar cases to a query."""
    query_embedding = model.encode([query])
    query_embedding = np.array(query_embedding).astype("float32")

    distances, indices = index.search(query_embedding, top_k)

    results = []
    for idx, dist in zip(indices[0], distances[0]):
        case = metadata[idx].copy()
        case["distance"] = float(dist)
        results.append(case)
    return results

if __name__ == "__main__":
    # Example query
    query_text = (
        "Cloud-based healthcare system targeted by ransomware, "
        "affecting patient records and hospital servers"
    )

    results = search(query_text, top_k=5)

    print(f"🔍 Top {len(results)} similar cases for your query:\n")
    for i, r in enumerate(results, 1):
        print(f"===== Case {i} =====")
        print(f"Incident ID: {r['incident_id']}")
        print(f"Industry: {r['industry']}")
        print(f"Country: {r['country']}")
        print(f"Actors: {r['actor']}")
        print(f"Actions: {r['action']}")
        print(f"Assets: {r['asset']}")
        print(f"Impact Rating: {r['impact_overall_rating']}")
        print(f"Summary: {r['summary']}")
        print(f"Distance: {r['distance']:.4f}\n")