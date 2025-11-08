# scripts/agent_vcdb_integration.py

import pickle
from pathlib import Path
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer

from architecture_query import architecture_to_query
from generate_suggestions import generate_suggestions

# Paths to FAISS index & metadata
INDEX_DIR = Path("data/dbir/index")
INDEX_FILE = INDEX_DIR / "vcdb_faiss.index"
METADATA_FILE = INDEX_DIR / "vcdb_metadata.pkl"

# Load FAISS index and metadata
index = faiss.read_index(str(INDEX_FILE))
with open(METADATA_FILE, "rb") as f:
    metadata = pickle.load(f)

# Load embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")

def search_similar_cases(query, top_k=5):
    query_embedding = model.encode([query])
    query_embedding = np.array(query_embedding).astype("float32")
    distances, indices = index.search(query_embedding, top_k)
    
    results = []
    for idx, dist in zip(indices[0], distances[0]):
        case = metadata[idx].copy()
        case["distance"] = float(dist)
        results.append(case)
    return results

def analyze_architecture(architecture, top_k=5):
    # Convert architecture → query
    query_text = architecture_to_query(architecture)
    
    # Search VCDB
    similar_cases = search_similar_cases(query_text, top_k=top_k)
    
    # Generate actionable suggestions
    suggestions = generate_suggestions(similar_cases)
    
    return {
        "query": query_text,
        "similar_cases": similar_cases,
        "suggestions": suggestions
    }

# Example usage
if __name__ == "__main__":
    sample_arch = {
        "components": [{"name": "Web Server"}, {"name": "Database"}],
        "potential_attacks": ["ransomware", "SQL injection"]
    }
    
    result = analyze_architecture(sample_arch)
    
    print("Query:", result["query"])
    print("\nSuggestions:")
    for s in result["suggestions"]:
        print("-", s)
