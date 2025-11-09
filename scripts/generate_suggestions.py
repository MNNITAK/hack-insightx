# scripts/generate_suggestions.py

def generate_suggestions(similar_cases):
    suggestions = []
    for case in similar_cases:
        # Example rules (you can expand)
        if "firewall" not in case["asset"].lower():
            suggestions.append("Add a firewall to protect key servers.")
        if "ransomware" in case["action"].lower():
            suggestions.append("Ensure regular backups and endpoint protection.")
        if "unpatched" in case["summary"].lower():
            suggestions.append("Patch vulnerable systems regularly.")
    
    
    
    return list(set(suggestions))  # remove duplicates
