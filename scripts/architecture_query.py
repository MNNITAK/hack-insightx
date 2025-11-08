# scripts/architecture_query.py

def architecture_to_query(architecture):
    """
    Converts a user architecture dict or object into a textual description
    suitable for semantic search.
    """
    components = architecture.get("components", [])
    attacks = architecture.get("potential_attacks", [])
    
    components_text = ", ".join([c["name"] for c in components])
    attacks_text = ", ".join(attacks)
    
    query = (
        f"Architecture includes components: {components_text}. "
        f"Potential attacks: {attacks_text}."
    )
    
    return query
