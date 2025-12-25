#!/usr/bin/env python3
import re

def classify_asset(token: str) -> tuple:
    """Classify a token based on v1.2.0 rules.
    
    Rules:
    - IP: ^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$
    - Hostname: ^[a-zA-Z0-9.-]+$
    
    Returns: (type_str, value, ip_address_or_dash)
    """
    token = token.strip()
    if not token: return None
    
    # IP Regex
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', token):
        return ("IPv4", "", token)
        
    # Composite: Host@IP
    # Matches: "Name with spaces @ 1.2.3.4" or "Name@1.2.3.4"
    match_at = re.match(r'^(.+?)\s*@\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})$', token)
    if match_at:
        return ("Derived", match_at.group(1).strip(), match_at.group(2))

    # Composite: Host (IP)
    # Matches: "Name (1.2.3.4)"
    match_paren = re.match(r'^(.+?)\s*\(\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s*\)$', token)
    if match_paren:
        return ("Derived", match_paren.group(1).strip(), match_paren.group(2))

    # Composite: Host IP (Space Separated)
    match_space = re.match(r'^(.+?)\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})$', token)
    if match_space:
        return ("Derived", match_space.group(1).strip(), match_space.group(2))
        
    # Hostname Regex
    if re.match(r'^[a-zA-Z0-9.-]+$', token):
        return ("Hostname", token, "")
        
    return ("Unknown", token, "")

def normalize_input_v12(text: str) -> list:
    """Normalization Pipeline v1.2.0:
    1. Replace newline with comma
    2. Split by comma
    3. Trim
    4. Remove Empty
    5. Deduplicate
    """
    if not text: return []
    
    # 1. Replace \n with ,
    text = text.replace('\n', ',')
    
    # 2. Split by comma
    tokens = text.split(',')
    
    # 3. Trim & 4. Remove Empty
    clean_tokens = [t.strip() for t in tokens if t.strip()]
    
    # 5. Deduplicate (preserve order using dict)
    seen = set()
    deduped = []
    for t in clean_tokens:
        if t not in seen:
            deduped.append(t)
            seen.add(t)
            
    return deduped
