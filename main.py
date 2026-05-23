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

    # Composite: Host | IP (Pipe Separated) - output format of this tool
    match_pipe = re.match(r'^(.+?)\s*\|\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})$', token)
    if match_pipe:
         return ("Derived", match_pipe.group(1).strip(), match_pipe.group(2))

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

def normalize_and_merge(text: str) -> list:
    """
    Advanced Normalization & Deduplication.
    1. Parse all items.
    2. Group by IP/Hash.
    3. Keep the version with a Hostname if available.
    4. Return list of string representations "Host | IP" or "IP".
    """
    if not text: return []
    
    # 1. Base split (by newline/comma)
    raw_tokens = normalize_input_v12(text)
    
    # 2. Build dictionary by Key (IP)
    merged_map = {} # Key -> (Type, Host, IP)
    
    # Preserve order of FAT unique keys
    unique_keys = []
    
    for token in raw_tokens:
        res = classify_asset(token)
        if not res:
            # Keep unknowns as unique items? Or merge? 
            # Treat token itself as key for unparseable
            key = token.strip()
            if key not in merged_map:
                merged_map[key] = ("Unknown", token, "")
                unique_keys.append(key)
            continue
            
        type_str, val, ip = res
        
        # Determine Key (IP or Hash)
        if type_str == "IPv4":
            key = ip
        elif type_str == "Derived":
            key = ip
        elif type_str == "Hostname":
            # For pure hostnames, key is hostname
            key = val.lower() # Case insensitive key for hostnames
        else:
            key = token
            
        # Check existing
        if key in merged_map:
            # Merge Logic:
            # If current has host and existing does not, update.
            curr_host = val if type_str in ["Hostname", "Derived"] else ""
            
            existing_type, existing_val, existing_ip = merged_map[key]
            existing_host = existing_val if existing_type in ["Hostname", "Derived"] else ""
            
            if curr_host and not existing_host:
                # Upgrade to entry with host
                merged_map[key] = (type_str, val, ip)
        else:
            merged_map[key] = (type_str, val, ip)
            unique_keys.append(key)
            
    # Reconstruct List
    output_lines = []
    for key in unique_keys:
        t, v, i = merged_map[key]
        if t == "Unknown":
            output_lines.append(v)
        elif t == "IPv4":
            output_lines.append(i)
        elif t == "Hostname":
            output_lines.append(v)
        elif t == "Derived":
            # Format: Host | IP
            output_lines.append(f"{v} | {i}")
            
    return output_lines
