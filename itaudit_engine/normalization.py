import pandas as pd
from .utils import logger

def normalize_hostnames(df: pd.DataFrame, column: str = 'hostname') -> pd.DataFrame:
    """
    Normalizes hostnames in the specified column:
    - Trim whitespace
    - Uppercase
    - Remove domain suffix (e.g., .domain.com)
    """
    if column not in df.columns:
        logger.warning(f"Column {column} not found for normalization.")
        return df

    logger.info(f"Normalizing column: {column}")
    
    # Trim whitespace
    df[column] = df[column].astype(str).str.strip()
    
    # Uppercase
    df[column] = df[column].str.upper()
    
    # Remove domain suffix (simple split by first dot if desired, or regex)
    # Requirement says "remove_domain_suffix". Assuming standard AD suffixes like .corp.local etc.
    # We'll just take the part before the first dot.
    df[column] = df[column].apply(lambda x: x.split('.')[0])
    
    # Remove '$' suffix (common in machine accounts)
    df[column] = df[column].str.rstrip('$')
    
    # Remove domain prefix (e.g., GTBANK\HOSTNAME)
    # We split by '\' and take the last part.
    df[column] = df[column].apply(lambda x: x.split('\\')[-1])
    
    # Log sample values for debugging
    sample_values = df[column].head(5).tolist()
    logger.info(f"Sample normalized values for {column}: {sample_values}")
    
    return df

def normalize_ip_address(df: pd.DataFrame, column: str = 'ip_address') -> pd.DataFrame:
    """
    Normalizes IP addresses:
    - Strips whitespace
    - Validates IPv4 format
    - Returns None (NaN) for invalid IPs to avoid pollution
    """
    if column not in df.columns:
        return df
        
    def clean_ip(ip):
        if pd.isna(ip): return None
        ip = str(ip).strip()
        try:
            # ip_address handles '192.168.0.1' correctly
            # It does NOT handle '192.168.0.01' (leading zeros) well by default in strict mode,
            # but we can try to be lenient or just use the library.
            # Let's use a simple regex first to strip non-allowed chars if needed, 
            # but usually just stripping whitespace is enough for standard CSVs.
            import ipaddress
            return str(ipaddress.IPv4Address(ip))
        except ValueError:
            return None
            
    df[column] = df[column].apply(clean_ip)
    return df

def normalize_mac_address(df: pd.DataFrame, column: str = 'mac_address') -> pd.DataFrame:
    """
    Normalizes MAC addresses:
    - Removes all non-hex characters
    - Uppercases
    - Formats as AA:BB:CC:DD:EE:FF
    """
    if column not in df.columns:
        return df
        
    def clean_mac(mac):
        if pd.isna(mac): return None
        # Remove all non-hex
        import re
        clean = re.sub(r'[^a-fA-F0-9]', '', str(mac)).upper()
        
        # Check length (should be 12 hex chars)
        if len(clean) != 12:
            return None
            
        # Format WITHOUT colons as requested by user
        return clean
        
    df[column] = df[column].apply(clean_mac)
    return df
