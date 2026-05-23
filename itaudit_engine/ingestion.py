import pandas as pd
import ipaddress
import re
from .utils import logger

def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes column names to standard snake_case and maps common aliases.
    """
    # 1. Strip whitespace and convert to lower case
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    
    # 2. Map aliases to standard names
    # Target: hostname, ip_address, mac_address, username, joined_date, joined_time
    alias_map = {
        'host_name': 'hostname',
        'computer_name': 'hostname',
        'pc_name': 'hostname',
        'system_name': 'hostname',
        'device_name': 'hostname',
        'name': 'hostname',
        
        'ip': 'ip_address',
        'ipv4_address': 'ip_address',
        'ipv4': 'ip_address',
        'ipaddress': 'ip_address',
        
        'mac': 'mac_address',
        'physical_address': 'mac_address',
        'macaddress': 'mac_address',
        
        'user_name': 'username',
        'user': 'username',
        'login': 'username',
        
        'date': 'joined_date',
        'time': 'joined_time',
        'joined': 'joined_date', # ambiguous but possible
        'start_time': 'joined_date', # Temporary mapping, might need splitting later
        
        # Specific user mappings
        'target_computer_name_(custom)': 'hostname',
        'host': 'hostname'
    }
    
    new_columns = []
    for col in df.columns:
        if col in alias_map:
            new_columns.append(alias_map[col])
        else:
            new_columns.append(col)
            
    df.columns = new_columns
    return df

def split_datetime_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Splits 'joined_date' into date and time if 'joined_time' is missing
    and 'joined_date' contains datetime information.
    """
    if 'joined_date' in df.columns and 'joined_time' not in df.columns:
        logger.info("Attempting to split 'joined_date' into date and time...")
        try:
            # Convert to datetime, handling errors
            # The screenshot shows "25 Nov 2025, 18:4..." which pandas should parse
            temp_dt = pd.to_datetime(df['joined_date'], errors='coerce')
            
            # Check if we actually got valid datetimes
            if temp_dt.notna().any():
                df['joined_date'] = temp_dt.dt.strftime('%Y-%m-%d')
                df['joined_time'] = temp_dt.dt.strftime('%H:%M:%S')
                logger.info("Successfully split joined_date into date and time.")
            else:
                logger.warning("Could not parse 'joined_date' as datetime.")
        except Exception as e:
            logger.warning(f"Failed to split datetime column: {e}")
            
    return df

def load_csv(file_path: str) -> pd.DataFrame:
    """Loads a CSV or Excel file into a pandas DataFrame."""
    try:
        logger.info(f"Loading data from {file_path}")
        
        # Determine file type
        if file_path.lower().endswith(('.xlsx', '.xls')):
            # Read Excel file
            df = pd.read_excel(file_path, dtype=str)
        else:
            # Assume CSV
            # Try reading with default settings but force dtype=str to prevent auto-formatting
            try:
                df = pd.read_csv(file_path, dtype=str)
            except UnicodeDecodeError:
                # Fallback to latin1 if utf-8 fails
                df = pd.read_csv(file_path, encoding='latin1', dtype=str)
        
        # Normalize columns
        df = normalize_columns(df)
        
        # Store raw values for diagnostics BEFORE any further processing
        # We want to keep a copy of the key columns if they exist
        key_cols = ['hostname', 'ip_address', 'mac_address']
        for col in key_cols:
            if col in df.columns:
                df[f'__{col}_raw'] = df[col].copy()
        
        # Handle datetime splitting
        df = split_datetime_columns(df)
        
        logger.info(f"Columns found: {list(df.columns)}")
        return df
    except Exception as e:
        logger.error(f"Failed to load {file_path}: {e}")
        raise

def validate_ip(ip: str) -> bool:
    try:
        if not isinstance(ip, str):
            return False
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_mac(mac: str) -> bool:
    if not isinstance(mac, str):
        return False
    # Hex with dash or colon OR raw 12-char hex
    pattern_sep = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    pattern_raw = re.compile(r'^[0-9A-Fa-f]{12}$')
    return bool(pattern_sep.match(mac) or pattern_raw.match(mac))

def validate_host_inventory(df: pd.DataFrame) -> pd.DataFrame:
    """
    Validates host inventory data.
    - Checks required columns: hostname, ip_address, mac_address
    - Validates IP and MAC formats
    - Rejects invalid rows (logs them)
    """
    required_cols = ['hostname', 'ip_address', 'mac_address']
    if not all(col in df.columns for col in required_cols):
        raise ValueError(f"Host inventory missing required columns: {required_cols}")

    logger.info("Validating host inventory...")
    
    # IP Validation
    invalid_ips = df[~df['ip_address'].apply(validate_ip)]
    if not invalid_ips.empty:
        logger.warning(f"Found {len(invalid_ips)} rows with invalid IPs. Rejecting them.")
        df = df[df['ip_address'].apply(validate_ip)]

    # MAC Validation
    invalid_macs = df[~df['mac_address'].apply(validate_mac)]
    if not invalid_macs.empty:
        logger.warning(f"Found {len(invalid_macs)} rows with invalid MACs. Rejecting them.")
        df = df[df['mac_address'].apply(validate_mac)]

    return df

def validate_system_joined(df: pd.DataFrame) -> pd.DataFrame:
    """
    Validates system joined domain data.
    - Checks required columns: username, hostname, joined_date, joined_time
    """
    required_cols = ['username', 'hostname', 'joined_date', 'joined_time']
    if not all(col in df.columns for col in required_cols):
        raise ValueError(f"System joined domain missing required columns: {required_cols}")
        
    # Basic check for empty values
    initial_len = len(df)
    df = df.dropna(subset=required_cols)
    if len(df) < initial_len:
        logger.warning(f"Dropped {initial_len - len(df)} rows with missing values.")
        
    return df
