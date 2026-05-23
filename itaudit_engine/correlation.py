import pandas as pd
from .utils import logger

def correlate_data(joined_df: pd.DataFrame, inventory_df: pd.DataFrame) -> pd.DataFrame:
    """
    Correlates joined systems with host inventory on 'hostname'.
    - join_key: hostname
    - case_sensitive: false (handled by normalization)
    - on_duplicate_key: halt_processing (check for duplicates before join)
    - on_missing_match: mark_unresolved
    """
    logger.info("Correlating data...")

    # Debug: Log samples from both sides
    logger.info(f"Joined DF Hostnames (First 5): {joined_df['hostname'].head(5).tolist()}")
    logger.info(f"Inventory DF Hostnames (First 5): {inventory_df['hostname'].head(5).tolist()}")

    # Handle duplicates in joined_df (primary source)
    if joined_df['hostname'].duplicated().any():
        dups = joined_df[joined_df['hostname'].duplicated()]['hostname'].unique().tolist()
        logger.warning(f"Duplicate hostnames found in System Joined Domain data: {dups}. Deduplicating (keeping first occurrence).")
        joined_df = joined_df.drop_duplicates(subset=['hostname'], keep='first')

    # Handle duplicates in inventory_df (reference source)
    if inventory_df['hostname'].duplicated().any():
        dups = inventory_df[inventory_df['hostname'].duplicated()]['hostname'].unique().tolist()
        logger.warning(f"Duplicate hostnames found in Host Inventory data: {dups}. Deduplicating (keeping first occurrence) to prevent join explosion.")
        inventory_df = inventory_df.drop_duplicates(subset=['hostname'], keep='first')

    # Merge
    # Left join to keep all joined systems
    merged_df = pd.merge(joined_df, inventory_df, on='hostname', how='left', indicator=True)
    
    # Map match_status
    merged_df['match_status'] = merged_df['_merge'].apply(lambda x: 'matched' if x == 'both' else 'unresolved')
    
    # Drop merge indicator
    merged_df = merged_df.drop(columns=['_merge'])
    
    # Log stats
    matched_count = len(merged_df[merged_df['match_status'] == 'matched'])
    unresolved_df = merged_df[merged_df['match_status'] == 'unresolved']
    unresolved_count = len(unresolved_df)
    
    logger.info(f"Correlation complete. Matched: {matched_count}, Unresolved: {unresolved_count}")
    
    if not unresolved_df.empty:
        # Store unresolved records as per spec
        import os
        import json
        output_dir = os.path.join(os.getcwd(), 'output') # Ensure output dir exists (it's created in main usually, but let's be safe)
        os.makedirs(output_dir, exist_ok=True)
        unresolved_file = os.path.join(output_dir, 'unresolved_records.json')
        
        # Convert to list of dicts
        records = unresolved_df.to_dict(orient='records')
        
        # Append to existing file or create new? Spec implies "store", usually log style. 
        # We'll append line by line or write a new file per run? 
        # Let's write a new file per run to avoid huge files, or append. 
        # Given the filename pattern isn't specified, let's use a timestamped file.
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unresolved_file = os.path.join(output_dir, f'unresolved_records_{timestamp}.json')
        
        with open(unresolved_file, 'w') as f:
            json.dump(records, f, indent=2, default=str)
            
        logger.info(f"Stored {unresolved_count} unresolved records to {unresolved_file}")

    return merged_df
