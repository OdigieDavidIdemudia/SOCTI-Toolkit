import pandas as pd
from .utils import logger
import os

def generate_diagnostics_report(joined_df: pd.DataFrame, inventory_df: pd.DataFrame, merged_df: pd.DataFrame, output_dir: str = "output"):
    """
    Generates a diagnostics CSV report to help debug matching issues.
    
    The report includes:
    - Raw and normalized hostname, IP, and MAC from both sources.
    - Final matched values.
    - Indicators for missing matches.
    """
    logger.info("Generating diagnostics report...")
    
    try:
        # Prepare Joined Data (Left Side)
        # We want raw values if available, otherwise current values
        diag_data = joined_df.copy()
        
        # Rename columns for clarity in diagnostics
        diag_data = diag_data.rename(columns={
            'hostname': 'joined_hostname_norm',
            '__hostname_raw': 'joined_hostname_raw',
            'username': 'username',
            'joined_date': 'joined_date',
            'joined_time': 'joined_time'
        })
        
        # Prepare Inventory Data (Right Side) for lookup
        # We'll merge this manually to control the output format
        inv_lookup = inventory_df.copy()
        inv_lookup = inv_lookup.rename(columns={
            'hostname': 'inv_hostname_norm',
            '__hostname_raw': 'inv_hostname_raw',
            'ip_address': 'inv_ip_norm',
            '__ip_address_raw': 'inv_ip_raw',
            'mac_address': 'inv_mac_norm',
            '__mac_address_raw': 'inv_mac_raw'
        })
        
        # Perform a left join on the normalized hostname to mimic the main correlation
        # Note: The main correlation might have already done this, but we want to see the "why" here.
        # If merged_df is passed, it might already have the results, but let's reconstruct the view 
        # to ensure we show the raw vs norm comparison clearly.
        
        # However, to be most useful, we should probably base this on the 'merged_df' 
        # but 'merged_df' might not have the raw columns if they weren't preserved.
        # So we will re-merge the source DFs which now (will) have raw columns.
        
        full_diag = pd.merge(
            diag_data, 
            inv_lookup, 
            left_on='joined_hostname_norm', 
            right_on='inv_hostname_norm', 
            how='left',
            indicator='_merge_status'
        )
        
        # Select and Reorder columns for the report
        # We want to see: Hostname (Raw/Norm), IP (Raw/Norm), MAC (Raw/Norm), Match Status
        
        cols_to_show = [
            'joined_hostname_raw', 'joined_hostname_norm',
            '_merge_status',
            'inv_hostname_raw', 'inv_hostname_norm',
            'inv_ip_raw', 'inv_ip_norm',
            'inv_mac_raw', 'inv_mac_norm'
        ]
        
        # Filter for columns that actually exist (in case some raw columns are missing)
        final_cols = [c for c in cols_to_show if c in full_diag.columns]
        
        final_diag = full_diag[final_cols]
        
        # Save to CSV
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "diagnostics.csv")
        final_diag.to_csv(output_path, index=False)
        
        logger.info(f"Diagnostics report saved to: {output_path}")
        
        # Log summary stats
        total_rows = len(final_diag)
        unmatched = len(final_diag[final_diag['_merge_status'] == 'left_only'])
        logger.info(f"Diagnostics Summary: {total_rows} rows, {unmatched} unmatched.")
        
    except Exception as e:
        logger.error(f"Failed to generate diagnostics report: {e}")
        # Don't raise, just log, so main pipeline doesn't crash just for diagnostics
