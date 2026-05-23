import argparse
import sys
import os
from datetime import datetime
from .ingestion import load_csv, validate_system_joined, validate_host_inventory
from .normalization import normalize_hostnames, normalize_ip_address, normalize_mac_address
from .correlation import correlate_data
from .reporting import generate_report
from .utils import logger
from .diagnostics import generate_diagnostics_report

def process_pipeline(joined_path: str, inventory_path: str) -> str:
    """
    Runs the full processing pipeline.
    Returns the path to the generated report.
    """
    logger.info("Starting processing pipeline...")
    
    # 1. Archive and Load Data
    from .utils import archive_file, cleanup_directory
    archive_file(joined_path)
    archive_file(inventory_path)
    cleanup_directory("archive")

    joined_df = load_csv(joined_path)
    inventory_df = load_csv(inventory_path)
    
    # 2. Normalize
    joined_df = normalize_hostnames(joined_df, 'hostname')
    inventory_df = normalize_hostnames(inventory_df, 'hostname')
    
    # Apply strict normalization to Inventory IP/MAC
    inventory_df = normalize_ip_address(inventory_df)
    inventory_df = normalize_mac_address(inventory_df)
    
    # 3. Validate
    joined_df = validate_system_joined(joined_df)
    inventory_df = validate_host_inventory(inventory_df)
    
    # 4. Correlate
    result_df = correlate_data(joined_df, inventory_df)
    
    # 5. Generate Diagnostics Report
    generate_diagnostics_report(joined_df, inventory_df, result_df)
    
    # 6. Generate Report
    from .utils import get_app_path
    output_dir = os.path.join(get_app_path(), 'output')
    os.makedirs(output_dir, exist_ok=True)
    
    # Use full timestamp to avoid file locking issues if user has previous report open
    timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = f"Domain_Admission_Review_{timestamp_str}.docx"
    output_path = os.path.join(output_dir, output_filename)
    
    from .utils import get_resource_path
    template_path = get_resource_path(os.path.join('templates', 'Domain_Admission_Review.docx'))
    if not os.path.exists(template_path):
        # Fallback or error? We'll error for now, but in a real app we might generate one.
        # For this demo, we'll assume the setup script created it.
        raise FileNotFoundError(f"Template not found at {template_path}")
        
    generate_report(result_df, template_path, output_path)
    
    # 7. Cleanup Output Directory
    cleanup_directory(output_dir)
    
    logger.info("Pipeline completed successfully.")
    return output_path

def main():
    parser = argparse.ArgumentParser(description="Domain Admission Automation Engine")
    parser.add_argument("--joined", help="Path to System Joined Domain CSV")
    parser.add_argument("--inventory", help="Path to Host Inventory CSV")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    
    args = parser.parse_args()
    
    if args.gui or (not args.joined and not args.inventory):
        from .gui import run_gui
        run_gui()
    else:
        if not args.joined or not args.inventory:
            print("Error: Both --joined and --inventory are required for CLI mode.")
            sys.exit(1)
        
        try:
            process_pipeline(args.joined, args.inventory)
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
