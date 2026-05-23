import os
import sys
from pm_engine import PMLogEngine
from pm_email_dispatcher import PMEmailDispatcher

def main():
    # --- CONFIGURATION ---
    INPUT_FILE = "pm_logs.xlsx" # Change to your actual file
    API_KEYS = {
        "gmaps": os.getenv("GMAPS_API_KEY"),
        "abuse": os.getenv("ABUSEIPDB_API_KEY")
    }
    
    SMTP_CONFIG = {
        "host": "relay.gtbank.com", # Update with internal relay
        "port": 25,
        "sender_email": "gtsoc@gtbank.com",
        "sender_name": "GTSOC",
        "domain": "gtbank.com",
        "dry_run": True # KEEP TRUE FOR TESTING
    }

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found.")
        return

    # 1. Initialize Engine
    engine = PMLogEngine(
        gmaps_api_key=API_KEYS.get("gmaps"),
        abuse_api_key=API_KEYS.get("abuse"),
        internal_prefix_len=16, # Clustering 10.2.x.x together
        external_prefix_len=24
    )

    print(f"Analyzing {INPUT_FILE}...")
    try:
        # 2. Parse Logs
        df, mismatch_data, travel_data, ext_ips = engine.parse_logs(INPUT_FILE)
        
        # 3. Generate Excel Report
        output_path = engine.generate_report(INPUT_FILE, version=2)
        print(f"Report generated: {output_path}")
        
        print(f"Found {len(mismatch_data)} subnet anomalies.")
        print(f"Found {len(travel_data)} impossible travel occurrences.")

        # 4. Dispatch Alerts
        if mismatch_data or travel_data:
            print("\nStarting Email Dispatch...")
            dispatcher = PMEmailDispatcher(
                smtp_host=SMTP_CONFIG["host"],
                smtp_port=SMTP_CONFIG["port"],
                sender_email=SMTP_CONFIG["sender_email"],
                sender_name=SMTP_CONFIG["sender_name"],
                email_domain=SMTP_CONFIG["domain"],
                dry_run=SMTP_CONFIG["dry_run"]
            )
            
            summary = dispatcher.dispatch_all(mismatch_data, travel_data)
            
            print("\nDispatch Summary:")
            print(f"- Subnet Alerts Sent (or dry-run): {summary['subnet_alerts_sent']}")
            print(f"- Travel Alerts Sent (or dry-run): {summary['travel_alerts_sent']}")
            if summary['failed']:
                print(f"- Failed: {len(summary['failed'])}")
                for f in summary['failed']:
                    print(f"  * To: {f['to']} | Error: {f['error']}")
        else:
            print("No anomalies found. No emails to send.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
