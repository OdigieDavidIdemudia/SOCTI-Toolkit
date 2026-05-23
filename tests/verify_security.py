import tkinter as tk
import sys
import os
import json

# Add parent dir to path to import gui
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui import SeparatorGUI

def test_security():
    print("Initializing GUI for testing...")
    root = tk.Tk()
    root.withdraw() # Hide window
    
    app = SeparatorGUI(root)
    
    # Use a test file instead of real settings.json
    test_file = 'tests/temp_settings.json'
    app.config_file = test_file
    
    # Setup test data with a password
    test_pass = "SuperSecret123"
    app.custom_config['proxy'] = {
        'host': '127.0.0.1',
        'port': '8080',
        'username': 'user',
        'password': test_pass,
        'enabled': True
    }
    
    print(f"Saving settings to {test_file}...")
    # Save
    app.save_settings()
    
    # Verify Disk
    print("Verifying disk content...")
    with open(test_file, 'r') as f:
        saved_data = json.load(f)
        
    proxy_saved = saved_data.get('proxy', {})
    if 'password' in proxy_saved:
        print("FAIL: Password found on disk!")
        return False
    else:
        print("PASS: Password NOT found on disk.")
        
    # Verify Memory
    print("Verifying memory content...")
    if app.custom_config['proxy'].get('password') == test_pass:
        print("PASS: Password preserved in memory.")
    else:
        print("FAIL: Password lost from memory!")
        return False
    
    # Clean up
    if os.path.exists(test_file):
        os.remove(test_file)
        
    root.destroy()
    return True

if __name__ == "__main__":
    try:
        if test_security():
            print("Security Verification Successful")
            sys.exit(0)
        else:
            print("Security Verification Failed")
            sys.exit(1)
    except Exception as e:
        print(f"Test Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
