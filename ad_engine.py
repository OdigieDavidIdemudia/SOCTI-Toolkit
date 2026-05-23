import subprocess
import json
import concurrent.futures
import platform
import re
from datetime import datetime

class ADEngine:
    def __init__(self, max_threads=5):
        self.max_threads = max_threads
        self.is_windows = platform.system().lower() == 'windows'

    def _parse_ps_date(self, date_str):
        """
        Parses PowerShell's JSON date format /Date(milliseconds)/ into a human-readable string.
        """
        if not isinstance(date_str, str) or not date_str.startswith('/Date('):
            return date_str
            
        try:
            # Extract milliseconds using regex
            match = re.search(r'\((\d+)\)', date_str)
            if match:
                ms = int(match.group(1))
                # Convert to seconds
                dt = datetime.fromtimestamp(ms / 1000.0)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
        return date_str

    def _process_ad_data(self, data):
        """
        Post-processes AD data to fix formatting issues (like dates).
        """
        if not isinstance(data, dict):
            return data
            
        new_data = {}
        for k, v in data.items():
            if isinstance(v, str) and v.startswith('/Date('):
                new_data[k] = self._parse_ps_date(v)
            elif isinstance(v, list):
                # Recursively check lists (like MemberOf) just in case, 
                # though MemberOf usually contains strings.
                new_data[k] = [self._process_ad_data(i) if isinstance(i, dict) else i for i in v]
            else:
                new_data[k] = v
        return new_data


    def query_batch(self, target_types, items, callback=None):
        """
        Executes AD queries for a list of items across multiple target types.
        target_types: list of 'Users', 'Computers', or 'Groups'
        items: list of names/strings
        callback: function to call with result dict
        """
        if not self.is_windows:
            # AD Queries usually require Windows / PowerShell setup
            error_res = [{"id": i, "Target": item, "Status": "Error: Not Windows", "Details": ""} for i, item in enumerate(items)]
            if callback:
                for r in error_res: callback(r)
            return error_res

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # For each item, try each active target type.
            # We will generate a separate search per target type.
            idx = 0
            future_to_req = {}
            for item in items:
                for ttype in target_types:
                    future = executor.submit(self.query_item, ttype, item, idx)
                    future_to_req[future] = (item, ttype, idx)
                    idx += 1
                    
            for future in concurrent.futures.as_completed(future_to_req):
                item, ttype, cur_idx = future_to_req[future]
                try:
                    data = future.result()
                except Exception as exc:
                    data = {"id": cur_idx, "Target": item, "Type": ttype, "Status": "Error", "Details": str(exc)}
                
                # Only callback if it's a success or if it's the last attempt that fails to avoid spamming "Not Found" individually
                results.append(data)
                if callback:
                    callback(data)
        
        results.sort(key=lambda x: x.get('id', 0))
        return results

    def query_item(self, target_type, item, idx):
        """
        Executes Get-ADUser, Get-ADComputer, or Get-ADGroup via PowerShell.
        """
        item = item.strip()
        if not item:
            return {"id": idx, "Target": "", "Status": "Skip", "Details": ""}
            
        cmd = ""
        # Be careful with injection: Since item might contain spaces, wrap in quotes
        # It's generally safer to just pass it directly if we restrict characters, but in AD names can have spaces
        safe_item = item.replace("'", "''") # escape single quotes for powershell
        
        if target_type == "Users":
            # Example properties: Enabled, LastLogonDate, PasswordLastSet, Description, MemberOf
            cmd = f"Get-ADUser -Identity '{safe_item}' -Properties Enabled,LastLogonDate,PasswordLastSet,Description,MemberOf | Select-Object Name,Enabled,LastLogonDate,PasswordLastSet,Description,SamAccountName,MemberOf | ConvertTo-Json -Compress -Depth 2"
        elif target_type == "Computers":
            cmd = f"Get-ADComputer -Identity '{safe_item}' -Properties Enabled,LastLogonDate,OperatingSystem,IPv4Address,MemberOf | Select-Object Name,Enabled,LastLogonDate,OperatingSystem,IPv4Address,MemberOf | ConvertTo-Json -Compress -Depth 2"
        elif target_type == "Groups":
            cmd = f"Get-ADGroup -Identity '{safe_item}' -Properties Description,GroupCategory,GroupScope | Select-Object Name,Description,GroupCategory,GroupScope | ConvertTo-Json -Compress -Depth 2"
        else:
            return {"id": idx, "Target": item, "Type": target_type, "Status": "Error", "Details": "Unknown Target Type"}

        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0 # SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW
            
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmd], 
                capture_output=True, 
                text=True, 
                timeout=15,
                startupinfo=startupinfo,
                creationflags=creationflags
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    ad_data = json.loads(result.stdout.strip())
                    # Post-process to fix dates and other formatting issues
                    processed_data = self._process_ad_data(ad_data)
                    return {"id": idx, "Target": item, "Type": target_type, "Status": "Success", "Details": processed_data}
                except json.JSONDecodeError:
                    return {"id": idx, "Target": item, "Type": target_type, "Status": "Parse Error", "Details": result.stdout.strip()}
            else:
                err = result.stderr.strip()
                if "Cannot find an object with identity" in err:
                    return {"id": idx, "Target": item, "Type": target_type, "Status": "Not Found", "Details": ""}
                return {"id": idx, "Target": item, "Type": target_type, "Status": "Failed", "Details": err}
                
        except subprocess.TimeoutExpired:
             return {"id": idx, "Target": item, "Type": target_type, "Status": "Timeout", "Details": ""}
        except Exception as e:
             return {"id": idx, "Target": item, "Type": target_type, "Status": "Error", "Details": str(e)}
