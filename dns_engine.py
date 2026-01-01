import subprocess
import re
import concurrent.futures
import platform

class DNSLookupEngine:
    def __init__(self, max_threads=5, timeout=3):
        self.max_threads = max_threads
        self.timeout = timeout
        # Determine shell based on platform, though requirement implies Windows/Powershell focus
        self.is_windows = platform.system().lower() == 'windows'

    def resolve_batch(self, items, callback=None):
        """
        Resolves a list of items in parallel.
        items: list of dicts {'hostname': str, 'ip': str, 'id': any}
        callback: function to call with result {'id': ..., 'hostname': ..., 'ip': ..., 'status': ...}
        """
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_item = {executor.submit(self.resolve_item, item): item for item in items}
            for future in concurrent.futures.as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    data = future.result()
                except Exception as exc:
                    data = item.copy()
                    data['status'] = 'Unresolved'
                    data['error'] = str(exc)
                
                results.append(data)
                if callback:
                    callback(data)
        return results

    def resolve_item(self, item):
        """
        Decides whether to perform forward or reverse lookup.
        Returns updated item dict with 'status' field.
        """
        hostname = item.get('hostname', '').strip()
        ip = item.get('ip', '').strip()
        
        # Strict Input Validation (Security)
        # Ensure hostname and IP only contain safe characters to prevent any command injection or tool misuse.
        # Although subprocess list-args is safe, this is defense-in-depth.
        if hostname and not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
             return {**item, 'status': 'Unresolved', 'error': 'Invalid Hostname Format'}
        
        if ip and not re.match(r'^[0-9.]+$', ip):
              return {**item, 'status': 'Unresolved', 'error': 'Invalid IP Format'}

        # Condition 3: skip if both present
        if hostname and ip:
            return {**item, 'status': 'Skipped'}

        # Condition 1: Forward (Hostname present, IP missing)
        if hostname and not ip:
            res_ip = self.forward_lookup(hostname)
            if res_ip:
                return {**item, 'ip': res_ip, 'status': 'Resolved'}
            else:
                # User request: blank if not found, status "Not Found"
                return {**item, 'ip': '', 'status': 'Not Found'}

        # Condition 2: Reverse (IP present, Hostname missing)
        if ip and not hostname:
            res_host = self.reverse_lookup(ip)
            if res_host:
                return {**item, 'hostname': res_host, 'status': 'Resolved'}
            else:
                return {**item, 'hostname': '', 'status': 'Not Found'}

        return {**item, 'status': 'Unresolved', 'error': 'No input'}

    def _run_command_silent(self, cmd):
        """Helper to run commands silently (no window on Windows)"""
        startupinfo = None
        creationflags = 0
        
        if self.is_windows:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0 # SW_HIDE
            creationflags = subprocess.CREATE_NO_WINDOW
            
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=self.timeout,
                startupinfo=startupinfo,
                creationflags=creationflags
            )
            return result
        except Exception:
            return None

    def forward_lookup(self, hostname):
        """
        Executes nslookup {hostname}
        """
        cmd = ["nslookup", hostname]

        try:
            result = self._run_command_silent(cmd)
            if result and result.returncode == 0:
                output = result.stdout
                
                # Regex for IP
                ipv4_regex = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
                
                # Context-aware parsing
                if "Name:" in output:
                    parts = output.split("Name:")
                    if len(parts) > 1:
                        target_part = parts[1]
                        ip_matches = re.findall(ipv4_regex, target_part)
                        if ip_matches:
                            return ip_matches[0]
                
                # Fallback
                matches = re.findall(ipv4_regex, output)
                if len(matches) > 1:
                    return matches[-1] 
                elif len(matches) == 1:
                    return matches[0]
                
        except Exception:
            return None
            
        return None

    def reverse_lookup(self, ip):
        """
        Executes nslookup {ip}
        """
        cmd = ["nslookup", ip]
        try:
            result = self._run_command_silent(cmd)
            if result and result.returncode == 0:
                output = result.stdout
                
                if "Name:" in output:
                     match = re.search(r"Name:\s+([a-zA-Z0-9.-]+)", output)
                     if match:
                         return match.group(1).strip()
        except:
            pass
        return None
