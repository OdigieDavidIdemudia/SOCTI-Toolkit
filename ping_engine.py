import subprocess
import re
import concurrent.futures
import platform

class PingEngine:
    def __init__(self, max_threads=10, timeout_ms=1000):
        self.max_threads = max_threads
        self.timeout_ms = timeout_ms
        self.is_windows = platform.system().lower() == 'windows'

    def ping_batch(self, items, callback=None):
        """
        Pings a list of items in parallel.
        items: list of dicts {'hostname': str, 'ip': str, 'id': any}
        callback: function to call with result {'id': ..., 'ping_status': ...}
        """
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_item = {executor.submit(self.ping_item, item): item for item in items}
            for future in concurrent.futures.as_completed(future_to_item):
                item = future_to_item[future]
                try:
                    data = future.result()
                except Exception as exc:
                    data = item.copy()
                    data['ping_status'] = 'Error'
                
                results.append(data)
                if callback:
                    callback(data)
        return results

    def ping_item(self, item):
        """
        Pings the IP or hostname of the item.
        Returns updated item dict with 'ping_status' field.
        """
        hostname = item.get('hostname', '').strip()
        ip = item.get('ip', '').strip()
        
        target = ip if ip else hostname
        
        if not target:
            return {**item, 'ping_status': 'Skip'}
            
        # Basic validation to prevent command injection
        if not re.match(r'^[a-zA-Z0-9.-]+$', target):
             return {**item, 'ping_status': 'Error (Invalid)'}

        cmd = []
        if self.is_windows:
            cmd = ["ping", "-n", "1", "-w", str(self.timeout_ms), target]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, self.timeout_ms // 1000)), target]

        try:
            startupinfo = None
            creationflags = 0
            if self.is_windows:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = 0 # SW_HIDE
                creationflags = subprocess.CREATE_NO_WINDOW
                
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=2 + (self.timeout_ms / 1000.0), # give subprocess slightly more time than ping wait
                startupinfo=startupinfo,
                creationflags=creationflags
            )
            
            output = result.stdout.lower()
            
            # Windows ping can return 0 exit code even for unreachable hosts so check the output
            if self.is_windows:
                if "unreachable" in output or "timed out" in output or "could not find host" in output or "failure" in output:
                    return {**item, 'ping_status': 'Dead'}
                if "ttl=" in output:
                    return {**item, 'ping_status': 'I\'m alive'}
            else:
                if result.returncode == 0:
                    return {**item, 'ping_status': 'I\'m alive'}
            
            # Default fallback
            return {**item, 'ping_status': 'Dead'}
            
        except Exception as e:
            return {**item, 'ping_status': 'Dead'}
