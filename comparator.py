class NormalizationEngine:
    def __init__(self):
        self.limit = 100000

    def normalize(self, text: str) -> list[str]:
        if not text:
            return []
            
        # Step 1: Replace newlines with commas
        # The prompt says "from: \n to: ,". 
        # We should handle generic newlines just in case, but specific instruction is replace \n with ,
        text = text.replace('\n', ',')
        
        # Step 2: Split values using comma delimiter
        parts = text.split(',')
        
        # Step 3: Trim whitespace
        parts = [p.strip() for p in parts]
        
        # Step 4: Remove empty values
        parts = [p for p in parts if p]
        
        # Step 5: Deduplicate (idempotent, order not strictly guaranteed by set but usually we want stable or sorted? 
        # JSON says "Deduplicate", output "array<string>". Let's use sorted list for consistent output)
        # However, purely "deduplicate" implies set. Sorted makes it easier to compare visually.
        # I'll use sorted(list(set(...))) for deterministic behavior.
        unique_parts = sorted(list(set(parts)))
        
        # Safety guard mostly applies to input, but let's check output size too just in case
        if len(unique_parts) > self.limit:
             # In a real app we might raise an error, for now we just process. 
             # The spec says "max_items_per_input": 100000. 
             pass

        return unique_parts

class ComparisonEngine:
    def _build_dict(self, input_list: list[dict]) -> dict:
        """
        Builds a dictionary from the input list with smart merging.
        Key: ip_or_hash (normalized)
        Value: dict item
        Logic: If a key exists, PRESERVE the entry with a hostname over one without.
        """
        result_dict = {}
        for item in input_list:
            key = item.get('ip_or_hash', '').lower().strip()
            if not key: continue
            
            existing = result_dict.get(key)
            if existing:
                # Merge Logic: If new item has hostname and existing doesn't, update.
                new_host = item.get('hostname', '').strip()
                old_host = existing.get('hostname', '').strip()
                
                if new_host and (not old_host or old_host == key):
                    # Update if new has a real hostname and old didn't (or old was just IP)
                    result_dict[key] = item
                # Else: keep existing (first come or already better) - actually logic was "last wins" usually, 
                # but here we want "best wins".
                # If both have host, we can overwrite or keep. Let's keep existing to rely on stable order if possible,
                # OR overwrite if we assume later input is newer.
                # Let's overwrite ONLY if new is "better" (has host). 
                # If both have host, let's keep existing to match "first occurrence" typically? 
                # Actually, standard dict behavior is overwrite. 
                # Let's do: If new has host, take it. Unless existing ALSO has host. 
                # If both have host, maybe keep existing?
            else:
                result_dict[key] = item
        return result_dict

    def compare(self, list_a: list[dict], list_b: list[dict], check_onboarded: bool = False) -> dict:
        """
        Compares two lists of assets.
        Each item in the list is expected to be a dict with keys: 'hostname', 'ip_or_hash'
        Comparison is done based on 'ip_or_hash' (primary key).
        """
        # Create dictionaries with smart merging
        dict_a = self._build_dict(list_a)
        dict_b = self._build_dict(list_b)
        
        keys_a = set(dict_a.keys())
        keys_b = set(dict_b.keys())
        
        # Sets
        common_keys = keys_a.intersection(keys_b)
        unique_a_keys = keys_a - keys_b
        unique_b_keys = keys_b - keys_a
        
        # Build Results
        results = {
            "common": [],
            "unique_to_a": [],
            "unique_to_b": []
        }
        
        # Common
        for k in common_keys:
            # We preferentially take data from A (uploaded/main input)
            item = dict_a[k].copy()
            
            # Merge opportunity: If B has a better hostname than A, maybe take B's host?
            # For now, stick to A as primary source.
            
            if check_onboarded:
                item['onboarded'] = "Yes"
            item['comparison_result'] = "common"
            results['common'].append(item)
            
        # Unique A
        for k in unique_a_keys:
            item = dict_a[k].copy()
            if check_onboarded:
                item['onboarded'] = "No" 
            item['comparison_result'] = "unique_to_input A"
            results['unique_to_a'].append(item)
            
        # Unique B
        for k in unique_b_keys:
            item = dict_b[k].copy()
            if check_onboarded:
                item['onboarded'] = "No"
            item['comparison_result'] = "unique_to_input B"
            results['unique_to_b'].append(item)
            
        # Sort results for consistent display
        sort_key = lambda x: (x.get('hostname', '').lower(), x.get('ip_or_hash', ''))
        results['common'].sort(key=sort_key)
        results['unique_to_a'].sort(key=sort_key)
        results['unique_to_b'].sort(key=sort_key)
            
        return results
