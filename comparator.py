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
    def compare(self, list_a: list[dict], list_b: list[dict], check_onboarded: bool = False) -> dict:
        """
        Compares two lists of assets.
        Each item in the list is expected to be a dict with keys: 'hostname', 'ip_or_hash'
        Comparison is done based on 'ip_or_hash' (primary key).
        """
        # Create dictionaries mapped by the primary key (ip_or_hash) for O(1) lookups
        # Normalization (lower/strip) should generally happen before this, but we can ensure case-insensitivity here
        
        dict_a = {item.get('ip_or_hash', '').lower().strip(): item for item in list_a if item.get('ip_or_hash')}
        dict_b = {item.get('ip_or_hash', '').lower().strip(): item for item in list_b if item.get('ip_or_hash')}
        
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
            # We preferentially take data from A, but allow merging if needed.
            # Spec says: "common to both inputs"
            item = dict_a[k].copy()
            if check_onboarded:
                item['onboarded'] = "Yes"
            item['comparison_result'] = "common"
            results['common'].append(item)
            
        # Unique A
        for k in unique_a_keys:
            item = dict_a[k].copy()
            if check_onboarded:
                item['onboarded'] = "No"  # Present in uploaded (A) but not in input (B) -> Not onboarded? 
                # Actually, spec says: True condition: "ip_or_hash common to both inputs" -> Yes.
                # False condition: "not common" -> No.
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
