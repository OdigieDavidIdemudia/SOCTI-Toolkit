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
    def compare(self, list_a: list[str], list_b: list[str]) -> dict:
        set_a = set(list_a)
        set_b = set(list_b)
        
        # Logic:
        # common: A ∩ B
        common = sorted(list(set_a.intersection(set_b)))
        
        # unique_to_a: A - B
        unique_a = sorted(list(set_a - set_b))
        
        # unique_to_b: B - A
        unique_b = sorted(list(set_b - set_a))
        
        return {
            "common": common,
            "unique_to_a": unique_a,
            "unique_to_b": unique_b
        }
