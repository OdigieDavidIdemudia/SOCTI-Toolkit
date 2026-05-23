import re

class LDAPFilterGenerator:
    """
    Generates a single LDAP filter from a list of values (usernames, IDs, etc.).
    """
    
    def __init__(self):
        # LDAP Special Characters that need escaping in filter values
        # Reference: RFC 4515
        self.special_chars = {
            '\\': '\\5c',
            '*': '\\2a',
            '(': '\\28',
            ')': '\\29',
            '\0': '\\00'
        }
        self.escape_re = re.compile('|'.join(re.escape(k) for k in self.special_chars.keys()))

    def normalize_value(self, value):
        """
        Normalizes values (typically names) to a consistent first.last format:
        - Replaces spaces and existing dots with a single dot
        - Converts to lowercase
        - Strips leading/trailing whitespace
        """
        if not value:
            return ""
        # 1. Lowercase and strip
        val = value.strip().lower()
        # 2. Replace one or more spaces/dots with a single dot
        val = re.sub(r'[\s\.]+', '.', val)
        return val

    def escape_ldap_value(self, value):
        """
        Escapes special characters in a value to be used in an LDAP filter.
        """
        if not value:
            return ""
        return self.escape_re.sub(lambda m: self.special_chars[m.group(0)], value)

    def generate_filter(self, items, attribute="CN"):
        """
        Generates an OR-joined LDAP filter for the given items.
        
        items: List of strings (e.g. ['david odigie', 'PETER MICHEAL'])
        attribute: The LDAP attribute to match (e.g. 'CN', 'sAMAccountName')
        
        Returns: String (LDAP filter)
        """
        # Clean, normalize and deduplicate items
        clean_items = []
        seen = set()
        for item in items:
            val = self.normalize_value(item)
            if val and val not in seen:
                clean_items.append(val)
                seen.add(val)
        
        if not clean_items:
            return ""

        # Wrap each item: (attribute=escaped_value)
        conditions = [f"({attribute}={self.escape_ldap_value(item)})" for item in clean_items]
        
        # Join with OR: (|(cond1)(cond2)...)
        # Note: If only one item, the OR block is still valid but could be simplified.
        # User request explicitly asked for the OR block structure.
        or_block = f"(|{''.join(conditions)})"
        
        # Wrap in user object restrictions: (&(objectCategory=person)(objectClass=user)(|...))
        final_filter = f"(&(objectCategory=person)(objectClass=user){or_block})"
        
        return final_filter

if __name__ == "__main__":
    # Small test
    gen = LDAPFilterGenerator()
    test_users = ["user1", "user2 (test)", "admin*"]
    print(f"Input: {test_users}")
    print(f"Filter: {gen.generate_filter(test_users, 'sAMAccountName')}")
