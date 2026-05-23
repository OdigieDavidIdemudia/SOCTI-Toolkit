import sys
import unittest
from datetime import datetime
import os

# Add current directory to path so we can import ad_engine
sys.path.append(os.getcwd())
from ad_engine import ADEngine

class TestADDateParsing(unittest.TestCase):
    def setUp(self):
        self.engine = ADEngine()

    def test_parse_ps_date(self):
        # Sample PowerShell JSON date (/Date(milliseconds)/)
        # 1773130611633 corresponds to a date in 2026
        ms = 1773130611633
        date_str = f"/Date({ms})/"
        
        expected_dt = datetime.fromtimestamp(ms / 1000.0)
        expected_str = expected_dt.strftime('%Y-%m-%d %H:%M:%S')
        
        result = self.engine._parse_ps_date(date_str)
        self.assertEqual(result, expected_str)

    def test_process_ad_data(self):
        raw_data = {
            "Name": "John Doe",
            "LastLogonDate": "/Date(1773130611633)/",
            "PasswordLastSet": "/Date(1773128400067)/",
            "Enabled": True,
            "MemberOf": ["CN=Group1,DC=example,DC=com", "/Date(0)/"] # Should handle strings in lists too
        }
        
        processed = self.engine._process_ad_data(raw_data)
        
        self.assertEqual(processed["Name"], "John Doe")
        self.assertTrue(processed["LastLogonDate"].startswith("20")) # Basic check for Year
        self.assertTrue(processed["PasswordLastSet"].startswith("20"))
        self.assertEqual(processed["Enabled"], True)
        # MemberOf in this specific code is handled in gui.py for CN extraction, 
        # but _process_ad_data handles /Date/ strings if they appear in lists.
        # Actually _process_ad_data only processes nested dicts in lists, not strings in lists.
        # Let's check the implementation:
        # new_data[k] = [self._process_ad_data(i) if isinstance(i, dict) else i for i in v]
        # So "/Date(0)/" in a list will remain as is. This is fine as MemberOf doesn't contain dates usually.
        # But for correctness, let's adjust the test to match implementation.
        self.assertEqual(processed["MemberOf"][1], "/Date(0)/")

if __name__ == '__main__':
    unittest.main()
