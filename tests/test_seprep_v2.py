import unittest
from unittest.mock import MagicMock, patch
import reputation

class TestSepRepV2(unittest.TestCase):
    def setUp(self):
        self.checker = reputation.ReputationChecker()
        # Mock sub-checkers
        self.checker.vt = MagicMock()
        self.checker.abuse = MagicMock()

    def test_check_vt_only(self):
        # Setup Mock
        self.checker.vt.check.return_value = {
            "source": "VirusTotal", "reputation": "Malicious", "malicious_score": 5
        }
        
        # Test
        res = self.checker.check_indicator("1.2.3.4", enable_vt=True, enable_abuse=False)
        
        # Assertions
        self.assertTrue("vt" in res)
        self.assertFalse("abuseip" in res)
        self.assertEqual(res["final_verdict"], "Malicious")
        self.checker.vt.check.assert_called_once()
        self.checker.abuse.check.assert_not_called()

    def test_check_abuse_only(self):
        # Setup Mock
        self.checker.abuse.check.return_value = {
            "source": "AbuseIPDB", "reputation": "Suspicious", "score": 20
        }
        
        # Test
        res = self.checker.check_indicator("1.2.3.4", enable_vt=False, enable_abuse=True)
        
        # Assertions
        self.assertFalse("vt" in res)
        self.assertTrue("abuseip" in res)
        self.assertEqual(res["final_verdict"], "Suspicious")
        self.checker.vt.check.assert_not_called()
        self.checker.abuse.check.assert_called_once()

    def test_check_both_merged(self):
        # Setup Mock
        self.checker.vt.check.return_value = {"reputation": "Safe"}
        self.checker.abuse.check.return_value = {"reputation": "Malicious"} # Conflict: Abuse says Malicious
        
        # Test
        res = self.checker.check_indicator("1.2.3.4", enable_vt=True, enable_abuse=True)
        
        # Assertions
        self.assertTrue("vt" in res)
        self.assertTrue("abuseip" in res)
        # Verdict Priority: Malicious > Suspicious > Safe
        self.assertEqual(res["final_verdict"], "Malicious") 

    def test_verdict_priority(self):
        # VT=Suspicious, Abuse=Safe -> Suspicious
        self.checker.vt.check.return_value = {"reputation": "Suspicious"}
        self.checker.abuse.check.return_value = {"reputation": "Safe"}
        res = self.checker.check_indicator("1.1.1.1", True, True)
        self.assertEqual(res["final_verdict"], "Suspicious")

if __name__ == '__main__':
    unittest.main()
