import os
import unittest
import database
import scanner

class TestReconX(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Initializing the database for testing
        database.init_db()
        
    def test_database_user_creation_and_auth(self):
        # Test creating user and verifying password hashing
        test_email = "tester@reconx.local"
        # Cleanup if left over
        conn = database.get_db_connection()
        conn.execute("DELETE FROM users WHERE email = ?", (test_email,))
        conn.commit()
        conn.close()
        
        uid = database.create_user("tester", test_email, "securepass123", "Researcher")
        self.assertIsNotNone(uid)
        
        # Verify login success
        user = database.verify_user(test_email, "securepass123")
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], "tester")
        self.assertEqual(user['role'], "Researcher")
        
        # Verify login failure with bad pass
        bad_user = database.verify_user(test_email, "wrongpassword")
        self.assertIsNone(bad_user)

    def test_scanner_passive_results(self):
        # Run real passive scans
        res = scanner.run_recon_scan("example.com", ["dns", "ip", "ssl"])
        self.assertEqual(res["target"], "example.com")
        
        # Verify presence of modules
        self.assertIn("dns", res["modules"])
        self.assertIn("ip", res["modules"])
        self.assertIn("ssl", res["modules"])
        
    def test_scanner_simulation_results(self):
        # Run active simulation modules
        res = scanner.run_recon_scan("example.com", ["portscan", "subdomains", "directory"])
        
        self.assertIn("portscan", res["modules"])
        self.assertIn("subdomains", res["modules"])
        self.assertIn("directory", res["modules"])
        
        # Check high-fidelity simulation properties
        ports = res["modules"]["portscan"]["ports"]
        self.assertTrue(len(ports) > 0)
        self.assertEqual(ports[0]["service"], "ssh")
        
        subdomains = res["modules"]["subdomains"]["subdomains"]
        self.assertTrue(len(subdomains) >= 2)
        
        paths = res["modules"]["directory"]["paths"]
        self.assertTrue(len(paths) > 0)

if __name__ == '__main__':
    unittest.main()
