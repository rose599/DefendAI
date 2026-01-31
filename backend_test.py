import requests
import sys
import time
from datetime import datetime

class CyberDefenseAPITester:
    def __init__(self, base_url="https://cyberdefend-sim.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.failed_tests = []

    def run_test(self, name, method, endpoint, expected_status, data=None, timeout=30):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    return True, response.json()
                except:
                    return True, response.text
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}")
                self.failed_tests.append({
                    'test': name,
                    'expected': expected_status,
                    'actual': response.status_code,
                    'response': response.text[:200]
                })
                return False, {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            self.failed_tests.append({
                'test': name,
                'error': str(e)
            })
            return False, {}

    def test_basic_endpoints(self):
        """Test basic API endpoints"""
        print("\n=== TESTING BASIC ENDPOINTS ===")
        
        # Test root endpoint
        self.run_test("API Root", "GET", "", 200)
        
        # Test dashboard stats
        success, stats = self.run_test("Dashboard Stats", "GET", "dashboard/stats", 200)
        if success:
            print(f"   Total logs: {stats.get('total_logs', 0)}")
            print(f"   Total alerts: {stats.get('total_alerts', 0)}")
            print(f"   ML trained: {stats.get('ml_trained', False)}")
        
        return success, stats

    def test_simulation_workflow(self):
        """Test attack simulation workflow"""
        print("\n=== TESTING ATTACK SIMULATION ===")
        
        # Check initial status
        self.run_test("Simulation Status", "GET", "simulation/status", 200)
        
        # Start simulation
        config = {
            "attack_types": ["DoS", "Port Scan", "Brute Force"],
            "intensity": "medium"
        }
        success, _ = self.run_test("Start Simulation", "POST", "simulation/start", 200, config)
        
        if success:
            print("   Waiting 3 seconds for simulation to generate logs...")
            time.sleep(3)
            
            # Check status after start
            self.run_test("Simulation Status After Start", "GET", "simulation/status", 200)
            
            # Stop simulation
            self.run_test("Stop Simulation", "POST", "simulation/stop", 200)
        
        return success

    def test_logs_and_alerts(self):
        """Test logs and alerts endpoints"""
        print("\n=== TESTING LOGS & ALERTS ===")
        
        # Get logs
        success, logs = self.run_test("Get Logs", "GET", "logs?limit=10", 200)
        if success and logs:
            print(f"   Retrieved {len(logs)} logs")
            if logs:
                print(f"   Sample log: {logs[0].get('source_ip', 'N/A')} -> {logs[0].get('destination_ip', 'N/A')}")
        
        # Get alerts
        success, alerts = self.run_test("Get Alerts", "GET", "alerts?limit=10", 200)
        if success:
            print(f"   Retrieved {len(alerts) if alerts else 0} alerts")
        
        return success

    def test_ml_workflow(self):
        """Test ML training and metrics"""
        print("\n=== TESTING ML WORKFLOW ===")
        
        # Check initial ML metrics
        self.run_test("ML Metrics (Before Training)", "GET", "ml/metrics", 200)
        
        # Train ML model
        train_request = {"num_logs": 500}
        success, metrics = self.run_test("Train ML Model", "POST", "ml/train", 200, train_request, timeout=60)
        
        if success and metrics and 'error' not in metrics:
            print(f"   Training completed successfully")
            print(f"   Accuracy: {metrics.get('accuracy', 0):.3f}")
            print(f"   Training time: {metrics.get('training_time', 0):.2f}s")
            
            # Check metrics after training
            self.run_test("ML Metrics (After Training)", "GET", "ml/metrics", 200)
        else:
            print(f"   Training failed or returned error: {metrics}")
        
        return success

    def test_rl_workflow(self):
        """Test RL training workflow"""
        print("\n=== TESTING RL WORKFLOW ===")
        
        # Check initial RL metrics
        self.run_test("RL Metrics (Before Training)", "GET", "rl/metrics", 200)
        
        # Start RL training (background task)
        train_request = {"timesteps": 1000}
        success, _ = self.run_test("Start RL Training", "POST", "rl/train", 200, train_request)
        
        if success:
            print("   RL training started in background")
            print("   Waiting 5 seconds for some training progress...")
            time.sleep(5)
            
            # Check metrics after some training
            self.run_test("RL Metrics (After Training Start)", "GET", "rl/metrics", 200)
        
        return success

    def run_comprehensive_test(self):
        """Run all tests in sequence"""
        print("🚀 Starting Comprehensive CyberDefense API Testing")
        print(f"Testing against: {self.base_url}")
        print("=" * 60)
        
        # Test basic functionality first
        basic_success, stats = self.test_basic_endpoints()
        
        # Test simulation workflow
        sim_success = self.test_simulation_workflow()
        
        # Test logs and alerts
        logs_success = self.test_logs_and_alerts()
        
        # Test ML workflow
        ml_success = self.test_ml_workflow()
        
        # Test RL workflow
        rl_success = self.test_rl_workflow()
        
        # Final dashboard check
        print("\n=== FINAL DASHBOARD CHECK ===")
        final_success, final_stats = self.run_test("Final Dashboard Stats", "GET", "dashboard/stats", 200)
        if final_success:
            print(f"   Final total logs: {final_stats.get('total_logs', 0)}")
            print(f"   Final total alerts: {final_stats.get('total_alerts', 0)}")
            print(f"   ML trained: {final_stats.get('ml_trained', False)}")
            print(f"   RL trained: {final_stats.get('rl_trained', False)}")
        
        # Print summary
        print("\n" + "=" * 60)
        print(f"📊 TESTING SUMMARY")
        print(f"Tests passed: {self.tests_passed}/{self.tests_run}")
        print(f"Success rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        
        if self.failed_tests:
            print(f"\n❌ FAILED TESTS:")
            for failure in self.failed_tests:
                error_msg = failure.get('error', f"Expected {failure.get('expected')}, got {failure.get('actual')}")
                print(f"   - {failure.get('test', 'Unknown')}: {error_msg}")
        
        return self.tests_passed == self.tests_run

def main():
    tester = CyberDefenseAPITester()
    success = tester.run_comprehensive_test()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())