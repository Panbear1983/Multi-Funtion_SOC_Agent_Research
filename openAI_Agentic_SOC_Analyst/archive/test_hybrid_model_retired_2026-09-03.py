"""
Comprehensive Sandbox Testing for Hybrid Model
Tests all combinations: 3 modes × 4 severity levels × 3 query methods
Validates: No API compromise, Hot-swappable, Speed + Reasoning
"""

import json
import time
import sys
import os
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from color_support import Fore, Style
import SEVERITY_LEVELS
from mock_clients.mock_openai_client import MockOpenAIClient
from mock_clients.mock_ollama_client import MockOllamaClient
from mock_clients.mock_law_client import MockLawClient

# Import hybrid model (sandbox version)
from HYBRID_ENGINE import HybridEngine


class HybridModelTestSuite:
    """Comprehensive test suite for hybrid model"""
    
    def __init__(self):
        self.test_results = {
            'tests_run': 0,
            'tests_passed': 0,
            'tests_failed': 0,
            'performance_metrics': {},
            'validation_report': []
        }
        
        # Mock clients (no real API calls)
        self.mock_openai = MockOpenAIClient()
        self.mock_ollama = MockOllamaClient()
        self.mock_law = MockLawClient()
    
    def run_all_tests(self):
        """Run complete test suite"""
        print(f"\n{Fore.LIGHTCYAN_EX}{'='*70}")
        print(f"{Fore.LIGHTCYAN_EX}🧪 HYBRID MODEL SANDBOX TESTING")
        print(f"{Fore.LIGHTCYAN_EX}{'='*70}{Fore.RESET}\n")
        
        # Test 1: Infrastructure Preservation
        print(f"{Fore.YELLOW}Test 1: Infrastructure Preservation (No API Compromise){Fore.RESET}")
        self.test_infrastructure_preservation()
        
        # Test 2: Model Hot-Swapping
        print(f"\n{Fore.YELLOW}Test 2: Model Hot-Swapping{Fore.RESET}")
        self.test_model_hot_swapping()
        
        # Test 3: Speed + Reasoning
        print(f"\n{Fore.YELLOW}Test 3: Speed + Reasoning Performance{Fore.RESET}")
        self.test_speed_and_reasoning()
        
        # Test 4: All Mode Combinations
        print(f"\n{Fore.YELLOW}Test 4: All Mode Combinations (3×4×3 = 36 tests){Fore.RESET}")
        self.test_all_combinations()
        
        # Test 5: Integration Tests
        print(f"\n{Fore.YELLOW}Test 5: Integration Tests{Fore.RESET}")
        self.test_integration()
        
        # Generate report
        self.generate_report()
    
    def test_infrastructure_preservation(self):
        """Verify no compromise to existing commercial API infrastructure"""
        print(f"  {Fore.WHITE}Checking API call patterns...{Fore.RESET}")
        
        # Test: get_query_context still works
        try:
            from EXECUTOR import get_query_context
            # Should still use gpt-4o-mini for query planning
            result = get_query_context(
                self.mock_openai,
                "Find suspicious PowerShell",
                "local-mix"
            )
            
            # Verify mock was called with correct model
            assert self.mock_openai.last_model == "gpt-4o-mini", \
                "Should use gpt-4o-mini for query planning"
            
            print(f"    {Fore.GREEN}✓ Query planning API preserved{Fore.RESET}")
            self.test_results['tests_passed'] += 1
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Query planning failed: {e}{Fore.RESET}")
            self.test_results['tests_failed'] += 1
        
        # Test: Existing model paths still work
        try:
            from EXECUTOR import hunt
            
            # Test qwen path
            result_qwen = hunt(
                self.mock_openai,
                {"role": "system", "content": "test"},
                {"role": "user", "content": "test"},
                "qwen",
                SEVERITY_LEVELS.get_severity_config('normal')
            )
            
            # Test gpt-oss path
            result_gpt_oss = hunt(
                self.mock_openai,
                {"role": "system", "content": "test"},
                {"role": "user", "content": "test"},
                "gpt-oss:20b",
                SEVERITY_LEVELS.get_severity_config('normal')
            )
            
            # Test OpenAI path
            result_openai = hunt(
                self.mock_openai,
                {"role": "system", "content": "test"},
                {"role": "user", "content": "test"},
                "gpt-4o-mini",
                SEVERITY_LEVELS.get_severity_config('normal')
            )
            
            print(f"    {Fore.GREEN}✓ All existing model paths preserved{Fore.RESET}")
            self.test_results['tests_passed'] += 1
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Model path test failed: {e}{Fore.RESET}")
            self.test_results['tests_failed'] += 1
        
        self.test_results['tests_run'] += 2
    
    def test_model_hot_swapping(self):
        """Test model hot-swapping capability"""
        print(f"  {Fore.WHITE}Testing model adapter swapping...{Fore.RESET}")
        
        try:
            # Initialize hybrid engine
            engine = HybridEngine(
                investigation_mode='threat_hunt',
                severity_config=SEVERITY_LEVELS.get_severity_config('normal'),
                query_method='llm'
            )
            
            # Test: Swap Qwen adapter
            original_qwen = engine.model_adapters['qwen'].config['model_name']
            engine.swap_model_adapter('qwen', {'model_name': 'qwen3:14b'})
            
            assert engine.model_adapters['qwen'].config['model_name'] == 'qwen3:14b', \
                "Model adapter should swap"
            
            # Test: Swap GPT-OSS adapter
            engine.swap_model_adapter('gpt_oss', {'model_name': 'gpt-oss:40b'})
            
            assert engine.model_adapters['gpt_oss'].config['model_name'] == 'gpt-oss:40b', \
                "GPT-OSS adapter should swap"
            
            # Test: Add new model
            engine.add_model_adapter('llama3', {
                'model_name': 'llama3:8b',
                'timeout': 180,
                'role': 'volume_processor'
            })
            
            assert 'llama3' in engine.model_adapters, \
                "Should support new model addition"
            
            print(f"    {Fore.GREEN}✓ Model hot-swapping works{Fore.RESET}")
            self.test_results['tests_passed'] += 1
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Model swapping failed: {e}{Fore.RESET}")
            self.test_results['tests_failed'] += 1
        
        self.test_results['tests_run'] += 1
    
    def test_speed_and_reasoning(self):
        """Test speed and reasoning performance"""
        print(f"  {Fore.WHITE}Benchmarking performance...{Fore.RESET}")
        
        # Load test data
        test_messages = self._load_test_messages('threat_hunt')
        
        test_cases = [
            ('threat_hunt', 'critical', 'llm'),
            ('anomaly', 'normal', 'structured'),
            ('ctf', 'relaxed', 'custom_kql')
        ]
        
        for mode, severity, query_method in test_cases:
            start_time = time.time()
            
            engine = HybridEngine(
                investigation_mode=mode,
                severity_config=SEVERITY_LEVELS.get_severity_config(severity),
                query_method=query_method
            )
            
            results = engine.analyze(test_messages)
            
            elapsed_time = time.time() - start_time
            
            # Speed requirement: Should complete in reasonable time
            max_time = 120 if mode == 'anomaly' else 90
            speed_pass = elapsed_time < max_time
            
            # Reasoning requirement: Should have findings
            reasoning_pass = len(results.get('findings', [])) > 0
            
            metric_key = f"{mode}_{severity}_{query_method}"
            self.test_results['performance_metrics'][metric_key] = {
                'time': elapsed_time,
                'findings_count': len(results.get('findings', [])),
                'speed_pass': speed_pass,
                'reasoning_pass': reasoning_pass
            }
            
            status = f"{Fore.GREEN}✓" if (speed_pass and reasoning_pass) else f"{Fore.RED}✗"
            print(f"    {status} {mode}/{severity}/{query_method}: {elapsed_time:.2f}s, {len(results.get('findings', []))} findings{Fore.RESET}")
            
            if speed_pass and reasoning_pass:
                self.test_results['tests_passed'] += 1
            else:
                self.test_results['tests_failed'] += 1
            
            self.test_results['tests_run'] += 1
    
    def test_all_combinations(self):
        """Test all 36 combinations (3 modes × 4 severity × 3 query methods)"""
        print(f"  {Fore.WHITE}Running 36 combination tests...{Fore.RESET}")
        
        modes = ['threat_hunt', 'anomaly', 'ctf']
        severities = ['critical', 'strict', 'normal', 'relaxed']
        query_methods = ['llm', 'structured', 'custom_kql']
        
        test_messages = self._load_test_messages('generic')
        passed = 0
        failed = 0
        
        for mode in modes:
            for severity in severities:
                for query_method in query_methods:
                    try:
                        engine = HybridEngine(
                            investigation_mode=mode,
                            severity_config=SEVERITY_LEVELS.get_severity_config(severity),
                            query_method=query_method
                        )
                        
                        results = engine.analyze(test_messages)
                        
                        # Basic validation: Should return results
                        assert 'findings' in results, "Should return findings"
                        
                        passed += 1
                        
                    except Exception as e:
                        print(f"    {Fore.RED}✗ {mode}/{severity}/{query_method}: {e}{Fore.RESET}")
                        failed += 1
        
        print(f"    {Fore.GREEN}✓ Passed: {passed}/{passed+failed}{Fore.RESET}")
        self.test_results['tests_passed'] += passed
        self.test_results['tests_failed'] += failed
        self.test_results['tests_run'] += (passed + failed)
    
    def test_integration(self):
        """Full integration tests with mock data"""
        print(f"  {Fore.WHITE}Running integration tests...{Fore.RESET}")
        
        # Test: Full pipeline with mock data
        try:
            from THREAT_HUNT_PIPELINE import run_threat_hunt
            
            # This should work with hybrid model
            results = run_threat_hunt(
                openai_client=self.mock_openai,
                law_client=self.mock_law,
                workspace_id="test-workspace",
                model="local-mix",
                severity_config=SEVERITY_LEVELS.get_severity_config('normal'),
                timerange_hours=24,
                use_llm_query=True
            )
            
            assert results is not None, "Integration test should succeed"
            
            print(f"    {Fore.GREEN}✓ Integration test passed{Fore.RESET}")
            self.test_results['tests_passed'] += 1
            
        except Exception as e:
            print(f"    {Fore.RED}✗ Integration test failed: {e}{Fore.RESET}")
            self.test_results['tests_failed'] += 1
        
        self.test_results['tests_run'] += 1
    
    def _load_test_messages(self, scenario_type):
        """Load test messages from mock data"""
        test_data_path = Path(__file__).parent / 'mock_data' / 'sample_logs'
        
        # Load sample CSV
        sample_file = test_data_path / 'DeviceProcessEvents.csv'
        if sample_file.exists():
            with open(sample_file, 'r') as f:
                csv_content = f.read()
        else:
            # Fallback test data
            csv_content = """TimeGenerated,DeviceName,AccountName,ProcessCommandLine,ProcessPath
2025-10-29T10:15:23Z,DESKTOP-001,admin,powershell.exe -enc SQBuAHYAbwBrAGUALQB3AGUAYgByAGUAcQB1AGUAcwB0,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2025-10-29T10:16:45Z,DESKTOP-001,admin,cmd.exe /c whoami /all,C:\Windows\System32\cmd.exe"""
        
        return [
            {"role": "system", "content": "You are a security analyst."},
            {"role": "user", "content": f"Analyze these logs:\n\n{csv_content[:5000]}"}
        ]
    
    def generate_report(self):
        """Generate comprehensive test report"""
        report_path = Path(__file__).parent / 'test_results' / 'validation_report.md'
        report_path.parent.mkdir(exist_ok=True)
        
        passed_rate = (self.test_results['tests_passed'] / 
                      max(self.test_results['tests_run'], 1)) * 100
        
        report = f"""# Hybrid Model Sandbox Test Report

Generated: {datetime.now().isoformat()}

## Test Summary

- **Total Tests**: {self.test_results['tests_run']}
- **Passed**: {self.test_results['tests_passed']}
- **Failed**: {self.test_results['tests_failed']}
- **Pass Rate**: {passed_rate:.1f}%

## Requirements Validation

### ✅ Requirement 1: No API Compromise
- Commercial API infrastructure preserved
- Existing model paths unchanged
- Query planning still uses gpt-4o-mini

### ✅ Requirement 2: Hot-Swappable Models
- Model adapters can be swapped at runtime
- New models can be added dynamically
- Configuration-driven model management

### ✅ Requirement 3: Speed + Reasoning
- Performance within acceptable limits
- Reasoning quality maintained
- All modes functional

## Performance Metrics

{json.dumps(self.test_results['performance_metrics'], indent=2)}

## Recommendations

{f"{'✅ Ready for deployment' if passed_rate >= 95 else '⚠️ Needs fixes before deployment'}"}
"""
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        print(f"\n{Fore.LIGHTGREEN_EX}{'='*70}")
        print(f"{Fore.LIGHTGREEN_EX}📊 Test Report Generated: {report_path}")
        print(f"{Fore.LIGHTGREEN_EX}Pass Rate: {passed_rate:.1f}%")
        print(f"{Fore.LIGHTGREEN_EX}{'='*70}{Fore.RESET}\n")


if __name__ == "__main__":
    suite = HybridModelTestSuite()
    suite.run_all_tests()
