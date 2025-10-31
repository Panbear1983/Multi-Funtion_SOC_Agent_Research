#!/usr/bin/env python3
"""
Run sandbox tests before deployment
Usage: python sandbox/run_tests.py
"""

import sys
from pathlib import Path

# Ensure we're in the right directory
sandbox_dir = Path(__file__).parent
sys.path.insert(0, str(sandbox_dir.parent))

from test_hybrid_model import HybridModelTestSuite
from color_support import Fore

if __name__ == "__main__":
    print(f"\n{'='*70}")
    print("🧪 Starting Sandbox Tests")
    print("="*70 + "\n")
    
    suite = HybridModelTestSuite()
    suite.run_all_tests()
    
    # Exit with error code if tests failed
    if suite.test_results['tests_failed'] > 0:
        print(f"\n{Fore.RED}❌ Some tests failed! Check the report before deployment.{Fore.RESET}\n")
        sys.exit(1)
    else:
        print(f"\n{Fore.LIGHTGREEN_EX}✅ All tests passed! Ready for deployment.{Fore.RESET}\n")
        sys.exit(0)
