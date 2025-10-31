"""Mock Ollama client for testing (no actual API calls)"""

from datetime import datetime

class MockOllamaClient:
    """Mock Ollama client that returns predefined responses"""
    
    def __init__(self):
        self.call_history = []
        self.mock_responses = {
            'qwen3:8b': '{"findings": [{"title": "Mock Qwen finding", "confidence": "High", "description": "Suspicious PowerShell execution detected", "ioc": "powershell.exe -enc"}]}',
            'gpt-oss:20b': '{"findings": [{"title": "Mock GPT-OSS finding", "confidence": "High", "description": "Advanced threat pattern identified", "ioc": "encoded command", "tactic": "Execution"}]}'
        }
    
    def chat(self, messages, model_name, timeout=300, json_mode=True):
        """Mock chat method"""
        self.call_history.append({
            'model': model_name,
            'timeout': timeout,
            'timestamp': datetime.now().isoformat()
        })
        
        # Simulate processing time
        import time
        time.sleep(0.1)  # Fast mock
        
        return self.mock_responses.get(model_name, '{"findings": []}')
