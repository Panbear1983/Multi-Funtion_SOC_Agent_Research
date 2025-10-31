"""Mock OpenAI client for testing (no actual API calls)"""

from datetime import datetime

class MockOpenAIClient:
    """Mock OpenAI client that returns predefined responses"""
    
    def __init__(self):
        self.call_history = []
        self.last_model = None
        self.mock_responses = {
            'gpt-4o-mini': {
                'tool_calls': [{
                    'function': {
                        'arguments': '{"table_name": "DeviceProcessEvents", "device_name": "", "account_name": "", "fields": "TimeGenerated,DeviceName,AccountName,ProcessCommandLine,ProcessPath"}'
                    }
                }]
            }
        }
    
    def chat(self, **kwargs):
        """Mock chat completions create method"""
        model = kwargs.get('model', 'gpt-4o-mini')
        self.last_model = model
        
        self.call_history.append({
            'model': model,
            'messages': kwargs.get('messages', []),
            'timestamp': datetime.now().isoformat()
        })
        
        # Return mock response
        class MockResponse:
            def __init__(self, data):
                self.choices = [MockChoice(data)]
        
        class MockChoice:
            def __init__(self, data):
                self.message = MockMessage(data)
        
        class MockMessage:
            def __init__(self, data):
                self.tool_calls = data.get('tool_calls', [])
                self.content = data.get('content', '')
        
        return MockResponse(self.mock_responses.get(model, {}))
