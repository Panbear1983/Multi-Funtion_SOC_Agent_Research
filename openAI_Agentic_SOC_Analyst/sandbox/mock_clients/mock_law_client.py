"""Mock Azure Log Analytics client for testing (no actual API calls)"""

from datetime import datetime

class MockLawClient:
    """Mock Azure Log Analytics client that returns predefined responses"""
    
    def __init__(self):
        self.call_history = []
        self.mock_data = {
            'DeviceProcessEvents': """TimeGenerated,DeviceName,AccountName,ProcessCommandLine,ProcessPath
2025-10-29T10:15:23Z,DESKTOP-001,admin,powershell.exe -enc SQBuAHYAbwBrAGUALQB3AGUAYgByAGUAcQB1AGUAcwB0,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2025-10-29T10:16:45Z,DESKTOP-001,admin,cmd.exe /c whoami /all,C:\Windows\System32\cmd.exe
2025-10-29T10:17:12Z,DESKTOP-001,admin,net user /domain,C:\Windows\System32\net.exe"""
        }
    
    def query_workspace(self, workspace_id, query, timespan):
        """Mock query workspace method"""
        self.call_history.append({
            'workspace_id': workspace_id,
            'query': query,
            'timespan': timespan,
            'timestamp': datetime.now().isoformat()
        })
        
        # Return mock data
        class MockResponse:
            def __init__(self, data):
                self.tables = [MockTable(data)]
                self.partial_error = None
        
        class MockTable:
            def __init__(self, data):
                self.rows = data.split('\n')[1:]  # Skip header
                self.columns = data.split('\n')[0].split(',')
        
        return MockResponse(self.mock_data.get('DeviceProcessEvents', ''))
