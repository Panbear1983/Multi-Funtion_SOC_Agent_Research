"""
Microsoft Defender for Endpoint (MDE) Advanced Hunting Client
Provides direct access to MDE tables via Advanced Hunting API
"""

import requests
import json
from datetime import datetime, timedelta
from color_support import Fore

class MDEClient:
    """Client for MDE Advanced Hunting API"""
    
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = None
        
        self.auth_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        self.api_url = "https://api.securitycenter.microsoft.com/api/advancedhunting/run"
    
    def _get_access_token(self):
        """Authenticate and get access token"""
        
        # Check if token is still valid
        if self.token and self.token_expiry and datetime.now() < self.token_expiry:
            return self.token
        
        # Request new token
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://api.securitycenter.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(self.auth_url, data=payload)
            response.raise_for_status()
            
            token_data = response.json()
            self.token = token_data['access_token']
            
            # Token typically valid for 1 hour
            expires_in = token_data.get('expires_in', 3600)
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 300)  # 5 min buffer
            
            return self.token
            
        except Exception as e:
            print(f"{Fore.RED}MDE Authentication Error: {e}{Fore.RESET}")
            raise
    
    def query_advanced_hunting(self, kql_query):
        """
        Execute KQL query against MDE Advanced Hunting
        
        Args:
            kql_query (str): KQL query string
            
        Returns:
            dict: Response with 'tables' structure compatible with Azure Log Analytics format
        """
        
        token = self._get_access_token()
        
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'Query': kql_query
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=300)
            response.raise_for_status()
            
            data = response.json()
            
            # Convert MDE response format to match Azure Log Analytics format
            # MDE returns: { "Schema": [...], "Results": [...] }
            # We need to match Azure format for compatibility
            
            schema = data.get('Schema', [])
            results = data.get('Results', [])
            
            # Build column names from schema
            columns = [col['Name'] for col in schema]
            
            # Convert results (array of dicts) to rows (array of arrays)
            rows = []
            for result in results:
                row = [result.get(col, '') for col in columns]
                rows.append(row)
            
            # Create Azure-compatible response structure
            class MockTable:
                def __init__(self, columns, rows):
                    self.columns = columns
                    self.rows = rows
            
            class MockResponse:
                def __init__(self, tables):
                    self.tables = tables
            
            mock_table = MockTable(columns, rows)
            mock_response = MockResponse([mock_table])
            
            return mock_response
            
        except requests.exceptions.HTTPError as e:
            error_detail = ""
            try:
                error_data = e.response.json()
                error_detail = error_data.get('error', {}).get('message', str(e))
            except:
                error_detail = str(e)
            
            print(f"{Fore.RED}MDE Query Error: {error_detail}{Fore.RESET}")
            raise
        
        except Exception as e:
            print(f"{Fore.RED}MDE Error: {e}{Fore.RESET}")
            raise


def create_mde_client(tenant_id, client_id, client_secret):
    """Factory function to create MDE client"""
    return MDEClient(tenant_id, client_id, client_secret)

