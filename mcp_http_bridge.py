#!/usr/bin/env python3
"""
MCP HTTP Bridge - Bridges stdio MCP protocol to HTTP MCP server
"""
import json
import sys
import requests
import uuid
from typing import Dict, Any

MCP_SERVER_URL = "http://127.0.0.1:5001/mcp/v1"

class MCPHttpBridge:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.session = requests.Session()
        self.initialized = False
    
    def send_request(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Send HTTP request to MCP server"""
        endpoint = f"{self.server_url}/{method.replace('/', '')}"
        
        try:
            if method == "initialize":
                response = self.session.post(f"{self.server_url}/initialize", json=params)
            elif method == "tools/list":
                response = self.session.post(f"{self.server_url}/tools/list", json=params or {})
            elif method == "tools/call":
                response = self.session.post(f"{self.server_url}/tools/call", json=params)
            else:
                return {"error": {"code": -32601, "message": f"Method not found: {method}"}}
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": {"code": response.status_code, "message": response.text}}
        except Exception as e:
            return {"error": {"code": -32603, "message": str(e)}}
    
    def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming MCP message"""
        method = message.get("method")
        params = message.get("params", {})
        
        if method == "initialize":
            result = self.send_request("initialize", params)
            self.initialized = True
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": result
            }
        elif method == "tools/list":
            result = self.send_request("tools/list", params)
            return {
                "jsonrpc": "2.0", 
                "id": message.get("id"),
                "result": result
            }
        elif method == "tools/call":
            result = self.send_request("tools/call", params)
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"), 
                "result": result
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }
    
    def run(self):
        """Main loop - read from stdin, write to stdout"""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
                
            try:
                message = json.loads(line)
                response = self.handle_message(message)
                print(json.dumps(response), flush=True)
            except json.JSONDecodeError:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"}
                }
                print(json.dumps(error_response), flush=True)
            except Exception as e:
                error_response = {
                    "jsonrpc": "2.0", 
                    "id": None,
                    "error": {"code": -32603, "message": str(e)}
                }
                print(json.dumps(error_response), flush=True)

if __name__ == "__main__":
    bridge = MCPHttpBridge(MCP_SERVER_URL)
    bridge.run()
