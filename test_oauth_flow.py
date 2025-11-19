"""Test OAuth flow and MCP functionality."""
import asyncio
import httpx
import json
import config


async def test_oauth_flow():
    """Test the complete OAuth flow with Authorization Code Grant."""
    print("=" * 60)
    print("Testing OAuth MCP Demo (Authorization Code Grant)")
    print("=" * 60)
    
    async with httpx.AsyncClient() as client:
        # Step 1: Check OAuth server health
        print("\n[1/8] Checking OAuth server health...")
        try:
            response = await client.get(f"{config.OAUTH_ISSUER}/health")
            print(f"✓ OAuth server is running: {response.json()}")
        except Exception as e:
            print(f"✗ OAuth server is not running: {e}")
            return
        
        # Step 2: Check MCP server health
        print("\n[2/8] Checking MCP server health...")
        try:
            response = await client.get(f"{config.MCP_SERVER_URL}/health")
            print(f"✓ MCP server is running: {response.json()}")
        except Exception as e:
            print(f"✗ MCP server is not running: {e}")
            return
        
        # Step 3: Test MCP Initialize
        print("\n[3/8] Testing MCP initialize endpoint...")
        try:
            response = await client.post(
                f"{config.MCP_SERVER_URL}/mcp/v1/initialize",
                json={
                    'protocolVersion': '2024-11-05',
                    'capabilities': {},
                    'clientInfo': {
                        'name': 'test-client',
                        'version': '1.0.0'
                    }
                }
            )
            response.raise_for_status()
            init_response = response.json()
            print(f"✓ MCP initialized successfully")
            print(f"  Server: {init_response['serverInfo']['name']} v{init_response['serverInfo']['version']}")
        except Exception as e:
            print(f"✗ MCP initialization failed: {e}")
            return
        
        # Step 4: Dynamic Client Registration
        print("\n[4/8] Registering OAuth client...")
        registration_data = {
            'client_name': 'Test Client',
            'redirect_uris': ['http://localhost:8080/callback'],
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'client_secret_post',
            'scope': 'read write',
        }
        
        try:
            response = await client.post(
                f"{config.OAUTH_ISSUER}/oauth/register",
                json=registration_data
            )
            response.raise_for_status()
            client_info = response.json()
            print(f"✓ Client registered successfully")
            print(f"  Client ID: {client_info['client_id']}")
            print(f"  Client Secret: {client_info['client_secret'][:20]}...")
        except Exception as e:
            print(f"✗ Client registration failed: {e}")
            return
        
        # Step 5: Get Authorization Code (Authorization Code Grant)
        print("\n[5/8] Getting authorization code...")
        auth_params = {
            'response_type': 'code',
            'client_id': client_info['client_id'],
            'redirect_uri': 'http://localhost:8080/callback',
            'scope': 'read write',
            'state': 'random_state_string',
        }
        
        try:
            # Request authorization (auto-approved in demo)
            auth_response = await client.get(
                f"{config.OAUTH_ISSUER}/oauth/authorize",
                params=auth_params,
                follow_redirects=False
            )
            
            # Extract authorization code from redirect
            if auth_response.status_code in [302, 303]:
                location = auth_response.headers.get('Location', '')
                if 'code=' in location:
                    import urllib.parse
                    parsed = urllib.parse.urlparse(location)
                    params = urllib.parse.parse_qs(parsed.query)
                    auth_code = params.get('code', [None])[0]
                    print(f"✓ Authorization code obtained: {auth_code[:20]}...")
                else:
                    print(f"✗ No authorization code in redirect: {location}")
                    return
            else:
                print(f"✗ Authorization failed with status: {auth_response.status_code}")
                return
        except Exception as e:
            print(f"✗ Authorization request failed: {e}")
            return
        
        # Step 6: Exchange Authorization Code for Access Token
        print("\n[6/8] Exchanging authorization code for access token...")
        token_data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': 'http://localhost:8080/callback',
            'client_id': client_info['client_id'],
            'client_secret': client_info['client_secret'],
        }
        
        try:
            response = await client.post(
                f"{config.OAUTH_ISSUER}/oauth/token",
                data=token_data
            )
            response.raise_for_status()
            token_response = response.json()
            access_token = token_response['access_token']
            print(f"✓ Access token obtained")
            print(f"  Token Type: {token_response.get('token_type', 'Bearer')}")
            print(f"  Expires In: {token_response.get('expires_in', 3600)} seconds")
            print(f"  Scope: {token_response.get('scope', '')}")
        except Exception as e:
            print(f"✗ Token exchange failed: {e}")
            return
        
        # Step 7: Access Protected Resource (GET)
        print("\n[7/8] Accessing protected resource (GET /api/data)...")
        headers = {
            'Authorization': f"Bearer {access_token}"
        }
        
        try:
            response = await client.get(
                f"{config.MCP_SERVER_URL}/api/data",
                headers=headers
            )
            response.raise_for_status()
            data = response.json()
            print(f"✓ Successfully accessed protected resource")
            print(f"  Data: {json.dumps(data, indent=2)}")
        except Exception as e:
            print(f"✗ Failed to access protected resource: {e}")
            return
        
        # Step 8: Create Data (POST)
        print("\n[8/8] Creating new data (POST /api/data)...")
        new_data = {
            'name': 'Test Item',
            'value': 999
        }
        
        try:
            response = await client.post(
                f"{config.MCP_SERVER_URL}/api/data",
                headers=headers,
                json=new_data
            )
            response.raise_for_status()
            result = response.json()
            print(f"✓ Successfully created new data")
            print(f"  Result: {json.dumps(result, indent=2)}")
        except Exception as e:
            print(f"✗ Failed to create data: {e}")
            return
        
        print("\n" + "=" * 60)
        print("All tests passed! ✓")
        print("=" * 60)
        print("\nAuthorization Code Grant flow completed successfully!")
        print("This flow included:")
        print("  1. Client registration")
        print("  2. Authorization request (auto-approved)")
        print("  3. Authorization code exchange")
        print("  4. Access token obtained with refresh token")
        print(f"\nMCP Base URL: {config.MCP_SERVER_URL}")
        print(f"MCP Endpoints:")
        print(f"  - Initialize: {config.MCP_SERVER_URL}/mcp/v1/initialize")
        print(f"  - List Tools: {config.MCP_SERVER_URL}/mcp/v1/tools/list")
        print(f"  - Call Tool:  {config.MCP_SERVER_URL}/mcp/v1/tools/call")
        print(f"  - SSE Stream: {config.MCP_SERVER_URL}/mcp/v1/sse")


if __name__ == "__main__":
    asyncio.run(test_oauth_flow())
