"""MCP Server with OAuth 2.0 Authentication (Streamable HTTP).

This server combines both MCP functionality and protected resource endpoints.
It implements the MCP SSE (Server-Sent Events) transport for streaming HTTP.
"""
import asyncio
import json
import logging
import time
import uuid
from typing import Any, Optional, Dict
from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from authlib.jose import jwt, JsonWebKey, JoseError
import httpx
import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY

# Enable CORS for all routes
CORS(app, resources={
    r"/*": {
        "origins": "*",  # Allow all origins (for development)
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["WWW-Authenticate"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# OAuth client configuration (will be set after registration)
oauth_client = {
    'client_id': None,
    'client_secret': None,
    'access_token': None,
    'refresh_token': None,
    'initialized': False,
}

# Flag to track if auto-initialization is in progress
_auto_init_lock = False

# In-memory data storage (for demo)
data_store = [
    {'id': 1, 'name': 'Item 1', 'value': 100},
    {'id': 2, 'name': 'Item 2', 'value': 200},
    {'id': 3, 'name': 'Item 3', 'value': 300},
]
next_id = 4

# Cache for public key
_public_key_cache = None
_public_key_cache_time = 0
PUBLIC_KEY_CACHE_TTL = 3600  # 1 hour


def get_public_key():
    """Get public key from OAuth server's JWKS endpoint."""
    global _public_key_cache, _public_key_cache_time
    
    now = time.time()
    if _public_key_cache and (now - _public_key_cache_time) < PUBLIC_KEY_CACHE_TTL:
        return _public_key_cache
    
    try:
        response = httpx.get(config.JWKS_URI, timeout=5.0)
        response.raise_for_status()
        jwks = response.json()
        
        if 'keys' in jwks and len(jwks['keys']) > 0:
            key_data = jwks['keys'][0]
            _public_key_cache = JsonWebKey.import_key(key_data)
            _public_key_cache_time = now
            return _public_key_cache
    except Exception as e:
        logger.error(f"Error fetching public key: {e}")
    
    return None


def verify_token(token: str) -> dict:
    """Verify JWT access token."""
    # In demo mode, accept fixed demo token without verification
    if config.DEMO_MODE and token == config.DEMO_ACCESS_TOKEN:
        logger.info("🎯 Demo Mode: Accepting fixed demo token without verification")
        # Return mock claims for demo token
        return {
            'iss': config.OAUTH_ISSUER,
            'sub': 'demo_user',
            'aud': 'demo_client',
            'iat': int(time.time()),
            'exp': int(time.time()) + 315360000,  # 10 years
            'scope': 'read write',
            'client_id': 'demo_client',
        }
    
    # Normal mode: Full JWT verification
    try:
        public_key = get_public_key()
        if not public_key:
            raise ValueError("Unable to fetch public key")
        
        # Decode and verify JWT
        claims = jwt.decode(token, public_key)
        
        # Verify expiration
        now = int(time.time())
        if claims.get('exp', 0) < now:
            raise ValueError("Token expired")
        
        # Verify issuer
        if claims.get('iss') != config.OAUTH_ISSUER:
            raise ValueError("Invalid issuer")
        
        return claims
    except JoseError as e:
        raise ValueError(f"Invalid token: {e}")


def require_oauth(scopes=None):
    """Decorator to require OAuth authentication.
    
    Returns 401 with WWW-Authenticate header per RFC 6750 and RFC 9728.
    """
    def decorator(f):
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            # Build WWW-Authenticate header per RFC 9728
            www_authenticate = (
                f'Bearer resource_metadata="{config.MCP_SERVER_URL}/.well-known/oauth-protected-resource"'
            )
            if scopes:
                scope_str = ' '.join(scopes)
                www_authenticate += f', scope="{scope_str}"'
            
            if not auth_header:
                response = jsonify({
                    'error': 'missing_token',
                    'error_description': 'Authorization header is required'
                })
                response.status_code = 401
                response.headers['WWW-Authenticate'] = www_authenticate
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                response.headers['Access-Control-Expose-Headers'] = 'WWW-Authenticate'
                return response
            
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                response = jsonify({
                    'error': 'invalid_token',
                    'error_description': 'Invalid authorization header format'
                })
                response.status_code = 401
                response.headers['WWW-Authenticate'] = www_authenticate
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                response.headers['Access-Control-Expose-Headers'] = 'WWW-Authenticate'
                return response
            
            token = parts[1]
            
            try:
                claims = verify_token(token)
                
                # Check scopes if required
                if scopes:
                    token_scopes = claims.get('scope', '').split()
                    if not any(scope in token_scopes for scope in scopes):
                        response = jsonify({
                            'error': 'insufficient_scope',
                            'error_description': 'Token does not have required scope'
                        })
                        response.status_code = 403
                        response.headers['WWW-Authenticate'] = www_authenticate + ', error="insufficient_scope"'
                        response.headers['Access-Control-Allow-Origin'] = '*'
                        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                        response.headers['Access-Control-Expose-Headers'] = 'WWW-Authenticate'
                        return response
                
                # Add claims to request context
                request.oauth_claims = claims
                return f(*args, **kwargs)
            except ValueError as e:
                response = jsonify({
                    'error': 'invalid_token',
                    'error_description': str(e)
                })
                response.status_code = 401
                response.headers['WWW-Authenticate'] = www_authenticate + ', error="invalid_token"'
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
                response.headers['Access-Control-Expose-Headers'] = 'WWW-Authenticate'
                return response
        
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator


# ============================================================================
# Protected Resource API Endpoints
# ============================================================================

@app.route('/api/user/profile', methods=['GET'])
@require_oauth(scopes=['read'])
def get_user_profile():
    """Get user profile (requires 'read' scope)."""
    claims = request.oauth_claims
    return jsonify({
        'user_id': claims.get('sub'),
        'username': f"user_{claims.get('sub')}",
        'email': f"user_{claims.get('sub')}@example.com",
        'scope': claims.get('scope'),
    })


@app.route('/api/data', methods=['GET'])
@require_oauth(scopes=['read'])
def get_data():
    """Get data (requires 'read' scope)."""
    return jsonify({
        'data': data_store,
        'total': len(data_store),
    })


@app.route('/api/data', methods=['POST'])
@require_oauth(scopes=['write'])
def create_data():
    """Create data (requires 'write' scope)."""
    global next_id
    data = request.get_json()
    new_item = {
        'id': next_id,
        'name': data.get('name', 'New Item'),
        'value': data.get('value', 0),
    }
    data_store.append(new_item)
    next_id += 1
    return jsonify({**new_item, 'created': True}), 201


@app.route('/api/data/<int:item_id>', methods=['PUT'])
@require_oauth(scopes=['write'])
def update_data(item_id):
    """Update data (requires 'write' scope)."""
    data = request.get_json()
    for item in data_store:
        if item['id'] == item_id:
            item['name'] = data.get('name', item['name'])
            item['value'] = data.get('value', item['value'])
            return jsonify({**item, 'updated': True})
    return jsonify({'error': 'Item not found'}), 404


@app.route('/api/data/<int:item_id>', methods=['DELETE'])
@require_oauth(scopes=['write'])
def delete_data(item_id):
    """Delete data (requires 'write' scope)."""
    global data_store
    for i, item in enumerate(data_store):
        if item['id'] == item_id:
            data_store.pop(i)
            return jsonify({'id': item_id, 'deleted': True})
    return jsonify({'error': 'Item not found'}), 404


# ============================================================================
# MCP Protocol Implementation (SSE/Streamable HTTP)
# ============================================================================

async def register_oauth_client() -> dict:
    """Register OAuth client dynamically."""
    logger.info("Registering OAuth client...")
    
    registration_data = {
        'client_name': 'MCP Demo Client',
        'redirect_uris': ['http://localhost:8080/callback'],
        'grant_types': ['client_credentials', 'authorization_code', 'refresh_token'],
        'response_types': ['code'],
        'token_endpoint_auth_method': 'client_secret_post',
        'scope': 'read write',
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                config.REGISTRATION_ENDPOINT,
                json=registration_data,
                timeout=10.0
            )
            response.raise_for_status()
            client_info = response.json()
            logger.info(f"Client registered successfully: {client_info['client_id']}")
            return client_info
        except Exception as e:
            logger.error(f"Failed to register client: {e}")
            raise


async def get_access_token(client_id: str, client_secret: str) -> dict:
    """Get access token using client credentials grant."""
    logger.info("Requesting access token...")
    
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'read write',
    }
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                config.TOKEN_ENDPOINT,
                data=token_data,
                timeout=10.0
            )
            response.raise_for_status()
            token_response = response.json()
            logger.info("Access token obtained successfully")
            return token_response
        except Exception as e:
            logger.error(f"Failed to get access token: {e}")
            raise


async def auto_initialize_oauth():
    """Automatically initialize OAuth on server startup."""
    global _auto_init_lock
    
    if oauth_client['initialized'] or _auto_init_lock:
        return
    
    _auto_init_lock = True
    try:
        logger.info("🔐 Auto-initializing OAuth...")
        
        # Register client if not already registered
        if not oauth_client['client_id']:
            client_info = await register_oauth_client()
            oauth_client['client_id'] = client_info['client_id']
            oauth_client['client_secret'] = client_info['client_secret']
            logger.info(f"✓ Client registered: {client_info['client_id']}")
        
        # Get access token
        token_response = await get_access_token(
            oauth_client['client_id'],
            oauth_client['client_secret']
        )
        oauth_client['access_token'] = token_response['access_token']
        if 'refresh_token' in token_response:
            oauth_client['refresh_token'] = token_response['refresh_token']
        
        oauth_client['initialized'] = True
        logger.info("✓ OAuth auto-initialization completed")
        
    except Exception as e:
        logger.error(f"✗ OAuth auto-initialization failed: {e}")
    finally:
        _auto_init_lock = False


async def handle_mcp_tool_call(tool_name: str, arguments: dict) -> dict:
    """Handle MCP tool calls."""
    try:
        if tool_name == "oauth_authenticate":
            # Register client if not already registered
            if not oauth_client['client_id']:
                client_info = await register_oauth_client()
                oauth_client['client_id'] = client_info['client_id']
                oauth_client['client_secret'] = client_info['client_secret']
            
            # Get access token
            token_response = await get_access_token(
                oauth_client['client_id'],
                oauth_client['client_secret']
            )
            oauth_client['access_token'] = token_response['access_token']
            if 'refresh_token' in token_response:
                oauth_client['refresh_token'] = token_response['refresh_token']
            
            return {
                'content': [{
                    'type': 'text',
                    'text': json.dumps({
                        'status': 'authenticated',
                        'client_id': oauth_client['client_id'],
                        'token_type': token_response.get('token_type', 'Bearer'),
                        'expires_in': token_response.get('expires_in', 3600),
                        'scope': token_response.get('scope', ''),
                    }, indent=2)
                }]
            }
        
        elif tool_name == "get_user_profile":
            # Call local API
            headers = {'Authorization': f"Bearer {oauth_client['access_token']}"}
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://{config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}/api/user/profile",
                    headers=headers
                )
                response.raise_for_status()
                result = response.json()
            
            return {
                'content': [{
                    'type': 'text',
                    'text': json.dumps(result, indent=2)
                }]
            }
        
        elif tool_name == "get_data":
            headers = {'Authorization': f"Bearer {oauth_client['access_token']}"}
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"http://{config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}/api/data",
                    headers=headers
                )
                response.raise_for_status()
                result = response.json()
            
            return {
                'content': [{
                    'type': 'text',
                    'text': json.dumps(result, indent=2)
                }]
            }
        
        elif tool_name == "create_data":
            headers = {'Authorization': f"Bearer {oauth_client['access_token']}"}
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://{config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}/api/data",
                    headers=headers,
                    json=arguments
                )
                response.raise_for_status()
                result = response.json()
            
            return {
                'content': [{
                    'type': 'text',
                    'text': json.dumps(result, indent=2)
                }]
            }
        
        elif tool_name == "update_data":
            item_id = arguments.pop('item_id')
            headers = {'Authorization': f"Bearer {oauth_client['access_token']}"}
            async with httpx.AsyncClient() as client:
                response = await client.put(
                    f"http://{config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}/api/data/{item_id}",
                    headers=headers,
                    json=arguments
                )
                response.raise_for_status()
                result = response.json()
            
            return {
                'content': [{
                    'type': 'text',
                    'text': json.dumps(result, indent=2)
                }]
            }
        
        elif tool_name == "delete_data":
            item_id = arguments['item_id']
            headers = {'Authorization': f"Bearer {oauth_client['access_token']}"}
            async with httpx.AsyncClient() as client:
                response = await client.delete(
                    f"http://{config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}/api/data/{item_id}",
                    headers=headers
                )
                response.raise_for_status()
                result = response.json()
            
            return {
                'content': [{
                    'type': 'text',
                    'text': json.dumps(result, indent=2)
                }]
            }
        
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    except Exception as e:
        logger.error(f"Error calling tool {tool_name}: {e}")
        return {
            'content': [{
                'type': 'text',
                'text': json.dumps({
                    'error': str(e),
                    'tool': tool_name,
                }, indent=2)
            }],
            'isError': True
        }


@app.route('/mcp/v1', methods=['GET', 'POST'])
def mcp_base():
    """MCP base endpoint for handshake and discovery."""
    if request.method == 'GET':
        # Return basic MCP server info for discovery
        return jsonify({
            'protocol': 'mcp',
            'version': '2024-11-05',
            'server': {
                'name': 'oauth-mcp-demo',
                'version': '1.0.0'
            },
            'endpoints': {
                'initialize': '/mcp/v1/initialize',
                'tools_list': '/mcp/v1/tools/list', 
                'tools_call': '/mcp/v1/tools/call',
                'sse': '/mcp/v1/sse'
            }
        })
    elif request.method == 'POST':
        # Handle POST requests as JSON-RPC
        return handle_jsonrpc_request()


def handle_jsonrpc_request():
    """Handle JSON-RPC 2.0 requests."""
    data = request.get_json()
    logger.info(f"JSON-RPC request: {data}")
    
    # Extract JSON-RPC fields
    jsonrpc = data.get('jsonrpc', '2.0')
    request_id = data.get('id')
    method = data.get('method')
    params = data.get('params', {})
    
    try:
        # Handle notifications (no response needed)
        if method and method.startswith('notifications/'):
            logger.info(f"Received notification: {method}")
            # Notifications don't get a response in JSON-RPC 2.0
            return '', 204
        
        if method == 'initialize':
            # Check if Authorization header is present
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                # No token provided - return 401 with WWW-Authenticate header
                logger.info("No authorization token, returning 401")
                www_authenticate = (
                    f'Bearer resource_metadata="{config.MCP_SERVER_URL}/.well-known/oauth-protected-resource"'
                )
                response = jsonify({
                    'jsonrpc': jsonrpc,
                    'id': request_id,
                    'error': {
                        'code': 401,
                        'message': 'Unauthorized'
                    }
                })
                response.status_code = 401
                response.headers['WWW-Authenticate'] = www_authenticate
                return response
            
            # Verify token
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                logger.info("Invalid authorization header format")
                response = jsonify({
                    'jsonrpc': jsonrpc,
                    'id': request_id,
                    'error': {
                        'code': 401,
                        'message': 'Invalid authorization header'
                    }
                })
                response.status_code = 401
                return response
            
            token = parts[1]
            try:
                claims = verify_token(token)
                logger.info(f"Token verified for client: {claims.get('client_id')}")
                
                # Store token for this session (in real app, use session management)
                oauth_client['access_token'] = token
                oauth_client['initialized'] = True
                
            except ValueError as e:
                logger.error(f"Token verification failed: {e}")
                response = jsonify({
                    'jsonrpc': jsonrpc,
                    'id': request_id,
                    'error': {
                        'code': 401,
                        'message': 'Invalid or expired token'
                    }
                })
                response.status_code = 401
                return response
            
            result = {
                'protocolVersion': '2024-11-05',
                'capabilities': {
                    'tools': {
                        'listChanged': False
                    }
                },
                'serverInfo': {
                    'name': 'oauth-mcp-demo',
                    'version': '1.0.0'
                }
            }
        elif method == 'tools/list':
            # Require authentication for tools/list
            if not oauth_client.get('initialized'):
                logger.info("Tools list requested without authentication")
                www_authenticate = (
                    f'Bearer resource_metadata="{config.MCP_SERVER_URL}/.well-known/oauth-protected-resource"'
                )
                response = jsonify({
                    'jsonrpc': jsonrpc,
                    'id': request_id,
                    'error': {
                        'code': 401,
                        'message': 'Unauthorized'
                    }
                })
                response.status_code = 401
                response.headers['WWW-Authenticate'] = www_authenticate
                return response
            
            result = {
                'tools': [
                    {
                        'name': 'oauth_authenticate',
            'description': 'Authenticate with OAuth server and obtain access token',
            'inputSchema': {
                'type': 'object',
                'properties': {},
                'required': [],
            }
        },
        {
            'name': 'get_user_profile',
            'description': 'Get user profile from resource server (requires authentication)',
            'inputSchema': {
                'type': 'object',
                'properties': {},
                'required': [],
            }
        },
        {
            'name': 'get_data',
            'description': 'Get data from resource server (requires authentication and read scope)',
            'inputSchema': {
                'type': 'object',
                'properties': {},
                'required': [],
            }
        },
        {
            'name': 'create_data',
            'description': 'Create new data on resource server (requires authentication and write scope)',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Name of the item to create',
                    },
                    'value': {
                        'type': 'number',
                        'description': 'Value of the item',
                    },
                },
                'required': ['name', 'value'],
            }
        },
        {
            'name': 'update_data',
            'description': 'Update existing data on resource server (requires authentication and write scope)',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'item_id': {
                        'type': 'number',
                        'description': 'ID of the item to update',
                    },
                    'name': {
                        'type': 'string',
                        'description': 'New name of the item',
                    },
                    'value': {
                        'type': 'number',
                        'description': 'New value of the item',
                    },
                },
                'required': ['item_id', 'name', 'value'],
            }
        },
        {
            'name': 'delete_data',
            'description': 'Delete data from resource server (requires authentication and write scope)',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'item_id': {
                        'type': 'number',
                        'description': 'ID of the item to delete',
                    },
                },
                'required': ['item_id'],
            }
        },
    ]
            }
        elif method == 'tools/call':
            # Require authentication for tools/call
            if not oauth_client.get('initialized'):
                logger.info("Tool call requested without authentication")
                www_authenticate = (
                    f'Bearer resource_metadata="{config.MCP_SERVER_URL}/.well-known/oauth-protected-resource"'
                )
                response = jsonify({
                    'jsonrpc': jsonrpc,
                    'id': request_id,
                    'error': {
                        'code': 401,
                        'message': 'Unauthorized'
                    }
                })
                response.status_code = 401
                response.headers['WWW-Authenticate'] = www_authenticate
                return response
            
            tool_name = params.get('name')
            arguments = params.get('arguments', {})
            
            # Run async function in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(handle_mcp_tool_call(tool_name, arguments))
            finally:
                loop.close()
        else:
            return jsonify({
                'jsonrpc': jsonrpc,
                'id': request_id,
                'error': {
                    'code': -32601,
                    'message': f'Method not found: {method}'
                }
            }), 404
        
        return jsonify({
            'jsonrpc': jsonrpc,
            'id': request_id,
            'result': result
        })
    
    except Exception as e:
        logger.error(f"Error handling JSON-RPC request: {e}", exc_info=True)
        return jsonify({
            'jsonrpc': jsonrpc,
            'id': request_id,
            'error': {
                'code': -32603,
                'message': str(e)
            }
        }), 500


@app.route('/mcp/v1/initialize', methods=['POST'])
def mcp_initialize():
    """MCP initialization endpoint (legacy, redirects to JSON-RPC handler)."""
    return handle_jsonrpc_request()


@app.route('/mcp/v1/tools/list', methods=['POST'])
def mcp_list_tools():
    """List available MCP tools (legacy, redirects to JSON-RPC handler)."""
    return handle_jsonrpc_request()


@app.route('/mcp/v1/tools/call', methods=['POST'])
def mcp_call_tool():
    """Call an MCP tool (legacy, redirects to JSON-RPC handler)."""
    return handle_jsonrpc_request()


@app.route('/mcp/v1/sse', methods=['GET', 'POST'])
def mcp_sse():
    """MCP Server-Sent Events endpoint for streaming."""
    if request.method == 'GET':
        # SSE stream
        def generate():
            # Send initial connection message
            yield f"data: {json.dumps({'type': 'connected', 'timestamp': time.time()})}\n\n"
            
            # Keep connection alive
            while True:
                time.sleep(30)  # Send keepalive every 30 seconds
                yield f"data: {json.dumps({'type': 'keepalive', 'timestamp': time.time()})}\n\n"
        
        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            }
        )
    else:
        # POST request - handle as JSON-RPC message
        return handle_jsonrpc_request()


@app.route('/mcp/v1/message', methods=['POST'])
def mcp_message():
    """MCP message endpoint for SSE transport."""
    return handle_jsonrpc_request()


@app.route('/.well-known/oauth-protected-resource', methods=['GET'])
@app.route('/.well-known/oauth-protected-resource/mcp/v1', methods=['GET'])
@app.route('/.well-known/oauth-protected-resource/mcp', methods=['GET'])
def oauth_protected_resource_metadata():
    """OAuth 2.0 Protected Resource Metadata (RFC9728).
    
    This endpoint provides information about the authorization servers
    that protect this MCP server's resources.
    
    Supports both root and sub-path discovery as per MCP specification:
    - /.well-known/oauth-protected-resource (root)
    - /.well-known/oauth-protected-resource/mcp/v1 (sub-path for /mcp/v1/*)
    - /.well-known/oauth-protected-resource/mcp (sub-path for /mcp/*)
    """
    metadata = {
        'resource': config.MCP_SERVER_URL,
        'authorization_servers': [config.OAUTH_ISSUER],
        'bearer_methods_supported': ['header'],
        'resource_signing_alg_values_supported': ['RS256'],
        'resource_documentation': f'{config.MCP_SERVER_URL}/',
        'scopes_supported': ['read', 'write'],
    }
    return jsonify(metadata)


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'service': 'mcp_server',
        'oauth_configured': oauth_client['client_id'] is not None,
        'authenticated': oauth_client['access_token'] is not None,
    })


@app.route('/', methods=['GET'])
def index():
    """Root endpoint with service information."""
    return jsonify({
        'service': 'OAuth MCP Demo Server',
        'version': '1.0.0',
        'endpoints': {
            'mcp': {
                'initialize': '/mcp/v1/initialize',
                'tools_list': '/mcp/v1/tools/list',
                'tools_call': '/mcp/v1/tools/call',
                'sse': '/mcp/v1/sse',
            },
            'api': {
                'user_profile': '/api/user/profile',
                'data': '/api/data',
            },
            'health': '/health',
        }
    })


if __name__ == '__main__':
    logger.info(f"MCP Server (Streamable HTTP) starting on {config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}")
    logger.info(f"MCP endpoints: http://{config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}/mcp/v1/*")
    logger.info(f"API endpoints: http://{config.MCP_SERVER_HOST}:{config.MCP_SERVER_PORT}/api/*")
    app.run(host=config.MCP_SERVER_HOST, port=config.MCP_SERVER_PORT, debug=True, threaded=True)
