"""OAuth 2.0 Authorization Server with Dynamic Client Registration and PKCE."""
import os
import secrets
import time
import uuid
import hashlib
import base64
from typing import Dict, Optional
from flask import Flask, request, jsonify, redirect, render_template_string
from flask_cors import CORS
from authlib.oauth2 import OAuth2Request
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7009 import RevocationEndpoint
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.jose import jwt, JsonWebKey
from werkzeug.security import gen_salt
import config

# Disable HTTPS requirement for development (INSECURE - for demo only!)
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY

# Enable CORS for all routes
CORS(app, resources={
    r"/*": {
        "origins": "*",  # Allow all origins (for development)
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Location"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

# In-memory storage (for demo purposes)
clients_db: Dict[str, dict] = {}
tokens_db: Dict[str, dict] = {}
authorization_codes_db: Dict[str, dict] = {}
users_db = {
    "demo_user": {
        "id": "1",
        "username": "demo_user",
        "password": "demo_password"
    }
}

# Generate RSA key for JWT signing
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


def query_client(client_id: str) -> Optional[dict]:
    """Query client by client_id."""
    return clients_db.get(client_id)


def save_token(token_data: dict, request):
    """Save access token."""
    token_id = str(uuid.uuid4())
    tokens_db[token_id] = {
        'access_token': token_data['access_token'],
        'token_type': token_data.get('token_type', 'Bearer'),
        'expires_in': token_data.get('expires_in', 3600),
        'scope': token_data.get('scope', ''),
        'client_id': request.client.client_id,
        'user_id': request.user.get('id') if hasattr(request, 'user') and request.user else None,
        'created_at': int(time.time())
    }
    return token_data


class AuthorizationCodeMixin:
    """Authorization Code mixin."""
    
    def __init__(self, data):
        self.data = data
    
    def get_redirect_uri(self):
        return self.data.get('redirect_uri')
    
    def get_scope(self):
        return self.data.get('scope')
    
    def get_auth_time(self):
        return self.data.get('auth_time')
    
    def __getitem__(self, key):
        return self.data[key]
    
    def get(self, key, default=None):
        return self.data.get(key, default)


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    """Authorization Code Grant implementation with PKCE support."""
    
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none']
    
    def save_authorization_code(self, code, request):
        """Save authorization code with PKCE parameters."""
        client = request.client
        auth_code = {
            'code': code,
            'client_id': client.client_id,
            'redirect_uri': request.redirect_uri,
            'scope': request.scope,
            'user_id': request.user.get('id'),
            'expires_at': int(time.time()) + 300,  # 5 minutes
            # Save PKCE parameters
            'code_challenge': request.data.get('code_challenge'),
            'code_challenge_method': request.data.get('code_challenge_method'),
        }
        authorization_codes_db[code] = auth_code
        return auth_code
    
    def query_authorization_code(self, code, client):
        """Query authorization code."""
        auth_code = authorization_codes_db.get(code)
        if auth_code and auth_code['client_id'] == client.client_id:
            return AuthorizationCodeMixin(auth_code)
        return None
    
    def delete_authorization_code(self, authorization_code):
        """Delete authorization code."""
        code = authorization_code.get('code') if hasattr(authorization_code, 'get') else authorization_code['code']
        if code in authorization_codes_db:
            del authorization_codes_db[code]
    
    def authenticate_user(self, authorization_code):
        """Authenticate user from authorization code."""
        user_id = authorization_code.get('user_id')
        if user_id:
            return {'id': user_id, 'username': f'user_{user_id}'}
        return None
    
    def validate_code_challenge(self, code_verifier, code_challenge, code_challenge_method):
        """Validate PKCE code challenge.
        
        Args:
            code_verifier: The code verifier from token request
            code_challenge: The code challenge from authorization request
            code_challenge_method: The challenge method (plain or S256)
        
        Returns:
            bool: True if valid, False otherwise
        """
        if not code_challenge or not code_challenge_method:
            # No PKCE parameters
            return True
        
        if not code_verifier:
            # PKCE was used in authorization but no verifier provided
            return False
        
        if code_challenge_method == 'S256':
            # SHA256 hash of code_verifier
            h = hashlib.sha256(code_verifier.encode('ascii')).digest()
            computed_challenge = base64.urlsafe_b64encode(h).decode('ascii').rstrip('=')
            return computed_challenge == code_challenge
        elif code_challenge_method == 'plain':
            return code_verifier == code_challenge
        return False
    
    def create_token_response(self):
        """Create token response with PKCE validation."""
        # Get code_verifier from request
        code_verifier = request.form.get('code_verifier')
        
        # Get authorization code
        code = request.form.get('code')
        if code:
            auth_code_data = authorization_codes_db.get(code)
            if auth_code_data:
                # Validate PKCE if present
                code_challenge = auth_code_data.get('code_challenge')
                code_challenge_method = auth_code_data.get('code_challenge_method')
                
                if not self.validate_code_challenge(code_verifier, code_challenge, code_challenge_method):
                    from authlib.oauth2.rfc6749 import InvalidGrantError
                    raise InvalidGrantError('PKCE validation failed')
        
        # Call parent implementation
        return super().create_token_response()


class ClientCredentialsGrant(grants.ClientCredentialsGrant):
    """Client Credentials Grant implementation."""
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']


class RefreshTokenGrant(grants.RefreshTokenGrant):
    """Refresh Token Grant implementation."""
    
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']
    
    def authenticate_refresh_token(self, refresh_token):
        """Authenticate refresh token."""
        for token_id, token in tokens_db.items():
            if token.get('refresh_token') == refresh_token:
                return token
        return None
    
    def authenticate_user(self, credential):
        """Authenticate user from refresh token."""
        user_id = credential.get('user_id')
        if user_id:
            return {'id': user_id, 'username': f'user_{user_id}'}
        return None
    
    def revoke_old_credential(self, credential):
        """Revoke old refresh token."""
        for token_id, token in list(tokens_db.items()):
            if token.get('refresh_token') == credential.get('refresh_token'):
                del tokens_db[token_id]
                break


# Initialize Authorization Server
authorization = AuthorizationServer()


def create_bearer_token_generator(issuer):
    """Create a bearer token generator that creates JWT tokens."""
    def generate_token(client, grant_type, user=None, scope=None, expires_in=None, include_refresh_token=True):
        """Generate JWT access token."""
        if expires_in is None:
            expires_in = 3600
        
        now = int(time.time())
        payload = {
            'iss': issuer,
            'sub': user.get('id') if user else client.client_id,
            'aud': client.client_id,
            'iat': now,
            'exp': now + expires_in,
            'scope': scope or '',
            'client_id': client.client_id,
        }
        
        header = {'alg': 'RS256'}
        access_token = jwt.encode(header, payload, private_pem)
        # Handle both bytes and str return types
        if isinstance(access_token, bytes):
            access_token = access_token.decode('utf-8')
        
        token_data = {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': expires_in,
            'scope': scope or '',
        }
        
        if include_refresh_token:
            refresh_token = secrets.token_urlsafe(48)
            token_data['refresh_token'] = refresh_token
            # Store refresh token
            token_id = str(uuid.uuid4())
            tokens_db[token_id] = {
                'refresh_token': refresh_token,
                'client_id': client.client_id,
                'user_id': user.get('id') if user else None,
                'scope': scope or '',
                'created_at': now,
            }
        
        return token_data
    
    return generate_token


class ClientMixin:
    """Client mixin for OAuth2."""
    
    def __init__(self, client_data):
        self.data = client_data
    
    @property
    def client_id(self):
        return self.data['client_id']
    
    @property
    def client_secret(self):
        return self.data.get('client_secret')
    
    @property
    def client_name(self):
        return self.data.get('client_name', '')
    
    @property
    def redirect_uris(self):
        return self.data.get('redirect_uris', [])
    
    @property
    def default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]
        return None
    
    @property
    def allowed_scope(self):
        return self.data.get('scope', '')
    
    def get_allowed_scope(self, scope):
        """Get allowed scope for the client."""
        if not scope:
            return self.allowed_scope
        allowed = set(self.allowed_scope.split())
        requested = set(scope.split())
        return ' '.join(requested & allowed)
    
    @property
    def grant_types(self):
        return self.data.get('grant_types', [])
    
    @property
    def response_types(self):
        return self.data.get('response_types', [])
    
    @property
    def token_endpoint_auth_method(self):
        return self.data.get('token_endpoint_auth_method', 'client_secret_basic')
    
    def check_redirect_uri(self, redirect_uri):
        """Check if redirect_uri is allowed."""
        return redirect_uri in self.redirect_uris
    
    def check_client_secret(self, client_secret):
        """Check if client_secret is valid."""
        # In demo mode, accept demo_secret for any client
        if config.DEMO_MODE and client_secret == config.DEMO_CLIENT_SECRET:
            return True
        return self.client_secret == client_secret
    
    def check_token_endpoint_auth_method(self, method):
        """Check if token endpoint auth method is allowed."""
        return method == self.token_endpoint_auth_method
    
    def check_endpoint_auth_method(self, method, endpoint):
        """Check if endpoint auth method is allowed."""
        if endpoint == 'token':
            return self.check_token_endpoint_auth_method(method)
        return True
    
    def check_response_type(self, response_type):
        """Check if response_type is allowed."""
        return response_type in self.response_types
    
    def check_grant_type(self, grant_type):
        """Check if grant_type is allowed."""
        return grant_type in self.grant_types


def query_client_func(client_id):
    """Query client function for authorization server."""
    client_data = query_client(client_id)
    if client_data:
        return ClientMixin(client_data)
    return None


authorization.init_app(app, query_client=query_client_func, save_token=save_token)

# Register grants
authorization.register_grant(AuthorizationCodeGrant)
authorization.register_grant(ClientCredentialsGrant)
authorization.register_grant(RefreshTokenGrant)

# Create and register token generator
token_generator = create_bearer_token_generator(config.OAUTH_ISSUER)
authorization.register_token_generator('default', token_generator)


# OAuth 2.0 Dynamic Client Registration (RFC 7591)
@app.route('/oauth/register', methods=['POST'])
def register_client():
    """Dynamic Client Registration endpoint."""
    data = request.get_json()
    
    # Validate required fields
    redirect_uris = data.get('redirect_uris')
    if not redirect_uris or not isinstance(redirect_uris, list):
        return jsonify({'error': 'invalid_redirect_uri', 'error_description': 'redirect_uris is required'}), 400
    
    # Generate client credentials
    client_id = f"client_{gen_salt(24)}"
    client_secret = gen_salt(48)
    
    # Default values
    grant_types = data.get('grant_types', ['authorization_code', 'refresh_token'])
    response_types = data.get('response_types', ['code'])
    token_endpoint_auth_method = data.get('token_endpoint_auth_method', 'client_secret_basic')
    
    # Create client
    client_data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'client_name': data.get('client_name', 'MCP Client'),
        'redirect_uris': redirect_uris,
        'grant_types': grant_types,
        'response_types': response_types,
        'token_endpoint_auth_method': token_endpoint_auth_method,
        'scope': data.get('scope', 'read write'),
        'created_at': int(time.time()),
    }
    
    clients_db[client_id] = client_data
    
    # Return client information
    response = {
        'client_id': client_id,
        'client_secret': client_secret,
        'client_name': client_data['client_name'],
        'redirect_uris': redirect_uris,
        'grant_types': grant_types,
        'response_types': response_types,
        'token_endpoint_auth_method': token_endpoint_auth_method,
        'client_id_issued_at': client_data['created_at'],
    }
    
    return jsonify(response), 201


@app.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    """Authorization endpoint with demo mode support."""
    if request.method == 'GET':
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        state = request.args.get('state', '')
        code_challenge = request.args.get('code_challenge')
        code_challenge_method = request.args.get('code_challenge_method')
        
        if not client_id:
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'client_id is required'
            }), 400
        
        # Demo mode: Accept any client_id and return fixed authorization code
        if config.DEMO_MODE:
            # Auto-register client if not exists (for demo convenience)
            if client_id not in clients_db:
                print(f"🎯 Demo Mode: Auto-registering client {client_id}")
                clients_db[client_id] = {
                    'client_id': client_id,
                    'client_secret': config.DEMO_CLIENT_SECRET,
                    'client_name': f'Auto-registered Demo Client',
                    'redirect_uris': [redirect_uri] if redirect_uri else ['http://localhost:8080/callback'],
                    'grant_types': ['authorization_code', 'refresh_token', 'client_credentials'],
                    'response_types': ['code'],
                    'token_endpoint_auth_method': 'client_secret_post',
                    'scope': 'read write',
                    'allowed_scope': 'read write',
                }
            
            # Update demo authorization code with current request parameters
            authorization_codes_db[config.DEMO_AUTHORIZATION_CODE] = {
                'code': config.DEMO_AUTHORIZATION_CODE,
                'client_id': client_id,
                'redirect_uri': redirect_uri or 'http://localhost:8080/callback',
                'scope': 'read write',
                'user_id': '1',
                'expires_at': int(time.time()) + 86400,  # 24 hours for demo
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
            }
            
            # Build redirect URL with fixed code
            redirect_url = redirect_uri or 'http://localhost:8080/callback'
            separator = '&' if '?' in redirect_url else '?'
            redirect_url += f'{separator}code={config.DEMO_AUTHORIZATION_CODE}'
            if state:
                redirect_url += f'&state={state}'
            
            print(f"🎯 Demo Mode: Returning fixed authorization code")
            print(f"   Client ID: {client_id}")
            print(f"   Redirect to: {redirect_url}")
            
            return redirect(redirect_url)
        
        # Normal mode: Check if client exists
        client = query_client(client_id)
        if not client:
            return jsonify({
                'error': 'invalid_client',
                'error_description': f'Client {client_id} not found. Please register the client first at {config.REGISTRATION_ENDPOINT}'
            }), 401
        
        # Normal mode: Show authorization page and auto-approve
        try:
            return authorization.create_authorization_response(grant_user=users_db['demo_user'])
        except Exception as e:
            error_msg = str(e)
            print(f"❌ Authorization error: {error_msg}")
            return jsonify({
                'error': 'server_error',
                'error_description': error_msg
            }), 400
    
    # POST - user approved
    try:
        return authorization.create_authorization_response(grant_user=users_db['demo_user'])
    except Exception as e:
        error_msg = str(e)
        print(f"❌ Authorization error: {error_msg}")
        return jsonify({
            'error': 'server_error',
            'error_description': error_msg
        }), 400


@app.route('/oauth/token', methods=['POST'])
def issue_token():
    """Token endpoint with demo mode support."""
    # Debug: print request data
    print(f"🔍 Token request received:")
    print(f"   Form data: {dict(request.form)}")
    print(f"   Headers: {dict(request.headers)}")
    
    # In demo mode, return fixed token immediately (skip all validation)
    if config.DEMO_MODE:
        print(f"🎯 Demo Mode: Returning fixed static token")
        print(f"   ⚠️  Skipping all validation - accepting any request")
        
        fixed_token_response = {
            'access_token': config.DEMO_ACCESS_TOKEN,
            'token_type': 'Bearer',
            'expires_in': 315360000,  # 10 years (for demo purposes)
            'scope': 'read write',
            'refresh_token': config.DEMO_REFRESH_TOKEN
        }
        
        print(f"✅ Fixed demo token returned successfully")
        print(f"   Access Token: {config.DEMO_ACCESS_TOKEN}")
        
        return jsonify(fixed_token_response), 200
    
    # Normal mode: Original validation logic
    try:
        response = authorization.create_token_response()
        print(f"✅ Token response created successfully")
        return response
    except Exception as e:
        print(f"❌ Token error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': 'server_error',
            'error_description': str(e)
        }), 500


@app.route('/.well-known/oauth-authorization-server', methods=['GET'])
def oauth_metadata():
    """OAuth 2.0 Authorization Server Metadata with PKCE support."""
    metadata = {
        'issuer': config.OAUTH_ISSUER,
        'authorization_endpoint': config.AUTHORIZATION_ENDPOINT,
        'token_endpoint': config.TOKEN_ENDPOINT,
        'registration_endpoint': config.REGISTRATION_ENDPOINT,
        'jwks_uri': config.JWKS_URI,
        'response_types_supported': ['code', 'token'],
        'grant_types_supported': ['authorization_code', 'client_credentials', 'refresh_token'],
        'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post', 'none'],
        'code_challenge_methods_supported': ['S256', 'plain'],  # PKCE support
        'scopes_supported': ['read', 'write'],
    }
    return jsonify(metadata)


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """JSON Web Key Set endpoint."""
    key = JsonWebKey.import_key(public_pem, {'kty': 'RSA', 'use': 'sig', 'kid': 'default'})
    return jsonify({'keys': [key.as_dict()]})


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok', 'service': 'oauth_server'})


if __name__ == '__main__':
    print(f"OAuth Server starting on {config.OAUTH_SERVER_HOST}:{config.OAUTH_SERVER_PORT}")
    print(f"Issuer: {config.OAUTH_ISSUER}")
    print(f"Registration endpoint: {config.REGISTRATION_ENDPOINT}")
    app.run(host=config.OAUTH_SERVER_HOST, port=config.OAUTH_SERVER_PORT, debug=True)

