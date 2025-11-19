"""Configuration for OAuth MCP Demo."""
import os
from dotenv import load_dotenv

load_dotenv()

# OAuth Server Configuration
OAUTH_SERVER_HOST = os.getenv("OAUTH_SERVER_HOST", "127.0.0.1")
OAUTH_SERVER_PORT = int(os.getenv("OAUTH_SERVER_PORT", "5000"))
OAUTH_ISSUER = os.getenv("OAUTH_ISSUER", f"http://{OAUTH_SERVER_HOST}:{OAUTH_SERVER_PORT}")

# MCP Server Configuration (also serves as Resource Server)
MCP_SERVER_HOST = os.getenv("MCP_SERVER_HOST", "127.0.0.1")
MCP_SERVER_PORT = int(os.getenv("MCP_SERVER_PORT", "5001"))
MCP_SERVER_URL = f"http://{MCP_SERVER_HOST}:{MCP_SERVER_PORT}"

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")

# Demo Mode Configuration
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
DEMO_AUTHORIZATION_CODE = "DEMO_AUTH_CODE_12345"  # Fixed authorization code for demo
DEMO_CLIENT_ID = "demo_client"  # Fixed client ID for demo
DEMO_CLIENT_SECRET = "demo_secret"  # Fixed client secret for demo

# Fixed demo tokens (for testing purposes only - never use in production!)
DEMO_ACCESS_TOKEN = "demo_access_token_fixed_for_testing_purposes_12345"
DEMO_REFRESH_TOKEN = "demo_refresh_token_fixed_for_testing_purposes_67890"

# OAuth Endpoints
AUTHORIZATION_ENDPOINT = f"{OAUTH_ISSUER}/oauth/authorize"
TOKEN_ENDPOINT = f"{OAUTH_ISSUER}/oauth/token"
REGISTRATION_ENDPOINT = f"{OAUTH_ISSUER}/oauth/register"
JWKS_URI = f"{OAUTH_ISSUER}/.well-known/jwks.json"

