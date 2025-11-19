"""Start all servers for the OAuth MCP demo."""
import os
import subprocess
import sys
import time
import signal

processes = []


def signal_handler(sig, frame):
    """Handle Ctrl+C to stop all servers."""
    print("\n\nStopping all servers...")
    for process in processes:
        process.terminate()
    sys.exit(0)


def main():
    """Start OAuth server and MCP server."""
    signal.signal(signal.SIGINT, signal_handler)
    
    # Set environment variable to allow HTTP (for development only!)
    os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'
    
    print("=" * 60)
    print("Starting OAuth MCP Demo Servers")
    print("=" * 60)
    print("\n⚠️  WARNING: Running in INSECURE mode (HTTP) for development")
    print("    DO NOT use in production! Use HTTPS in production.\n")
    
    # Start OAuth Server
    print("[1/2] Starting OAuth Authorization Server...")
    oauth_env = os.environ.copy()
    oauth_env['AUTHLIB_INSECURE_TRANSPORT'] = '1'
    # Create log directory if it doesn't exist
    os.makedirs('log', exist_ok=True)
    
    # Open log files (truncate mode to clear previous logs)
    oauth_log = open('log/oauth.log', 'w')
    mcp_log = open('log/mcp.log', 'w')
    
    oauth_process = subprocess.Popen(
        [sys.executable, "oauth_server.py"],
        stdout=oauth_log,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=oauth_env
    )
    processes.append(oauth_process)
    time.sleep(2)  # Wait for server to start
    
    # Start MCP Server (which also serves as Resource Server)
    print("\n[2/2] Starting MCP Server (with Resource API)...")
    mcp_process = subprocess.Popen(
        [sys.executable, "mcp_server.py"],
        stdout=mcp_log,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    processes.append(mcp_process)
    time.sleep(2)  # Wait for server to start
    
    print("\n" + "=" * 60)
    print("All servers started successfully!")
    print("=" * 60)
    print("\nServer URLs:")
    print(f"  - OAuth Server: http://127.0.0.1:5000")
    print(f"  - MCP Server:   http://127.0.0.1:5001")
    print(f"    • MCP Protocol: http://127.0.0.1:5001/mcp/v1/*")
    print(f"    • Resource API: http://127.0.0.1:5001/api/*")
    print(f"    • SSE Stream:   http://127.0.0.1:5001/mcp/v1/sse")
    print("\nIntegration:")
    print("  Configure in Cursor or Amazon Q CLI using Streamable HTTP")
    print("  Base URL: http://127.0.0.1:5001")
    print("\nPress Ctrl+C to stop all servers")
    print("=" * 60)
    
    # Keep the script running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
