#!/bin/bash

# Test script to verify MCP remote connection works

echo "Testing MCP server with mcp-remote client..."
echo ""

# Test 1: Initialize
echo "1. Testing initialize..."
npx --yes mcp-remote http://127.0.0.1:5001/mcp/v1 << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}
EOF

echo ""
echo "2. Testing tools/list..."
npx --yes mcp-remote http://127.0.0.1:5001/mcp/v1 << 'EOF'
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
EOF

echo ""
echo "Done!"

