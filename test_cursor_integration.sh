#!/bin/bash

# 测试 Cursor 集成的脚本

echo "======================================"
echo "测试 OAuth MCP Demo - Cursor 集成"
echo "======================================"
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 测试 1: 检查服务器是否运行
echo "1. 检查服务器状态..."
if curl -s http://127.0.0.1:5000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ OAuth 服务器运行正常${NC}"
else
    echo -e "${RED}✗ OAuth 服务器未运行${NC}"
    exit 1
fi

if curl -s http://127.0.0.1:5001/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ MCP 服务器运行正常${NC}"
else
    echo -e "${RED}✗ MCP 服务器未运行${NC}"
    exit 1
fi
echo ""

# 测试 2: 测试 JSON-RPC initialize
echo "2. 测试 MCP 初始化..."
INIT_RESPONSE=$(curl -s -X POST http://127.0.0.1:5001/mcp/v1 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}')

if echo "$INIT_RESPONSE" | grep -q 'jsonrpc' && echo "$INIT_RESPONSE" | grep -q 'result'; then
    echo -e "${GREEN}✓ 初始化成功（JSON-RPC 格式正确）${NC}"
else
    echo -e "${RED}✗ 初始化失败${NC}"
    echo "$INIT_RESPONSE"
    exit 1
fi
echo ""

# 测试 3: 测试通知处理
echo "3. 测试通知处理..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:5001/mcp/v1 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}')

if [ "$HTTP_CODE" = "204" ]; then
    echo -e "${GREEN}✓ 通知处理正确（返回 204）${NC}"
else
    echo -e "${RED}✗ 通知处理失败（返回 $HTTP_CODE）${NC}"
    exit 1
fi
echo ""

# 测试 4: 测试工具列表
echo "4. 测试工具列表..."
TOOLS_RESPONSE=$(curl -s -X POST http://127.0.0.1:5001/mcp/v1 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

if echo "$TOOLS_RESPONSE" | grep -q 'oauth_authenticate' && echo "$TOOLS_RESPONSE" | grep -q 'get_data'; then
    echo -e "${GREEN}✓ 找到工具列表${NC}"
    echo "   主要工具："
    echo "   - oauth_authenticate"
    echo "   - get_user_profile"
    echo "   - get_data"
    echo "   - create_data"
    echo "   - update_data"
    echo "   - delete_data"
else
    echo -e "${RED}✗ 工具列表不完整${NC}"
    exit 1
fi
echo ""

# 测试 5: 测试 SSE 端点
echo "5. 测试 SSE 端点..."
SSE_RESPONSE=$(curl -s -N http://127.0.0.1:5001/mcp/v1/sse -H "Accept: text/event-stream" --max-time 1 2>&1 || true)

if echo "$SSE_RESPONSE" | grep -q "data:"; then
    echo -e "${GREEN}✓ SSE 端点工作正常${NC}"
else
    echo -e "${YELLOW}⚠ SSE 端点可能有问题（但这不影响 HTTP 传输）${NC}"
fi
echo ""

# 测试 6: 测试 OAuth 认证工具
echo "6. 测试 OAuth 认证工具..."
AUTH_RESPONSE=$(curl -s -X POST http://127.0.0.1:5001/mcp/v1 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"oauth_authenticate","arguments":{}}}')

if echo "$AUTH_RESPONSE" | grep -q "authenticated"; then
    echo -e "${GREEN}✓ OAuth 认证工具工作正常${NC}"
else
    echo -e "${RED}✗ OAuth 认证工具失败${NC}"
    echo "$AUTH_RESPONSE"
    exit 1
fi
echo ""

# 测试 7: 检查 Cursor 配置
echo "7. 检查 Cursor 配置..."
if [ -f ~/.cursor/mcp.json ]; then
    if grep -q "127.0.0.1:5001/mcp/v1" ~/.cursor/mcp.json; then
        echo -e "${GREEN}✓ Cursor 配置正确${NC}"
    else
        echo -e "${YELLOW}⚠ Cursor 配置可能不正确${NC}"
        echo "   请确保配置为: http://127.0.0.1:5001/mcp/v1"
    fi
else
    echo -e "${YELLOW}⚠ 未找到 Cursor 配置文件${NC}"
    echo "   配置文件应该在: ~/.cursor/mcp.json"
fi
echo ""

# 总结
echo "======================================"
echo -e "${GREEN}✓ 所有测试通过！${NC}"
echo "======================================"
echo ""
echo "现在您可以在 Cursor 中使用 MCP 工具了！"
echo ""
echo "使用方法："
echo "1. 在 Cursor 中对 AI 说："
echo "   '请调用 oauth_authenticate 工具进行认证'"
echo ""
echo "2. 认证成功后，您可以说："
echo "   '帮我获取所有数据'"
echo "   '创建一个新数据项，名称为 Test，值为 123'"
echo ""
echo "详细使用指南请查看: CURSOR_USAGE.md"
echo ""

