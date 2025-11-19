#!/bin/bash

# OAuth MCP Demo - 启动脚本
# 启动 OAuth 服务器和 MCP 服务器，并将日志输出到文件

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

pkill -9 -f mcp
pkill -9 -f oauth

# 创建日志目录
mkdir -p log

# 清空旧日志
> log/oauth.log
> log/mcp.log

echo "============================================================"
echo -e "${BLUE}Starting OAuth MCP Demo Servers${NC}"
echo "============================================================"
echo ""
echo -e "${YELLOW}⚠️  WARNING: Running in INSECURE mode (HTTP) for development${NC}"
echo -e "${YELLOW}    DO NOT use in production! Use HTTPS in production.${NC}"
echo ""

# 设置环境变量（允许 HTTP，仅用于开发）
export AUTHLIB_INSECURE_TRANSPORT=1

# 启动 OAuth 服务器
echo -e "${GREEN}[1/2] Starting OAuth Authorization Server...${NC}"
python oauth_server.py > log/oauth.log 2>&1 &
OAUTH_PID=$!
echo "  → PID: $OAUTH_PID"
echo "  → Log: log/oauth.log"

# 等待 OAuth 服务器启动
sleep 2

# 检查 OAuth 服务器是否启动成功
if ps -p $OAUTH_PID > /dev/null; then
    echo -e "  → ${GREEN}✓ OAuth Server started successfully${NC}"
else
    echo -e "  → ${RED}✗ OAuth Server failed to start${NC}"
    echo "  → Check log/oauth.log for details"
    exit 1
fi

echo ""

# 启动 MCP 服务器
echo -e "${GREEN}[2/2] Starting MCP Server (with Resource API)...${NC}"
python mcp_server.py > log/mcp.log 2>&1 &
MCP_PID=$!
echo "  → PID: $MCP_PID"
echo "  → Log: log/mcp.log"

# 等待 MCP 服务器启动
sleep 2

# 检查 MCP 服务器是否启动成功
if ps -p $MCP_PID > /dev/null; then
    echo -e "  → ${GREEN}✓ MCP Server started successfully${NC}"
else
    echo -e "  → ${RED}✗ MCP Server failed to start${NC}"
    echo "  → Check log/mcp.log for details"
    kill $OAUTH_PID 2>/dev/null
    exit 1
fi

echo ""
echo "============================================================"
echo -e "${GREEN}All servers started successfully!${NC}"
echo "============================================================"
echo ""
echo "Server URLs:"
echo "  - OAuth Server: http://127.0.0.1:5000"
echo "  - MCP Server:   http://127.0.0.1:5001"
echo "    • MCP Protocol: http://127.0.0.1:5001/mcp/v1/*"
echo "    • Resource API: http://127.0.0.1:5001/api/*"
echo "    • SSE Stream:   http://127.0.0.1:5001/mcp/v1/sse"
echo ""
echo "Process IDs:"
echo "  - OAuth Server PID: $OAUTH_PID"
echo "  - MCP Server PID:   $MCP_PID"
echo ""
echo "Logs:"
echo "  - OAuth Server: log/oauth.log"
echo "  - MCP Server:   log/mcp.log"
echo ""
echo "View logs in real-time:"
echo "  tail -f log/oauth.log"
echo "  tail -f log/mcp.log"
echo "  tail -f log/*.log    # 查看所有日志"
echo ""
echo "Stop servers:"
echo "  ./stop.sh"
echo "  或手动: kill $OAUTH_PID $MCP_PID"
echo ""
echo "============================================================"

# 保存 PID 到文件，方便停止
echo $OAUTH_PID > log/oauth.pid
echo $MCP_PID > log/mcp.pid

echo ""
echo -e "${BLUE}Servers are running in background.${NC}"
echo "Press Ctrl+C to exit this script (servers will continue running)"
echo ""

# 可选：保持脚本运行并显示日志
# 如果不需要，可以注释掉下面的部分
read -p "Do you want to watch logs? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Watching logs... Press Ctrl+C to stop watching (servers will continue running)"
    echo ""
    tail -f log/*.log
fi

