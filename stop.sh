#!/bin/bash

# OAuth MCP Demo - 停止脚本
# 停止所有运行中的服务器

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "============================================================"
echo -e "${BLUE}Stopping OAuth MCP Demo Servers${NC}"
echo "============================================================"
echo ""

# 从 PID 文件读取进程 ID
if [ -f log/oauth.pid ]; then
    OAUTH_PID=$(cat log/oauth.pid)
    if ps -p $OAUTH_PID > /dev/null 2>&1; then
        echo -e "${YELLOW}Stopping OAuth Server (PID: $OAUTH_PID)...${NC}"
        kill $OAUTH_PID
        sleep 1
        if ps -p $OAUTH_PID > /dev/null 2>&1; then
            echo -e "${RED}  → Force killing OAuth Server...${NC}"
            kill -9 $OAUTH_PID
        fi
        echo -e "${GREEN}  → ✓ OAuth Server stopped${NC}"
    else
        echo -e "${YELLOW}  → OAuth Server is not running${NC}"
    fi
    rm log/oauth.pid
else
    echo -e "${YELLOW}  → No OAuth Server PID file found${NC}"
fi

echo ""

if [ -f log/mcp.pid ]; then
    MCP_PID=$(cat log/mcp.pid)
    if ps -p $MCP_PID > /dev/null 2>&1; then
        echo -e "${YELLOW}Stopping MCP Server (PID: $MCP_PID)...${NC}"
        kill $MCP_PID
        sleep 1
        if ps -p $MCP_PID > /dev/null 2>&1; then
            echo -e "${RED}  → Force killing MCP Server...${NC}"
            kill -9 $MCP_PID
        fi
        echo -e "${GREEN}  → ✓ MCP Server stopped${NC}"
    else
        echo -e "${YELLOW}  → MCP Server is not running${NC}"
    fi
    rm log/mcp.pid
else
    echo -e "${YELLOW}  → No MCP Server PID file found${NC}"
fi

echo ""

# 额外检查：通过端口查找并停止进程
echo "Checking for any remaining processes on ports 5000 and 5001..."

# 查找并停止占用 5000 端口的进程
PORT_5000_PID=$(lsof -ti:5000)
if [ ! -z "$PORT_5000_PID" ]; then
    echo -e "${YELLOW}  → Found process on port 5000 (PID: $PORT_5000_PID), stopping...${NC}"
    kill $PORT_5000_PID 2>/dev/null
    sleep 1
    if lsof -ti:5000 > /dev/null 2>&1; then
        kill -9 $PORT_5000_PID 2>/dev/null
    fi
fi

# 查找并停止占用 5001 端口的进程
PORT_5001_PID=$(lsof -ti:5001)
if [ ! -z "$PORT_5001_PID" ]; then
    echo -e "${YELLOW}  → Found process on port 5001 (PID: $PORT_5001_PID), stopping...${NC}"
    kill $PORT_5001_PID 2>/dev/null
    sleep 1
    if lsof -ti:5001 > /dev/null 2>&1; then
        kill -9 $PORT_5001_PID 2>/dev/null
    fi
fi

echo ""
echo "============================================================"
echo -e "${GREEN}All servers stopped${NC}"
echo "============================================================"

