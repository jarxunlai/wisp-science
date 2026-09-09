#!/usr/bin/env bash
# BaiduPCS-Go 安全登录与 Token 提取脚本
# 解决官方 -cookies 参数在 BDUSS 处于末尾或缺失分号时的 panic 缺陷

set -e

COOKIE_INPUT="${COOKIES:-$1}"
PCS_BIN="${PCS_BIN:-$HOME/bin/BaiduPCS-Go}"

if [ -z "$COOKIE_INPUT" ]; then
    echo "用法:"
    echo "  export COOKIES='你的完整Cookie字符串'"
    echo "  bash login.sh"
    echo "或者:"
    echo "  bash login.sh '你的完整Cookie字符串'"
    exit 1
fi

if [ ! -x "$PCS_BIN" ]; then
    if command -v BaiduPCS-Go >/dev/null 2>&1; then
        PCS_BIN="$(command -v BaiduPCS-Go)"
    else
        echo "错误: 未找到 BaiduPCS-Go 可执行程序，请检查路径。"
        exit 1
    fi
fi

# 确保 Cookie 字符串末尾有分号，避免正则匹配截断
FORMATTED_COOKIE="${COOKIE_INPUT%;};"

# 提取 BDUSS
BDUSS=$(echo "$FORMATTED_COOKIE" | grep -o 'BDUSS=[^;]*' | head -n 1 | cut -d'=' -f2-)

# 提取 STOKEN
STOKEN=$(echo "$FORMATTED_COOKIE" | grep -o 'STOKEN=[^;]*' | head -n 1 | cut -d'=' -f2-)

if [ -z "$BDUSS" ]; then
    echo "错误: 未在 Cookie 中检测到 BDUSS！"
    echo "请确认是否从 pan.baidu.com 的 Network -> Fetch/XHR (例如 tasklist 请求) 中复制了完整的 Cookie 请求头。"
    exit 1
fi

if [ -z "$STOKEN" ]; then
    echo "警告: 未检测到 STOKEN！"
    echo "注意: 仅有 BDUSS 时执行 who/quota 可能成功，但执行 ls/download 会返回 -6 报错。"
    echo "正在尝试仅用 BDUSS 登录..."
    "$PCS_BIN" login -bduss="$BDUSS"
else
    echo "成功检测到 BDUSS 与 STOKEN，正在安全登录..."
    "$PCS_BIN" login -bduss="$BDUSS" -stoken="$STOKEN"
fi

echo ""
echo "=== 登录状态检查 ==="
"$PCS_BIN" who
