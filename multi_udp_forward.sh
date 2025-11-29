#!/usr/bin/env bash
set -euo pipefail
# ================================================================
# Multi-mode IPv6->IPv4 UDP forwarder
# Modes: socat / gost / realm / hysteria2 relay
# Script: fixed version (auto-install "file" removed, no file detection)
# ================================================================

RULE_DIR="/etc/udp-forward-multi"
SERVICE_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"
NFT_RULESET="/etc/nftables.conf"

mkdir -p "$RULE_DIR" "$SERVICE_DIR" "$BIN_DIR"

ech(){ printf '%s\n' "$*"; }

# ================================================================
# Install basic dependencies
# ================================================================
install_common() {
    ech ">>> 安装基础依赖: curl jq nftables iproute2 socat"
    apt update
    apt install -y --no-install-recommends \
        curl jq ca-certificates nftables iproute2 socat

    # enable forwarding
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1

    grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf \
        || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    grep -q '^net.ipv6.conf.all.forwarding' /etc/sysctl.conf \
        || echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf

    systemctl enable --now nftables.service || true
    ech ">>> 基础依赖安装完成。"
}

# ================================================================
# GitHub download helper (no file command needed)
# ================================================================
# $1 = repo "owner/repo"
# $2 = regex pattern for asset name
# $3 = dest binary path
gh_download_latest_asset() {
    local repo="$1" pat="$2" dest="$3"

    ech "获取 $repo 最新 release..."

    local api="https://api.github.com/repos/${repo}/releases/latest"
    local url
    url=$(curl -s "$api" \
        | jq -r --arg PAT "$pat" '.assets[] | select(.name | test($PAT)) | .browser_download_url' \
        | head -n1)

    if [[ -z "$url" || "$url" == "null" ]]; then
        ech "❌ 未找到合适的 release asset: $pat"
        return 1
    fi

    ech "下载 $url ..."
    curl -L --fail -o /tmp/tmp_asset "$url"

    chmod +x /tmp/tmp_asset
    mv /tmp/tmp_asset "$dest"

    ech "已安装: $dest"
}

# ================================================================
# Install individual tools
# ================================================================
install_socat() {
    ech ">>> socat 已包含在基础依赖，将自动安装（如果未安装）。"
    apt install -y socat
}

install_gost() {
    if command -v gost >/dev/null 2>&1; then ech "gost already installed"; return; fi
    gh_download_latest_asset "go-gost/gost" "linux.*amd64" "$BIN_DIR/gost" \
        || gh_download_latest_asset "ginuerzh/gost" "linux.*amd64" "$BIN_DIR/gost" \
        || ech "⚠ gost 自动安装失败，请手动安装。"
}

install_realm() {
    if command -v realm >/dev/null 2>&1; then ech "realm already installed"; return; fi
    gh_download_latest_asset "zhboner/realm" "linux.*(amd64|x86_64)" "$BIN_DIR/realm" \
        || ech "⚠ realm 自动安装失败，请手动安装。"
}

install_hysteria() {
    if command -v hysteria >/dev/null 2>&1; then ech "hysteria already installed"; return; fi
    gh_download_latest_asset "apernet/hysteria" "linux.*amd64" "$BIN_DIR/hysteria" \
        || ech "⚠ Hysteria 自动安装失败，请手动安装。"
}

# ================================================================
# nftables helper
# ================================================================
ensure_nft_base() {
    if [[ ! -f "$NFT_RULESET" ]]; then
        cat > "$NFT_RULESET" <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy accept;
        ct state established,related accept
        iif "lo" accept
        accept
    }
}
EOF
        nft -f "$NFT_RULESET" || true
    fi
}

nft_allow_udp6_port() {
    ensure_nft_base
    nft add rule inet filter input ip6 nexthdr udp udp dport "$1" accept 2>/dev/null || true
}

nft_clear() {
    nft flush ruleset || true
    nft -f "$NFT_RULESET" || true
}

# ================================================================
# Rule management
# ================================================================
add_rule_interactive() {
    ech "选择转发模式:"
    ech "1) socat  (低性能)"
    ech "2) gost   (中等)"
    ech "3) realm  (高性能)"
    ech "4) hysteria (relay 最强)"
    read -rp "模式: " M

    case "$M" in
        1) MODE="socat" ;;
        2) MODE="gost" ;;
        3) MODE="realm" ;;
        4) MODE="hysteria" ;;
        *) ech "无效模式"; return ;;
    esac

    read -rp "监听 IPv6 端口: " IN_PORT
    read -rp "目标 IPv4 地址: " OUT_IP
    read -rp "目标 IPv4 端口: " OUT_PORT

    NAME="${MODE}-${IN_PORT}-${OUT_IP//./-}-${OUT_PORT}"
    CONF="$RULE_DIR/$NAME.conf"

    cat > "$CONF" <<EOF
NAME=$NAME
MODE=$MODE
IN_PORT=$IN_PORT
OUT_IP=$OUT_IP
OUT_PORT=$OUT_PORT
EOF

    nft_allow_udp6_port "$IN_PORT"

    SERVICE_FILE="$SERVICE_DIR/$NAME.service"

    case "$MODE" in
        socat)
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=UDP forward (socat) $NAME
After=network-online.target

[Service]
ExecStart=/usr/bin/socat -T 1 UDP6-LISTEN:${IN_PORT},fork,reuseaddr UDP4:${OUT_IP}:${OUT_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        ;;
        gost)
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=UDP forward (gost) $NAME
After=network-online.target

[Service]
ExecStart=$BIN_DIR/gost -L udp://[::]:${IN_PORT}/${OUT_IP}:${OUT_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        ;;
        realm)
            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=UDP forward (realm) $NAME
After=network-online.target

[Service]
ExecStart=$BIN_DIR/realm -u -l [::]:${IN_PORT} -r ${OUT_IP}:${OUT_PORT}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        ;;
        hysteria)
            mkdir -p /etc/hysteria
            cat > "/etc/hysteria/$NAME.json" <<EOF
{
  "log_level": "info",
  "relay_udps": [
    {
      "listen": "[::]:${IN_PORT}",
      "remote": "${OUT_IP}:${OUT_PORT}"
    }
  ]
}
EOF

            cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Hysteria UDP Relay $NAME
After=network-online.target

[Service]
ExecStart=$BIN_DIR/hysteria server -c /etc/hysteria/$NAME.json
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        ;;
    esac

    systemctl daemon-reload
    systemctl enable --now "$NAME.service"
    ech "规则添加完成：$NAME"
}

list_rules() {
    ech "=== 规则列表 ==="
    ls -1 "$RULE_DIR" || ech "无规则"
}

delete_rule_interactive() {
    list_rules
    read -rp "输入要删除的规则名（不带 .conf）: " NAME

    rm -f "$RULE_DIR/$NAME.conf"
    rm -f "$SERVICE_DIR/$NAME.service"
    systemctl daemon-reload
    ech "已删除规则 $NAME"

    nft_clear
}

status_show() {
    systemctl --type=service --state=running | grep -E "socat|realm|gost|hysteria" || true
    ech "--- nftables ---"
    nft list ruleset || true
}

# ================================================================
# Menu
# ================================================================
main_menu() {
    [[ "$(id -u)" != 0 ]] && { ech "请用 root 运行"; exit 1; }

    while true; do
        cat <<EOF

=========== 多模式 UDP 转发菜单 ===============
1) 安装通用依赖
2) 安装工具 (socat/gost/realm/hysteria)
3) 添加转发规则
4) 查看规则
5) 删除规则
6) 查看运行状态
7) 退出
================================================
EOF
        read -rp "选择: " CH
        case "$CH" in
            1) install_common ;;
            2)
                echo "1: socat  2: gost  3: realm  4: hysteria"
                read -rp "选择安装工具: " T
                case "$T" in
                    1) install_socat ;;
                    2) install_gost ;;
                    3) install_realm ;;
                    4) install_hysteria ;;
                    *) ech "无效" ;;
                esac
            ;;
            3) add_rule_interactive ;;
            4) list_rules ;;
            5) delete_rule_interactive ;;
            6) status_show ;;
            7) exit 0 ;;
            *) ech "无效" ;;
        esac
    done
}

main_menu
