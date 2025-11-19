#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
CURRENT_DIR=$(pwd)
CONFIG_DIR="/etc/network_toolkit"

# 初始化配置目录
init_config() {
    mkdir -p $CONFIG_DIR
}

# 系统检测
detect_os() {
    if [ -f /etc/redhat-release ]; then
        echo "centos"
    elif [ -f /etc/debian_version ]; then
        if grep -q "Ubuntu" /etc/os-release; then
            echo "ubuntu"
        else
            echo "debian"
        fi
    else
        echo "unknown"
    fi
}

# 检查root权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}请使用root权限运行此脚本${NC}"
        exit 1
    fi
}

# 等待用户按键
press_any_key() {
    echo
    read -n 1 -s -r -p "按任意键继续..."
    clear
}

# ==================== BBR 加速模块 ====================

BBR_MODULE_DIR="$CONFIG_DIR/bbr"

bbr_detect_system() {
    OS=$(detect_os)
    KERNEL_VERSION=$(uname -r | cut -d '-' -f 1)
}

bbr_check_kernel_support() {
    local major=$(echo $KERNEL_VERSION | cut -d '.' -f 1)
    local minor=$(echo $KERNEL_VERSION | cut -d '.' -f 2)
    
    if [ $major -lt 4 ] || ([ $major -eq 4 ] && [ $minor -lt 9 ]); then
        return 1
    fi
    return 0
}

bbr_check_status() {
    echo -e "${BLUE}检查 BBR 状态...${NC}"
    
    local bbr_enabled=0
    local fq_enabled=0
    
    if [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
        local current_cc=$(cat /proc/sys/net/ipv4/tcp_congestion_control)
        if [ "$current_cc" = "bbr" ]; then
            bbr_enabled=1
            echo -e "${GREEN}✓ BBR 已启用${NC}"
        else
            echo -e "${YELLOW}✗ BBR 未启用 (当前: $current_cc)${NC}"
        fi
    fi
    
    if [ -f /proc/sys/net/core/default_qdisc ]; then
        local current_qdisc=$(cat /proc/sys/net/core/default_qdisc)
        if [ "$current_qdisc" = "fq" ]; then
            fq_enabled=1
            echo -e "${GREEN}✓ FQ 队列规则已启用${NC}"
        else
            echo -e "${YELLOW}✗ FQ 队列规则未启用 (当前: $current_qdisc)${NC}"
        fi
    fi
    
    if lsmod | grep -q "tcp_bbr"; then
        echo -e "${GREEN}✓ BBR 内核模块已加载${NC}"
    else
        echo -e "${YELLOW}✗ BBR 内核模块未加载${NC}"
    fi
    
    if [ $bbr_enabled -eq 1 ] && [ $fq_enabled -eq 1 ]; then
        return 0
    else
        return 1
    fi
}

bbr_enable() {
    echo -e "${BLUE}启用 BBR 加速...${NC}"
    
    if ! lsmod | grep -q "tcp_bbr"; then
        modprobe tcp_bbr
    fi
    
    echo "bbr" > /proc/sys/net/ipv4/tcp_congestion_control
    echo "fq" > /proc/sys/net/core/default_qdisc
    
    # 优化TCP参数
    cat >> /etc/sysctl.conf << EOF

# BBR 网络优化配置
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.ip_local_port_range = 1024 65535
fs.file-max = 102400
EOF

    sysctl -p > /dev/null 2>&1
    echo -e "${GREEN}✓ BBR+FQ 加速已启用${NC}"
}

bbr_disable() {
    echo -e "${YELLOW}禁用 BBR...${NC}"
    echo "cubic" > /proc/sys/net/ipv4/tcp_congestion_control
    echo "pfifo_fast" > /proc/sys/net/core/default_qdisc
    
    # 从配置文件中移除BBR设置
    sed -i '/^# BBR/,/^fs.file-max/d' /etc/sysctl.conf
    echo -e "${GREEN}✓ BBR 已禁用${NC}"
}

bbr_update_kernel() {
    echo -e "${BLUE}更新系统内核...${NC}"
    local os_type=$(detect_os)
    
    case $os_type in
        "ubuntu"|"debian")
            apt update
            apt install -y linux-image-generic-hwe-$(lsb_release -rs)
            ;;
        "centos")
            yum update -y kernel
            ;;
    esac
    
    echo -e "${GREEN}✓ 内核更新完成，请重启系统${NC}"
}

bbr_menu() {
    while true; do
        echo -e "\n${BLUE}=== BBR 网络加速管理 ===${NC}"
        echo -e "${GREEN}1.${NC} 启用 BBR+FQ 加速"
        echo -e "${GREEN}2.${NC} 检查 BBR 状态"
        echo -e "${GREEN}3.${NC} 禁用 BBR"
        echo -e "${GREEN}4.${NC} 更新系统内核"
        echo -e "${GREEN}5.${NC} 网络性能测试"
        echo -e "${GREEN}0.${NC} 返回主菜单"
        echo -e "${BLUE}========================${NC}"
        
        read -p "请选择操作 [0-5]: " choice
        
        case $choice in
            1)
                bbr_detect_system
                if bbr_check_kernel_support; then
                    bbr_enable
                else
                    echo -e "${RED}当前内核版本 $KERNEL_VERSION 不支持 BBR${NC}"
                    read -p "是否更新内核？(y/N): " update_confirm
                    if [[ $update_confirm =~ ^[Yy]$ ]]; then
                        bbr_update_kernel
                    fi
                fi
                ;;
            2)
                bbr_check_status
                ;;
            3)
                bbr_disable
                ;;
            4)
                bbr_update_kernel
                ;;
            5)
                echo -e "${BLUE}网络性能测试...${NC}"
                ping -c 4 8.8.8.8 | tail -2
                ;;
            0)
                break
                ;;
            *)
                echo -e "${RED}无效选择${NC}"
                ;;
        esac
        press_any_key
    done
}

# ==================== iptables 转发模块 ====================

IPTABLES_MODULE_DIR="$CONFIG_DIR/iptables"

iptables_format_destination() {
    local ip=$1
    local port=$2
    
    ip=$(echo "$ip" | sed 's/^\[//;s/\]$//')
    port=$(echo "$port" | tr -d ':')
    
    if [[ $ip =~ : ]]; then
        echo "[$ip]:$port"
    else
        echo "$ip:$port"
    fi
}

iptables_list_rules() {
    echo -e "${BLUE}=== iptables 转发规则 ===${NC}"
    
    local has_rules=0
    
    # IPv4规则
    echo -e "${CYAN}IPv4 规则:${NC}"
    iptables -t nat -L PREROUTING -n | grep "DNAT" | grep "dpt:" | while read line; do
        echo -e "  ${GREEN}$line${NC}"
        has_rules=1
    done
    
    # IPv6规则
    echo -e "${CYAN}IPv6 规则:${NC}"
    ip6tables -t nat -L PREROUTING -n | grep "DNAT" | grep "dpt:" | while read line; do
        echo -e "  ${GREEN}$line${NC}"
        has_rules=1
    done
    
    if [ $has_rules -eq 0 ]; then
        echo -e "${YELLOW}暂无转发规则${NC}"
    fi
}

iptables_add_rule() {
    echo -e "${BLUE}添加 iptables 转发规则${NC}"
    
    read -p "请输入本地端口: " local_port
    read -p "请输入目标IP: " target_ip
    read -p "请输入目标端口: " target_port
    read -p "请输入协议 (tcp/udp/both, 默认tcp): " protocol
    protocol=${protocol:-tcp}
    
    destination=$(iptables_format_destination "$target_ip" "$target_port")
    
    if [[ $target_ip =~ : ]]; then
        iptables_cmd="ip6tables"
        ip_version="IPv6"
    else
        iptables_cmd="iptables"
        ip_version="IPv4"
    fi
    
    if [[ $protocol == "both" ]]; then
        protocols=("tcp" "udp")
    else
        protocols=($protocol)
    fi
    
    clean_target_ip=$(echo "$target_ip" | sed 's/^\[//;s/\]$//')
    
    for proto in "${protocols[@]}"; do
        $iptables_cmd -t nat -A PREROUTING -p $proto --dport $local_port -j DNAT --to-destination $destination
        $iptables_cmd -t nat -A POSTROUTING -p $proto -d $clean_target_ip --dport $target_port -j MASQUERADE
        $iptables_cmd -A FORWARD -p $proto -d $clean_target_ip --dport $target_port -j ACCEPT
        $iptables_cmd -A FORWARD -p $proto -s $clean_target_ip --sport $target_port -j ACCEPT
    done
    
    echo -e "${GREEN}✓ 规则添加成功: $local_port -> $destination ($protocol)${NC}"
}

iptables_delete_rule() {
    echo -e "${YELLOW}删除 iptables 规则${NC}"
    iptables_list_rules
    
    read -p "请输入要删除的本地端口: " local_port
    read -p "请输入协议 (tcp/udp, 默认tcp): " protocol
    protocol=${protocol:-tcp}
    
    for iptables_cmd in "iptables" "ip6tables"; do
        # 获取规则编号
        rules=$($iptables_cmd -t nat -L PREROUTING -n --line-numbers | grep "dpt:$local_port.*$proto" | awk '{print $1}' | sort -rn)
        
        for rule in $rules; do
            $iptables_cmd -t nat -D PREROUTING $rule
        done
    done
    
    echo -e "${GREEN}✓ 端口 $local_port 的规则已删除${NC}"
}

iptables_save_rules() {
    local os_type=$(detect_os)
    
    case $os_type in
        "centos")
            service iptables save
            service ip6tables save
            ;;
        "ubuntu"|"debian")
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
            ;;
    esac
    echo -e "${GREEN}✓ iptables 规则已保存${NC}"
}

iptables_menu() {
    while true; do
        echo -e "\n${BLUE}=== iptables 端口转发管理 ===${NC}"
        echo -e "${GREEN}1.${NC} 添加转发规则"
        echo -e "${GREEN}2.${NC} 查看转发规则"
        echo -e "${GREEN}3.${NC} 删除转发规则"
        echo -e "${GREEN}4.${NC} 保存规则"
        echo -e "${GREEN}5.${NC} 安装 iptables"
        echo -e "${GREEN}0.${NC} 返回主菜单"
        echo -e "${BLUE}============================${NC}"
        
        read -p "请选择操作 [0-5]: " choice
        
        case $choice in
            1) iptables_add_rule ;;
            2) iptables_list_rules ;;
            3) iptables_delete_rule ;;
            4) iptables_save_rules ;;
            5) 
                echo -e "${BLUE}安装 iptables...${NC}"
                apt update && apt install -y iptables ip6tables
                ;;
            0) break ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
        press_any_key
    done
}

# ==================== realm 转发模块 ====================

REALM_MODULE_DIR="$CONFIG_DIR/realm"
REALM_CONFIG_FILE="/etc/realm.conf"

realm_install() {
    echo -e "${BLUE}安装 realm...${NC}"
    local os_type=$(detect_os)
    
    case $os_type in
        "centos")
            yum install -y epel-release
            yum install -y realm
            ;;
        "ubuntu"|"debian")
            apt update
            apt install -y realm
            ;;
    esac
    
    if command -v realm >/dev/null 2>&1; then
        echo -e "${GREEN}✓ realm 安装成功${NC}"
    else
        echo -e "${RED}realm 安装失败，尝试源码安装...${NC}"
        curl -fsSL https://raw.githubusercontent.com/zhboner/realm/master/install.sh | sh
    fi
}

realm_list_rules() {
    if [ ! -f "$REALM_CONFIG_FILE" ]; then
        echo -e "${YELLOW}暂无 realm 转发规则${NC}"
        return
    fi
    
    echo -e "${BLUE}=== realm 转发规则 ===${NC}"
    local rule_count=0
    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            rule_count=$((rule_count + 1))
            echo -e "  ${GREEN}$rule_count. $line${NC}"
        fi
    done < "$REALM_CONFIG_FILE"
    
    if [ $rule_count -eq 0 ]; then
        echo -e "${YELLOW}暂无转发规则${NC}"
    fi
}

realm_add_rule() {
    echo -e "${BLUE}添加 realm 转发规则${NC}"
    
    read -p "请输入监听地址 (默认: 0.0.0.0): " listen_addr
    listen_addr=${listen_addr:-"0.0.0.0"}
    read -p "请输入监听端口: " listen_port
    read -p "请输入目标地址: " target_addr
    read -p "请输入目标端口: " target_port
    
    # IPv6地址处理
    if [[ $listen_addr =~ : ]] && [[ ! $listen_addr =~ \[.*\] ]]; then
        listen_addr="[$listen_addr]"
    fi
    if [[ $target_addr =~ : ]] && [[ ! $target_addr =~ \[.*\] ]]; then
        target_addr="[$target_addr]"
    fi
    
    local rule_line="$listen_addr:$listen_port $target_addr:$target_port"
    
    # 创建配置目录
    mkdir -p $(dirname "$REALM_CONFIG_FILE")
    
    # 检查规则是否已存在
    if [ -f "$REALM_CONFIG_FILE" ] && grep -qF "$rule_line" "$REALM_CONFIG_FILE"; then
        echo -e "${YELLOW}规则已存在${NC}"
        return
    fi
    
    echo "$rule_line" >> "$REALM_CONFIG_FILE"
    echo -e "${GREEN}✓ 规则添加成功: $rule_line${NC}"
}

realm_delete_rule() {
    realm_list_rules
    read -p "请输入要删除的规则编号: " rule_num
    
    if [ ! -f "$REALM_CONFIG_FILE" ]; then
        echo -e "${RED}配置文件不存在${NC}"
        return
    fi
    
    local temp_file=$(mktemp)
    local current_line=0
    local target_line=""
    
    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            current_line=$((current_line + 1))
            if [ $current_line -ne $rule_num ]; then
                echo "$line" >> "$temp_file"
            else
                target_line="$line"
            fi
        else
            echo "$line" >> "$temp_file"
        fi
    done < "$REALM_CONFIG_FILE"
    
    if [ -n "$target_line" ]; then
        mv "$temp_file" "$REALM_CONFIG_FILE"
        echo -e "${GREEN}✓ 规则删除成功: $target_line${NC}"
    else
        rm -f "$temp_file"
        echo -e "${RED}未找到指定规则${NC}"
    fi
}

realm_manage_service() {
    if ! command -v realm >/dev/null 2>&1; then
        echo -e "${RED}realm 未安装${NC}"
        return
    fi
    
    echo -e "${BLUE}realm 服务管理${NC}"
    echo -e "1. 启动服务"
    echo -e "2. 停止服务"
    echo -e "3. 重启服务"
    echo -e "4. 查看状态"
    
    read -p "请选择: " service_choice
    
    case $service_choice in
        1)
            if pgrep -x "realm" >/dev/null; then
                echo -e "${YELLOW}realm 已在运行${NC}"
            else
                realm -c "$REALM_CONFIG_FILE" &
                echo -e "${GREEN}✓ realm 服务已启动${NC}"
            fi
            ;;
        2)
            pkill -x "realm"
            echo -e "${GREEN}✓ realm 服务已停止${NC}"
            ;;
        3)
            pkill -x "realm"
            sleep 1
            realm -c "$REALM_CONFIG_FILE" &
            echo -e "${GREEN}✓ realm 服务已重启${NC}"
            ;;
        4)
            if pgrep -x "realm" >/dev/null; then
                echo -e "${GREEN}realm 服务正在运行${NC}"
                ps aux | grep realm | grep -v grep
            else
                echo -e "${RED}realm 服务未运行${NC}"
            fi
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            ;;
    esac
}

realm_menu() {
    while true; do
        echo -e "\n${BLUE}=== realm 端口转发管理 ===${NC}"
        echo -e "${GREEN}1.${NC} 安装 realm"
        echo -e "${GREEN}2.${NC} 添加转发规则"
        echo -e "${GREEN}3.${NC} 查看转发规则"
        echo -e "${GREEN}4.${NC} 删除转发规则"
        echo -e "${GREEN}5.${NC} 服务管理"
        echo -e "${GREEN}0.${NC} 返回主菜单"
        echo -e "${BLUE}==========================${NC}"
        
        read -p "请选择操作 [0-5]: " choice
        
        case $choice in
            1) realm_install ;;
            2) realm_add_rule ;;
            3) realm_list_rules ;;
            4) realm_delete_rule ;;
            5) realm_manage_service ;;
            0) break ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
        press_any_key
    done
}

# ==================== 系统信息模块 ====================

system_info() {
    echo -e "${BLUE}=== 系统信息 ===${NC}"
    echo -e "主机名: $(hostname)"
    echo -e "操作系统: $(detect_os)"
    echo -e "内核版本: $(uname -r)"
    echo -e "架构: $(uname -m)"
    
    echo -e "\n${BLUE}=== 网络信息 ===${NC}"
    echo -e "IP地址: $(hostname -I 2>/dev/null || ip addr show | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | head -1)"
    echo -e "公网IP: $(curl -s http://ipinfo.io/ip || echo "无法获取")"
    
    echo -e "\n${BLUE}=== 服务状态 ===${NC}"
    bbr_check_status
}

# ==================== 主菜单 ====================

show_banner() {
    clear
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════╗"
    echo "║          网络工具集 v2.0                ║"
    echo "║         Network Toolkit v2.0            ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
}

main_menu() {
    while true; do
        show_banner
        echo -e "${BLUE}请选择功能模块:${NC}"
        echo -e "${GREEN}1.${NC} BBR 网络加速管理"
        echo -e "${GREEN}2.${NC} iptables 端口转发"
        echo -e "${GREEN}3.${NC} realm 端口转发"
        echo -e "${GREEN}4.${NC} 系统信息"
        echo -e "${GREEN}0.${NC} 退出"
        echo -e "${BLUE}========================${NC}"
        
        read -p "请输入选择 [0-4]: " main_choice
        
        case $main_choice in
            1) bbr_menu ;;
            2) iptables_menu ;;
            3) realm_menu ;;
            4) 
                system_info
                press_any_key
                ;;
            0)
                echo -e "${GREEN}感谢使用！再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请重新输入${NC}"
                sleep 2
                ;;
        esac
    done
}

# ==================== 脚本初始化 ====================

init_script() {
    check_root
    init_config
    detect_os
}

# 安装依赖
install_dependencies() {
    local os_type=$(detect_os)
    echo -e "${BLUE}安装必要依赖...${NC}"
    
    case $os_type in
        "ubuntu"|"debian")
            apt update
            apt install -y curl wget iputils-ping
            ;;
        "centos")
            yum install -y curl wget iputils
            ;;
    esac
}

# 主程序
main() {
    init_script
    
    # 检查并安装依赖
    if ! command -v curl >/dev/null 2>&1; then
        install_dependencies
    fi
    
    # 显示欢迎信息
    show_banner
    echo -e "${GREEN}系统检测: $(detect_os) | 内核: $(uname -r)${NC}"
    echo -e "${YELLOW}正在加载网络工具集...${NC}"
    sleep 2
    
    # 进入主菜单
    main_menu
}

# 脚本说明
echo -e "${BLUE}网络工具集 v2.0${NC}"
echo -e "功能: BBR加速 + iptables转发 + realm转发"
echo -e "支持: Debian/Ubuntu/CentOS"

# 启动主程序
main
