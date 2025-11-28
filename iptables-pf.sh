#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要 root 权限执行${NC}"
        exit 1
    fi
}

# 安装依赖
install_dependencies() {
    echo -e "${YELLOW}检查并安装依赖...${NC}"
    
    # 检查系统类型
    if [[ -f /etc/redhat-release ]]; then
        # CentOS/RHEL
        if command -v dnf >/dev/null 2>&1; then
            dnf install -y iptables iptables-services ip6tables iptables-utils 2>/dev/null
        else
            yum install -y iptables iptables-services ip6tables iptables-utils 2>/dev/null
        fi
    elif [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y iptables ip6tables iptables-persistent 2>/dev/null
    elif [[ -f /etc/arch-release ]]; then
        # Arch Linux
        pacman -Sy --noconfirm iptables ip6tables 2>/dev/null
    else
        echo -e "${YELLOW}无法自动识别系统类型，请手动安装 iptables 和 ip6tables${NC}"
    fi
    
    # 检查是否安装成功
    if command -v iptables >/dev/null 2>&1 && command -v ip6tables >/dev/null 2>&1; then
        echo -e "${GREEN}依赖安装完成${NC}"
    else
        echo -e "${RED}依赖安装失败，请手动安装 iptables 和 ip6tables${NC}"
        exit 1
    fi
}

# 启用 IP 转发
enable_ip_forward() {
    echo -e "${YELLOW}启用 IP 转发...${NC}"
    
    # 备份原有配置
    cp /etc/sysctl.conf /etc/sysctl.conf.bak 2>/dev/null
    
    # IPv4 转发
    if ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
        echo 'net.ipv4.ip_forward = 1' >> /etc/sysctl.conf
    fi
    
    # IPv6 转发
    if ! grep -q "net.ipv6.conf.all.forwarding = 1" /etc/sysctl.conf; then
        echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
    fi
    
    # 应用配置
    sysctl -p >/dev/null 2>&1
    
    echo -e "${GREEN}IP 转发已启用${NC}"
}

# 验证 IP 地址格式
validate_ip() {
    local ip=$1
    local version=$2
    
    if [[ $version == "ipv4" ]]; then
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return 0
        fi
    elif [[ $version == "ipv6" ]]; then
        if [[ $ip =~ ^[0-9a-fA-F:]+$ ]]; then
            return 0
        fi
    fi
    return 1
}

# 获取用户输入
get_user_input() {
    echo -e "${BLUE}=== iptables 端口转发配置 ===${NC}"
    echo
    
    # 选择协议
    while true; do
        read -p "选择协议 (tcp/udp/both) [默认: both]: " protocol
        protocol=${protocol:-both}
        case $protocol in
            tcp|udp|both) break ;;
            *) echo -e "${RED}无效选择，请输入 tcp, udp 或 both${NC}" ;;
        esac
    done
    
    # 输入监听端口
    while true; do
        read -p "输入监听端口: " listen_port
        if [[ $listen_port =~ ^[0-9]+$ ]] && [ $listen_port -ge 1 ] && [ $listen_port -le 65535 ]; then
            break
        else
            echo -e "${RED}无效端口，请输入 1-65535 之间的数字${NC}"
        fi
    done
    
    # 输入目标地址
    while true; do
        read -p "输入目标地址 (IP 或域名): " target_host
        if [[ -n $target_host ]]; then
            break
        else
            echo -e "${RED}目标地址不能为空${NC}"
        fi
    done
    
    # 输入目标端口
    while true; do
        read -p "输入目标端口: " target_port
        if [[ $target_port =~ ^[0-9]+$ ]] && [ $target_port -ge 1 ] && [ $target_port -le 65535 ]; then
            break
        else
            echo -e "${RED}无效端口，请输入 1-65535 之间的数字${NC}"
        fi
    done
    
    # 选择 IP 版本
    while true; do
        read -p "选择 IP 版本 (ipv4/ipv6/both) [默认: both]: " ip_version
        ip_version=${ip_version:-both}
        case $ip_version in
            ipv4|ipv6|both) break ;;
            *) echo -e "${RED}无效选择，请输入 ipv4, ipv6 或 both${NC}" ;;
        esac
    done
}

# 解析目标地址
resolve_target() {
    local host=$1
    local version=$2
    
    # 如果是 IP 地址，直接返回
    if validate_ip "$host" "ipv4"; then
        echo "$host"
        return 0
    elif validate_ip "$host" "ipv6"; then
        echo "$host"
        return 0
    fi
    
    # 根据 IP 版本解析域名
    if [[ $version == "ipv4" ]]; then
        # 只获取 IPv4 地址
        result=$(dig +short A "$host" | head -n1)
        if [[ -z $result ]]; then
            result=$(getent ahosts "$host" 2>/dev/null | awk '$2 == "STREAM" && $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $1; exit}')
        fi
    elif [[ $version == "ipv6" ]]; then
        # 只获取 IPv6 地址
        result=$(dig +short AAAA "$host" | head -n1)
        if [[ -z $result ]]; then
            result=$(getent ahosts "$host" 2>/dev/null | awk '$2 == "STREAM" && $1 ~ /:/ {print $1; exit}')
        fi
    else
        # 尝试获取 IPv4，如果失败则获取 IPv6
        result=$(dig +short A "$host" | head -n1)
        if [[ -z $result ]]; then
            result=$(dig +short AAAA "$host" | head -n1)
        fi
    fi
    
    if [[ -z $result ]]; then
        echo -e "${RED}无法解析目标地址: $host${NC}"
        return 1
    fi
    
    echo "$result"
}

# 配置 iptables 规则
configure_iptables() {
    local protocol=$1
    local listen_port=$2
    local target_ip=$3
    local target_port=$4
    local ip_type=$5
    
    echo -e "${YELLOW}配置 $ip_type 转发规则...${NC}"
    
    if [[ $ip_type == "ipv4" ]]; then
        iptables_cmd="iptables"
        target_addr="$target_ip:$target_port"
    else
        iptables_cmd="ip6tables"
        # IPv6 地址需要用方括号括起来
        target_addr="[$target_ip]:$target_port"
    fi
    
    # 检查是否已存在相同规则
    if $iptables_cmd -t nat -C PREROUTING -p tcp --dport $listen_port -j DNAT --to-destination $target_addr 2>/dev/null; then
        echo -e "${YELLOW}$ip_type TCP 规则已存在，跳过${NC}"
    elif [[ $protocol == "tcp" || $protocol == "both" ]]; then
        $iptables_cmd -t nat -A PREROUTING -p tcp --dport $listen_port -j DNAT --to-destination $target_addr
        $iptables_cmd -A FORWARD -p tcp -d $target_ip --dport $target_port -j ACCEPT
        echo -e "${GREEN}已添加 $ip_type TCP 转发: $listen_port -> $target_ip:$target_port${NC}"
    fi
    
    if [[ $protocol == "udp" || $protocol == "both" ]]; then
        if $iptables_cmd -t nat -C PREROUTING -p udp --dport $listen_port -j DNAT --to-destination $target_addr 2>/dev/null; then
            echo -e "${YELLOW}$ip_type UDP 规则已存在，跳过${NC}"
        else
            $iptables_cmd -t nat -A PREROUTING -p udp --dport $listen_port -j DNAT --to-destination $target_addr
            $iptables_cmd -A FORWARD -p udp -d $target_ip --dport $target_port -j ACCEPT
            echo -e "${GREEN}已添加 $ip_type UDP 转发: $listen_port -> $target_ip:$target_port${NC}"
        fi
    fi
    
    # 添加 POSTROUTING 规则确保数据包能正确返回
    if [[ $ip_type == "ipv4" ]]; then
        $iptables_cmd -t nat -A POSTROUTING -j MASQUERADE
    else
        $iptables_cmd -t nat -A POSTROUTING -j MASQUERADE
    fi
}

# 保存 iptables 规则
save_iptables_rules() {
    echo -e "${YELLOW}保存 iptables 规则...${NC}"
    
    # 创建保存目录
    mkdir -p /etc/iptables
    
    # 保存 IPv4 规则
    if command -v iptables-save >/dev/null 2>&1; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null && \
        echo -e "${GREEN}IPv4 规则已保存到 /etc/iptables/rules.v4${NC}"
    fi
    
    # 保存 IPv6 规则
    if command -v ip6tables-save >/dev/null 2>&1; then
        ip6tables-save > /etc/iptables/rules.v6 2>/dev/null && \
        echo -e "${GREEN}IPv6 规则已保存到 /etc/iptables/rules.v6${NC}"
    fi
    
    # 对于不同系统的持久化
    if [[ -f /etc/redhat-release ]]; then
        # CentOS/RHEL
        if systemctl is-active iptables >/dev/null 2>&1; then
            systemctl enable iptables 2>/dev/null
            service iptables save 2>/dev/null
        fi
        if systemctl is-active ip6tables >/dev/null 2>&1; then
            systemctl enable ip6tables 2>/dev/null
            service ip6tables save 2>/dev/null
        fi
    elif [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save 2>/dev/null
        fi
    fi
    
    echo -e "${GREEN}规则保存完成${NC}"
}

# 显示当前规则
show_current_rules() {
    echo -e "${BLUE}=== 当前 IPv4 转发规则 ===${NC}"
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep -E "DNAT|dpt:" || echo "无 IPv4 转发规则"
    
    echo -e "${BLUE}=== 当前 IPv6 转发规则 ===${NC}"
    ip6tables -t nat -L PREROUTING -n 2>/dev/null | grep -E "DNAT|dpt:" || echo "无 IPv6 转发规则"
}

# 测试连接
test_connection() {
    local target_ip=$1
    local target_port=$2
    local ip_type=$3
    
    echo -e "${YELLOW}测试 $ip_type 连接到 $target_ip:$target_port ...${NC}"
    
    if [[ $ip_type == "ipv4" ]]; then
        if command -v nc >/dev/null 2>&1; then
            if nc -z -w 3 $target_ip $target_port 2>/dev/null; then
                echo -e "${GREEN}$ip_type 连接测试成功${NC}"
            else
                echo -e "${YELLOW}$ip_type 连接测试失败（这可能正常，如果目标服务未运行）${NC}"
            fi
        else
            echo -e "${YELLOW}未安装 nc (netcat)，跳过连接测试${NC}"
        fi
    else
        if command -v nc >/dev/null 2>&1; then
            if nc -6 -z -w 3 $target_ip $target_port 2>/dev/null; then
                echo -e "${GREEN}$ip_type 连接测试成功${NC}"
            else
                echo -e "${YELLOW}$ip_type 连接测试失败（这可能正常，如果目标服务未运行）${NC}"
            fi
        else
            echo -e "${YELLOW}未安装 nc (netcat)，跳过连接测试${NC}"
        fi
    fi
}

# 主函数
main() {
    check_root
    
    echo -e "${GREEN}开始配置 iptables 端口转发${NC}"
    echo
    
    # 安装依赖
    install_dependencies
    
    # 启用 IP 转发
    enable_ip_forward
    
    # 获取用户输入
    get_user_input
    
    # 根据 IP 版本处理
    if [[ $ip_version == "ipv4" || $ip_version == "both" ]]; then
        target_ipv4=$(resolve_target "$target_host" "ipv4")
        if [[ -n $target_ipv4 ]] && validate_ip "$target_ipv4" "ipv4"; then
            configure_iptables "$protocol" "$listen_port" "$target_ipv4" "$target_port" "ipv4"
            test_connection "$target_ipv4" "$target_port" "ipv4"
        else
            echo -e "${RED}无法解析或无效的 IPv4 地址: $target_host${NC}"
        fi
    fi
    
    if [[ $ip_version == "ipv6" || $ip_version == "both" ]]; then
        target_ipv6=$(resolve_target "$target_host" "ipv6")
        if [[ -n $target_ipv6 ]] && validate_ip "$target_ipv6" "ipv6"; then
            configure_iptables "$protocol" "$listen_port" "$target_ipv6" "$target_port" "ipv6"
            test_connection "$target_ipv6" "$target_port" "ipv6"
        else
            echo -e "${RED}无法解析或无效的 IPv6 地址: $target_host${NC}"
        fi
    fi
    
    # 保存规则
    save_iptables_rules
    
    echo -e "${GREEN}配置完成！${NC}"
    echo
    show_current_rules
    
    echo
    echo -e "${YELLOW}注意事项:${NC}"
    echo -e "1. 确保防火墙已允许转发流量"
    echo -e "2. 重启后规则可能会丢失，请确认已正确保存"
    echo -e "3. 可以使用 'iptables -t nat -L -n' 查看当前规则"
    echo -e "4. 可以使用 'ip6tables -t nat -L -n' 查看 IPv6 规则"
}

# 运行主函数
main "$@"
