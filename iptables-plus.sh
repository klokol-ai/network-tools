#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 规则存储文件
RULES_FILE="/etc/iptables/forwarding_rules.conf"

# 检查 root 权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此脚本需要 root 权限执行${NC}"
        exit 1
    fi
}

# 初始化规则文件
init_rules_file() {
    mkdir -p /etc/iptables
    if [[ ! -f $RULES_FILE ]]; then
        touch $RULES_FILE
        echo "# iptables 端口转发规则记录" > $RULES_FILE
        echo "# 格式: 协议:监听端口:目标IP:目标端口:IP版本:规则哈希" >> $RULES_FILE
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

# 生成规则哈希
generate_rule_hash() {
    local protocol=$1
    local listen_port=$2
    local target_ip=$3
    local target_port=$4
    local ip_version=$5
    echo "$protocol:$listen_port:$target_ip:$target_port:$ip_version" | md5sum | cut -d' ' -f1
}

# 保存规则到文件
save_rule_to_file() {
    local protocol=$1
    local listen_port=$2
    local target_ip=$3
    local target_port=$4
    local ip_version=$5
    local rule_hash=$(generate_rule_hash "$protocol" "$listen_port" "$target_ip" "$target_port" "$ip_version")
    
    # 检查是否已存在
    if ! grep -q "$rule_hash" $RULES_FILE; then
        echo "$protocol:$listen_port:$target_ip:$target_port:$ip_version:$rule_hash" >> $RULES_FILE
        echo -e "${GREEN}规则已保存到规则文件${NC}"
    fi
}

# 从文件删除规则
delete_rule_from_file() {
    local rule_hash=$1
    sed -i "/$rule_hash/d" $RULES_FILE
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

# 显示菜单
show_menu() {
    echo -e "${BLUE}=== iptables 端口转发管理 ===${NC}"
    echo
    echo -e "${GREEN}1. 添加端口转发规则${NC}"
    echo -e "${GREEN}2. 查看当前转发规则${NC}"
    echo -e "${GREEN}3. 删除端口转发规则${NC}"
    echo -e "${GREEN}4. 测试连接${NC}"
    echo -e "${GREEN}5. 保存规则到持久化存储${NC}"
    echo -e "${GREEN}6. 退出${NC}"
    echo
}

# 获取用户输入 - 添加规则
get_user_input_add() {
    echo -e "${BLUE}=== 添加端口转发规则 ===${NC}"
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
    
    # 根据协议设置规则
    if [[ $protocol == "tcp" || $protocol == "both" ]]; then
        # 删除可能存在的重复规则
        $iptables_cmd -t nat -D PREROUTING -p tcp --dport $listen_port -j DNAT --to-destination $target_addr 2>/dev/null
        $iptables_cmd -D FORWARD -p tcp -d $target_ip --dport $target_port -j ACCEPT 2>/dev/null
        
        # 添加新规则
        $iptables_cmd -t nat -A PREROUTING -p tcp --dport $listen_port -j DNAT --to-destination $target_addr
        $iptables_cmd -A FORWARD -p tcp -d $target_ip --dport $target_port -j ACCEPT
        echo -e "${GREEN}已添加 $ip_type TCP 转发: $listen_port -> $target_ip:$target_port${NC}"
    fi
    
    if [[ $protocol == "udp" || $protocol == "both" ]]; then
        # 删除可能存在的重复规则
        $iptables_cmd -t nat -D PREROUTING -p udp --dport $listen_port -j DNAT --to-destination $target_addr 2>/dev/null
        $iptables_cmd -D FORWARD -p udp -d $target_ip --dport $target_port -j ACCEPT 2>/dev/null
        
        # 添加新规则
        $iptables_cmd -t nat -A PREROUTING -p udp --dport $listen_port -j DNAT --to-destination $target_addr
        $iptables_cmd -A FORWARD -p udp -d $target_ip --dport $target_port -j ACCEPT
        echo -e "${GREEN}已添加 $ip_type UDP 转发: $listen_port -> $target_ip:$target_port${NC}"
    fi
    
    # 添加 POSTROUTING 规则确保数据包能正确返回
    $iptables_cmd -t nat -D POSTROUTING -j MASQUERADE 2>/dev/null
    $iptables_cmd -t nat -A POSTROUTING -j MASQUERADE
}

# 显示所有规则
show_all_rules() {
    echo -e "${BLUE}=== 已保存的转发规则 ===${NC}"
    
    if [[ ! -s $RULES_FILE ]]; then
        echo -e "${YELLOW}没有已保存的规则${NC}"
        return
    fi
    
    echo
    echo -e "${CYAN}编号 | 协议 | 监听端口 | 目标地址 | 目标端口 | IP版本 | 规则哈希${NC}"
    echo "----------------------------------------------------------------------------"
    
    local count=1
    while IFS=: read -r protocol listen_port target_ip target_port ip_version rule_hash; do
        if [[ $protocol != "#"* ]] && [[ -n $protocol ]]; then
            printf "%-4s | %-6s | %-10s | %-15s | %-10s | %-7s | %s\n" \
                   "$count" "$protocol" "$listen_port" "$target_ip" "$target_port" "$ip_version" "${rule_hash:0:8}..."
            ((count++))
        fi
    done < "$RULES_FILE"
    
    echo
    echo -e "${BLUE}=== 当前生效的 iptables 规则 ===${NC}"
    echo
    echo -e "${GREEN}IPv4 TCP 规则:${NC}"
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep -E "tcp dpt:|DNAT" | grep tcp || echo "无 IPv4 TCP 规则"
    
    echo
    echo -e "${GREEN}IPv4 UDP 规则:${NC}"
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep -E "udp dpt:|DNAT" | grep udp || echo "无 IPv4 UDP 规则"
    
    echo
    echo -e "${GREEN}IPv6 TCP 规则:${NC}"
    ip6tables -t nat -L PREROUTING -n 2>/dev/null | grep -E "tcp dpt:|DNAT" | grep tcp || echo "无 IPv6 TCP 规则"
    
    echo
    echo -e "${GREEN}IPv6 UDP 规则:${NC}"
    ip6tables -t nat -L PREROUTING -n 2>/dev/null | grep -E "udp dpt:|DNAT" | grep udp || echo "无 IPv6 UDP 规则"
}

# 删除规则
delete_rule() {
    show_all_rules
    
    if [[ ! -s $RULES_FILE ]]; then
        return
    fi
    
    echo
    read -p "输入要删除的规则编号 (输入 0 取消): " rule_num
    
    if [[ $rule_num -eq 0 ]]; then
        return
    fi
    
    local count=1
    local target_rule=""
    
    # 查找对应规则
    while IFS=: read -r protocol listen_port target_ip target_port ip_version rule_hash; do
        if [[ $protocol != "#"* ]] && [[ -n $protocol ]]; then
            if [[ $count -eq $rule_num ]]; then
                target_rule="$protocol:$listen_port:$target_ip:$target_port:$ip_version:$rule_hash"
                break
            fi
            ((count++))
        fi
    done < "$RULES_FILE"
    
    if [[ -z $target_rule ]]; then
        echo -e "${RED}无效的规则编号${NC}"
        return
    fi
    
    IFS=: read -r protocol listen_port target_ip target_port ip_version rule_hash <<< "$target_rule"
    
    echo
    echo -e "${YELLOW}即将删除规则:${NC}"
    echo -e "协议: $protocol"
    echo -e "监听端口: $listen_port"
    echo -e "目标地址: $target_ip"
    echo -e "目标端口: $target_port"
    echo -e "IP版本: $ip_version"
    echo
    
    read -p "确认删除？(y/N): " confirm
    if [[ $confirm != "y" && $confirm != "Y" ]]; then
        echo -e "${YELLOW}取消删除${NC}"
        return
    fi
    
    # 从 iptables 删除规则
    if [[ $ip_version == "ipv4" || $ip_version == "both" ]]; then
        if [[ $protocol == "tcp" || $protocol == "both" ]]; then
            iptables -t nat -D PREROUTING -p tcp --dport $listen_port -j DNAT --to-destination $target_ip:$target_port 2>/dev/null
            iptables -D FORWARD -p tcp -d $target_ip --dport $target_port -j ACCEPT 2>/dev/null
        fi
        if [[ $protocol == "udp" || $protocol == "both" ]]; then
            iptables -t nat -D PREROUTING -p udp --dport $listen_port -j DNAT --to-destination $target_ip:$target_port 2>/dev/null
            iptables -D FORWARD -p udp -d $target_ip --dport $target_port -j ACCEPT 2>/dev/null
        fi
    fi
    
    if [[ $ip_version == "ipv6" || $ip_version == "both" ]]; then
        if [[ $protocol == "tcp" || $protocol == "both" ]]; then
            ip6tables -t nat -D PREROUTING -p tcp --dport $listen_port -j DNAT --to-destination "[$target_ip]:$target_port" 2>/dev/null
            ip6tables -D FORWARD -p tcp -d $target_ip --dport $target_port -j ACCEPT 2>/dev/null
        fi
        if [[ $protocol == "udp" || $protocol == "both" ]]; then
            ip6tables -t nat -D PREROUTING -p udp --dport $listen_port -j DNAT --to-destination "[$target_ip]:$target_port" 2>/dev/null
            ip6tables -D FORWARD -p udp -d $target_ip --dport $target_port -j ACCEPT 2>/dev/null
        fi
    fi
    
    # 从规则文件删除
    delete_rule_from_file "$rule_hash"
    
    echo -e "${GREEN}规则删除成功${NC}"
}

# 测试连接
test_connection() {
    echo -e "${BLUE}=== 连接测试 ===${NC}"
    
    if [[ ! -s $RULES_FILE ]]; then
        echo -e "${YELLOW}没有已保存的规则${NC}"
        return
    fi
    
    show_all_rules
    echo
    read -p "输入要测试的规则编号 (输入 0 取消): " rule_num
    
    if [[ $rule_num -eq 0 ]]; then
        return
    fi
    
    local count=1
    while IFS=: read -r protocol listen_port target_ip target_port ip_version rule_hash; do
        if [[ $protocol != "#"* ]] && [[ -n $protocol ]]; then
            if [[ $count -eq $rule_num ]]; then
                echo -e "${YELLOW}测试连接到 $target_ip:$target_port ...${NC}"
                
                if [[ $ip_version == "ipv4" || $ip_version == "both" ]]; then
                    if command -v nc >/dev/null 2>&1; then
                        if nc -z -w 3 $target_ip $target_port 2>/dev/null; then
                            echo -e "${GREEN}IPv4 连接测试成功${NC}"
                        else
                            echo -e "${YELLOW}IPv4 连接测试失败（这可能正常，如果目标服务未运行）${NC}"
                        fi
                    else
                        echo -e "${YELLOW}未安装 nc (netcat)，跳过 IPv4 连接测试${NC}"
                    fi
                fi
                
                if [[ $ip_version == "ipv6" || $ip_version == "both" ]]; then
                    if command -v nc >/dev/null 2>&1; then
                        if nc -6 -z -w 3 $target_ip $target_port 2>/dev/null; then
                            echo -e "${GREEN}IPv6 连接测试成功${NC}"
                        else
                            echo -e "${YELLOW}IPv6 连接测试失败（这可能正常，如果目标服务未运行）${NC}"
                        fi
                    else
                        echo -e "${YELLOW}未安装 nc (netcat)，跳过 IPv6 连接测试${NC}"
                    fi
                fi
                return
            fi
            ((count++))
        fi
    done < "$RULES_FILE"
    
    echo -e "${RED}无效的规则编号${NC}"
}

# 保存 iptables 规则到持久化存储
save_iptables_rules() {
    echo -e "${YELLOW}保存 iptables 规则到持久化存储...${NC}"
    
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

# 添加规则流程
add_rule_flow() {
    get_user_input_add
    
    # 根据 IP 版本处理
    if [[ $ip_version == "ipv4" || $ip_version == "both" ]]; then
        target_ipv4=$(resolve_target "$target_host" "ipv4")
        if [[ -n $target_ipv4 ]] && validate_ip "$target_ipv4" "ipv4"; then
            configure_iptables "$protocol" "$listen_port" "$target_ipv4" "$target_port" "ipv4"
            save_rule_to_file "$protocol" "$listen_port" "$target_ipv4" "$target_port" "ipv4"
        else
            echo -e "${RED}无法解析或无效的 IPv4 地址: $target_host${NC}"
        fi
    fi
    
    if [[ $ip_version == "ipv6" || $ip_version == "both" ]]; then
        target_ipv6=$(resolve_target "$target_host" "ipv6")
        if [[ -n $target_ipv6 ]] && validate_ip "$target_ipv6" "ipv6"; then
            configure_iptables "$protocol" "$listen_port" "$target_ipv6" "$target_port" "ipv6"
            save_rule_to_file "$protocol" "$listen_port" "$target_ipv6" "$target_port" "ipv6"
        else
            echo -e "${RED}无法解析或无效的 IPv6 地址: $target_host${NC}"
        fi
    fi
    
    save_iptables_rules
}

# 主菜单循环
main_menu() {
    while true; do
        show_menu
        read -p "请选择操作 (1-6): " choice
        
        case $choice in
            1)
                add_rule_flow
                ;;
            2)
                show_all_rules
                ;;
            3)
                delete_rule
                ;;
            4)
                test_connection
                ;;
            5)
                save_iptables_rules
                ;;
            6)
                echo -e "${GREEN}再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请输入 1-6${NC}"
                ;;
        esac
        
        echo
        read -p "按回车键继续..."
        clear
    done
}

# 主函数
main() {
    check_root
    init_rules_file
    
    echo -e "${GREEN}iptables 端口转发管理脚本${NC}"
    echo
    
    # 安装依赖
    install_dependencies
    
    # 启用 IP 转发
    enable_ip_forward
    
    # 显示主菜单
    main_menu
}

# 运行主函数
main "$@"
