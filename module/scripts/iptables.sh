#!/system/bin/sh
# ==============================================================================
# AdGuard Home for Android - 低功耗 DNS / DoT / SNI 防火墙编排脚本 (iptables.sh)
# 特性：
# 1. 与 service.sh / switch_mode.sh 共享内核级 flock 短期操作锁 (OP_LOCK_FILE, FD 9)
# 2. 挂载前严格验证 AdGuardHome 核心存活且 UDP + TCP DNS 端口均已监听，否则卸载防断网
# 3. 挂载后强制执行 post_apply_check 校验规则完整性，任何必需步骤失败均清理回退并返回非 0
# 4. 启用首包精准盘查 (connbytes 1:4) + --queue-bypass，并记录实际生效能力供巡检与诊断读取
# 5. IPv6 DNS 优先使用 nat REDIRECT，不支持时自动回退 filter REJECT/DROP 并记录实际模式
# ==============================================================================

trap '' HUP

SH_BIN="/system/bin/sh"
[ -x "$SH_BIN" ] || SH_BIN="/bin/sh"

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
MODDIR="${MODDIR:-/data/adb/modules/AdGuardHome}"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
MAIN_LOG="$AGH_DIR/agh.log"
PID_FILE="$BIN_DIR/AdGuardHome.pid"
AGH_GID=23333
PROC_DIR="${AGH_PROC_DIR:-/proc}"
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

BUSYBOX_BIN=""
for bb in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox /debug_ramdisk/.magisk/busybox/busybox /sbin/.magisk/busybox/busybox; do
    if [ -x "$bb" ]; then
        BUSYBOX_BIN="$bb"
        command -v awk >/dev/null 2>&1 || awk() { "$bb" awk "$@"; }
        command -v pidof >/dev/null 2>&1 || pidof() { "$bb" pidof "$@"; }
        command -v killall >/dev/null 2>&1 || killall() { "$bb" killall "$@"; }
        break
    fi
done

if [ -z "${RUN_DIR:-}" ]; then
    mkdir -p /dev/shm 2>/dev/null
    if ( : >> /dev/shm/.agh_probe ) 2>/dev/null; then
        rm -f /dev/shm/.agh_probe 2>/dev/null
        RUN_DIR="/dev/shm"
    else
        mkdir -p "$AGH_DIR/run" 2>/dev/null
        RUN_DIR="$AGH_DIR/run"
    fi
else
    mkdir -p "$RUN_DIR" 2>/dev/null
fi
OP_LOCK_FILE="$RUN_DIR/agh_op.flock"
OP_PID_FILE="$RUN_DIR/agh_op.pid"
SESSION_STOP_FILE="$RUN_DIR/agh_manual_stop"
IPV6_DNS_MODE_FILE="$RUN_DIR/agh_ipv6_dns_mode"
SNI_FW_MODE_FILE="$RUN_DIR/agh_sni_fw_mode"

load_runtime_config() {
    redir_port=55453
    ENABLE_SNI=1
    VPN_DNS_TAKEOVER=auto
    RUN_MODE=overseas
    [ -f "$SCRIPT_DIR/config.prop" ] && . "$SCRIPT_DIR/config.prop"
    redir_port=${redir_port:-55453}
    ENABLE_SNI=${ENABLE_SNI:-1}
    VPN_DNS_TAKEOVER=${VPN_DNS_TAKEOVER:-auto}
    RUN_MODE=${RUN_MODE:-overseas}
}
load_runtime_config

# ==============================================================================
# 内核级 flock 文件锁与受控子进程信号终止机制
# ==============================================================================
FLOCK_MODE=""
detect_flock_cmd() {
    [ -n "$FLOCK_MODE" ] && return 0
    if [ -n "$BUSYBOX_BIN" ] && "$BUSYBOX_BIN" flock --help >/dev/null 2>&1; then
        FLOCK_MODE="busybox"
        return 0
    fi
    if command -v flock >/dev/null 2>&1; then
        FLOCK_MODE="system"
        return 0
    fi
    if command -v toybox >/dev/null 2>&1 && toybox flock --help >/dev/null 2>&1; then
        FLOCK_MODE="toybox"
        return 0
    fi
    return 1
}

flock_nb() {
    fd_num="$1"
    detect_flock_cmd || return 1
    case "$FLOCK_MODE" in
        busybox) "$BUSYBOX_BIN" flock -n "$fd_num" >/dev/null 2>&1 ;;
        system)  flock -n "$fd_num" >/dev/null 2>&1 ;;
        toybox)  toybox flock -n "$fd_num" >/dev/null 2>&1 ;;
        *)       return 1 ;;
    esac
}

flock_unlock() {
    fd_num="$1"
    [ -n "$FLOCK_MODE" ] || return 0
    case "$FLOCK_MODE" in
        busybox) "$BUSYBOX_BIN" flock -u "$fd_num" >/dev/null 2>&1 ;;
        system)  flock -u "$fd_num" >/dev/null 2>&1 ;;
        toybox)  toybox flock -u "$fd_num" >/dev/null 2>&1 ;;
    esac
}

OP_LOCK_OWNED=0
OP_LOCK_INHERITED=0
ACTIVE_CHILD_PID=""

acquire_op_lock() {
    max_wait="${1:-15}"
    if [ "${AGH_OP_LOCK_EXEC_TRANSFER:-0}" = "1" ]; then
        OP_LOCK_OWNED=1
        OP_LOCK_INHERITED=0
        unset AGH_OP_LOCK_EXEC_TRANSFER
        export AGH_OP_LOCK_HELD=1
        echo "$$" > "$OP_PID_FILE" 2>/dev/null
        return 0
    fi
    if [ "${AGH_OP_LOCK_HELD:-0}" = "1" ]; then
        OP_LOCK_INHERITED=1
        return 0
    fi
    if ! detect_flock_cmd; then
        echo "$(date '+%F %T') [ERROR] iptables.sh: kernel flock utility not available, refusing unlocked execution." >> "$MAIN_LOG" 2>/dev/null
        return 1
    fi
    exec 9>>"$OP_LOCK_FILE" 2>/dev/null || return 1
    waited=0
    step_max=$((max_wait * 5))
    [ "$step_max" -lt 1 ] && step_max=1
    while [ "$waited" -lt "$step_max" ]; do
        if flock_nb 9; then
            echo "$$" > "$OP_PID_FILE" 2>/dev/null
            OP_LOCK_OWNED=1
            export AGH_OP_LOCK_HELD=1
            return 0
        fi
        if sleep 0.2 2>/dev/null; then
            waited=$((waited + 1))
        else
            sleep 1
            waited=$((waited + 5))
        fi
    done
    holder=$(cat "$OP_PID_FILE" 2>/dev/null)
    exec 9>&- 2>/dev/null
    echo "$(date '+%F %T') [WARN] iptables.sh: timed out waiting for operation lock after ${max_wait}s (last recorded holder PID ${holder:-unknown})" >> "$MAIN_LOG" 2>/dev/null
    return 1
}

release_op_lock() {
    if [ "$OP_LOCK_OWNED" = "1" ]; then
        if [ "$(cat "$OP_PID_FILE" 2>/dev/null)" = "$$" ]; then
            : > "$OP_PID_FILE" 2>/dev/null
        fi
        flock_unlock 9
        exec 9>&- 2>/dev/null
        OP_LOCK_OWNED=0
        unset AGH_OP_LOCK_HELD
    fi
}

terminate_active_child() {
    if [ -n "$ACTIVE_CHILD_PID" ]; then
        cpid="$ACTIVE_CHILD_PID"
        ACTIVE_CHILD_PID=""
        if kill -0 "$cpid" 2>/dev/null; then
            kill -TERM "$cpid" 2>/dev/null
            for _w in 1 2 3 4 5; do
                kill -0 "$cpid" 2>/dev/null || break
                sleep 0.1 2>/dev/null || sleep 1
            done
            kill -0 "$cpid" 2>/dev/null && kill -KILL "$cpid" 2>/dev/null
            wait "$cpid" 2>/dev/null
        fi
    fi
}

on_script_exit() {
    terminate_active_child
    release_op_lock
}

on_signal_abort() {
    sig_name="${1:-TERM}"
    trap - EXIT INT TERM
    echo "$(date '+%F %T') [WARN] iptables.sh (PID $$) received $sig_name, terminating active child and aborting." >> "$MAIN_LOG" 2>/dev/null
    terminate_active_child
    release_op_lock
    exit 130
}

# 检测 AdGuardHome 核心进程是否真实存活（校验 /proc/$pid/comm 及有效 GID 23333）
agh_running() {
    agh_pid=""
    if [ -f "$PID_FILE" ]; then
        agh_pid=$(cat "$PID_FILE" 2>/dev/null)
        case "$agh_pid" in
            ''|*[!0-9]*) agh_pid="" ;;
        esac
    fi
    if [ -n "$agh_pid" ] && kill -0 "$agh_pid" 2>/dev/null && \
       [ "$(cat "$PROC_DIR/$agh_pid/comm" 2>/dev/null)" = "AdGuardHome" ]; then
        if [ -r "$PROC_DIR/$agh_pid/status" ]; then
            grep -qE "^Gid:[[:space:]]*[0-9]+[[:space:]]+${AGH_GID}([[:space:]]|$)" "$PROC_DIR/$agh_pid/status" 2>/dev/null || return 1
        fi
        return 0
    fi
    rm -f "$PID_FILE" 2>/dev/null
    for p in $(pidof AdGuardHome 2>/dev/null); do
        if [ "$(cat "$PROC_DIR/$p/comm" 2>/dev/null)" = "AdGuardHome" ]; then
            if [ -r "$PROC_DIR/$p/status" ]; then
                grep -qE "^Gid:[[:space:]]*[0-9]+[[:space:]]+${AGH_GID}([[:space:]]|$)" "$PROC_DIR/$p/status" 2>/dev/null || continue
            fi
            echo "$p" > "$PID_FILE" 2>/dev/null
            return 0
        fi
    done
    return 1
}

udp_port_listening() {
    p_hex=$(printf '%04X' "$1" 2>/dev/null)
    [ -n "$p_hex" ] || return 1
    for f in "$PROC_DIR/net/udp" "$PROC_DIR/net/udp6"; do
        [ -r "$f" ] || continue
        if grep -qiE "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-Fa-f]+:${p_hex}[[:space:]]" "$f" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

tcp_port_listening() {
    p_hex=$(printf '%04X' "$1" 2>/dev/null)
    [ -n "$p_hex" ] || return 1
    for f in "$PROC_DIR/net/tcp" "$PROC_DIR/net/tcp6"; do
        [ -r "$f" ] || continue
        if grep -qiE "^[[:space:]]*[0-9]+:[[:space:]]+[0-9A-Fa-f]+:${p_hex}[[:space:]]+[0-9A-Fa-f]+:[0-9A-Fa-f]+[[:space:]]+0A[[:space:]]" "$f" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

agh_core_healthy() {
    agh_running && udp_port_listening "${1:-$redir_port}" && tcp_port_listening "${1:-$redir_port}"
}

# 清理旧版本及冲突规则 (彻底杜绝粗暴封禁443/853导致VPN无法连接的问题)
clean_legacy_conflicts() {
    while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j DROP 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p udp --dport 853 -j DROP 2>/dev/null; do :; done
    while iptables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
}

# 解析放行名单 (/data/adb/agh/app-allow.txt) 对应的 Android 应用 UID，实现内核层 0 延迟精准按应用分流
get_allowlist_uids() {
    [ -s "$AGH_DIR/app-allow.txt" ] && [ -r /data/system/packages.list ] || return 0
    awk '
        NR == FNR {
            sub(/\r$/, "")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if ($0 != "" && $0 !~ /^#/) allow[$0] = 1
            next
        }
        ($1 in allow) && $2 ~ /^[0-9]+$/ {
            if (!seen[$2]++) print $2
        }
    ' "$AGH_DIR/app-allow.txt" /data/system/packages.list 2>/dev/null
}

# 首包级低功耗 mangle 表 SNI 队列规则（仅查 TLS 握手前 4 包 + 强制 --queue-bypass + 严禁修改任何 sysctl 内核参数）
clean_sni_rules() {
    while iptables -w 2 -t mangle -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    iptables -w 2 -t mangle -F AGH_SNI 2>/dev/null
    iptables -w 2 -t mangle -X AGH_SNI 2>/dev/null
    while ip6tables -w 2 -t mangle -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    ip6tables -w 2 -t mangle -F AGH_SNI 2>/dev/null
    ip6tables -w 2 -t mangle -X AGH_SNI 2>/dev/null

    while iptables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    iptables -w 2 -t filter -F AGH_SNI 2>/dev/null
    iptables -w 2 -t filter -X AGH_SNI 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F AGH_SNI 2>/dev/null
    ip6tables -w 2 -t filter -X AGH_SNI 2>/dev/null
}

rebuild_sni() {
    allow_uids="${1:-}"
    clean_sni_rules
    if [ "$ENABLE_SNI" = "0" ]; then
        echo "disabled" > "$SNI_FW_MODE_FILE" 2>/dev/null
        return 0
    fi

    sni_queue=$(sed -n 's/^[[:space:]]*queue_num:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
        "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
    [ -z "$sni_queue" ] && sni_queue=0

    LAN_BYPASS_IPV4="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8"
    LAN_BYPASS_IPV6="::1/128 fc00::/7 fe80::/10 ff00::/8 ::ffff:127.0.0.0/104 ::ffff:10.0.0.0/104 ::ffff:172.16.0.0/108 ::ffff:192.168.0.0/112 ::ffff:169.254.0.0/112"

    # --- IPv4 mangle 表 AGH_SNI 链配置 ---
    iptables -w 2 -t mangle -N AGH_SNI 2>/dev/null
    iptables -w 2 -t mangle -F AGH_SNI 2>/dev/null || return 1
    iptables -w 2 -t mangle -A AGH_SNI -o lo -j RETURN || return 1
    iptables -w 2 -t mangle -A AGH_SNI -m owner --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        iptables -w 2 -t mangle -A AGH_SNI -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV4; do
        iptables -w 2 -t mangle -A AGH_SNI -d "$net" -j RETURN || return 1
    done
    v4_sni_mode="unsupported"
    for sni_port in 443 8443; do
        if iptables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
            -m connbytes --connbytes 1:4 --connbytes-dir original --connbytes-mode packets \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
            v4_sni_mode="connbytes"
        elif iptables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
            [ "$v4_sni_mode" != "connbytes" ] && v4_sni_mode="fallback"
        fi
    done
    if [ "$v4_sni_mode" != "unsupported" ]; then
        iptables -w 2 -t mangle -C OUTPUT -j AGH_SNI 2>/dev/null || \
            iptables -w 2 -t mangle -I OUTPUT 1 -j AGH_SNI || return 1
    fi
    echo "$v4_sni_mode" > "$SNI_FW_MODE_FILE" 2>/dev/null

    # --- IPv6 mangle 表 AGH_SNI 链配置 ---
    ip6tables -w 2 -t mangle -N AGH_SNI 2>/dev/null
    ip6tables -w 2 -t mangle -F AGH_SNI 2>/dev/null
    ip6tables -w 2 -t mangle -A AGH_SNI -o lo -j RETURN 2>/dev/null
    ip6tables -w 2 -t mangle -A AGH_SNI -m owner --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        ip6tables -w 2 -t mangle -A AGH_SNI -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV6; do
        ip6tables -w 2 -t mangle -A AGH_SNI -d "$net" -j RETURN 2>/dev/null
    done
    v6_has_nfq=0
    for sni_port in 443 8443; do
        if ip6tables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
            -m connbytes --connbytes 1:4 --connbytes-dir original --connbytes-mode packets \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
            v6_has_nfq=1
        elif ip6tables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
            v6_has_nfq=1
        fi
    done
    if [ "$v6_has_nfq" -eq 1 ]; then
        ip6tables -w 2 -t mangle -C OUTPUT -j AGH_SNI 2>/dev/null || \
            ip6tables -w 2 -t mangle -I OUTPUT 1 -j AGH_SNI 2>/dev/null
    fi
    return 0
}

# DoT / DoQ 加密 DNS 端口（853, 784, 8853）智能防绕过链
rebuild_dot_guard() {
    takeover_mode="${1:-0}"
    allow_uids="${2:-}"
    while iptables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    iptables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null

    LAN_BYPASS_IPV4="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 224.0.0.0/4 240.0.0.0/4 0.0.0.0/8"
    LAN_BYPASS_IPV6="::1/128 fc00::/7 fe80::/10 ff00::/8 ::ffff:127.0.0.0/104 ::ffff:10.0.0.0/104 ::ffff:172.16.0.0/108 ::ffff:192.168.0.0/112 ::ffff:169.254.0.0/112"

    iptables -w 2 -t filter -N ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null || return 1
    iptables -w 2 -t filter -A ADGUARD_DOT -o lo -j RETURN || return 1
    iptables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        iptables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV4; do
        iptables -w 2 -t filter -A ADGUARD_DOT -d "$net" -j RETURN || return 1
    done
    if [ "$takeover_mode" != "0" ]; then
        iptables -w 2 -t filter -A ADGUARD_DOT -o tun+ -j RETURN || return 1
        iptables -w 2 -t filter -A ADGUARD_DOT -o wg+ -j RETURN || return 1
        iptables -w 2 -t filter -A ADGUARD_DOT -o ppp+ -j RETURN || return 1
    fi
    if ! iptables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j REJECT --reject-with tcp-reset 2>/dev/null; then
        iptables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null || return 1
    fi
    if ! iptables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp-port-unreachable 2>/dev/null; then
        iptables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null || return 1
    fi
    iptables -w 2 -t filter -I OUTPUT 1 -j ADGUARD_DOT || return 1

    ip6tables -w 2 -t filter -N ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -o lo -j RETURN 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        ip6tables -w 2 -t filter -A ADGUARD_DOT -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV6; do
        ip6tables -w 2 -t filter -A ADGUARD_DOT -d "$net" -j RETURN 2>/dev/null
    done
    if [ "$takeover_mode" != "0" ]; then
        ip6tables -w 2 -t filter -A ADGUARD_DOT -o tun+ -j RETURN 2>/dev/null
        ip6tables -w 2 -t filter -A ADGUARD_DOT -o wg+ -j RETURN 2>/dev/null
        ip6tables -w 2 -t filter -A ADGUARD_DOT -o ppp+ -j RETURN 2>/dev/null
    fi
    ip6tables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j REJECT --reject-with tcp-reset 2>/dev/null || \
        ip6tables -w 2 -t filter -A ADGUARD_DOT -p tcp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null || \
        ip6tables -w 2 -t filter -A ADGUARD_DOT -p udp -m multiport --dports 853,784,8853 -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -I OUTPUT 1 -j ADGUARD_DOT 2>/dev/null
    return 0
}

# 智能零耗电本地判定 VPN DNS 接管模式
should_takeover_vpn_dns() {
    if [ "$VPN_DNS_TAKEOVER" = "1" ]; then
        echo "takeover" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    elif [ "$VPN_DNS_TAKEOVER" = "0" ]; then
        echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 1
    fi

    has_vpn=0
    for iface in /sys/class/net/tun* /sys/class/net/wg* /sys/class/net/ppp*; do
        if [ -d "$iface" ]; then
            has_vpn=1
            break
        fi
    done

    if [ "$has_vpn" = "0" ]; then
        echo "off" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    fi

    vpn_procs=$(ps -A -o ARGS 2>/dev/null || ps 2>/dev/null)
    if echo "$vpn_procs" | grep -qiE 'in\.malus|getmalus|transocks|shuttle|speedcn|quickfox|sixfast|golink|kanet|flycn|backcn|c2cvpn|haigui|guiyan|unblockcn'; then
        echo "takeover" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    fi

    op_country=$(getprop gsm.operator.iso-country 2>/dev/null | tr 'A-Z' 'a-z')
    op_mcc=$(getprop gsm.operator.numeric 2>/dev/null)
    in_mainland_cn=0
    [ "${RUN_MODE:-overseas}" = "cn" ] && in_mainland_cn=1
    case "$op_country" in
        *cn*) in_mainland_cn=1 ;;
    esac
    case "$op_mcc" in
        460*|*,460*) in_mainland_cn=1 ;;
    esac

    if [ "$in_mainland_cn" = "0" ]; then
        echo "takeover" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 0
    fi

    if ip -4 addr show 2>/dev/null | grep -qE '198\.18\.|172\.19\.' || \
       ip -4 route show table all 2>/dev/null | grep -qE '198\.18\.|172\.19\.' || \
       ip -6 addr show 2>/dev/null | grep -qiE 'fdfe:dcba:9876|fc00::' || \
       ip -6 route show table all 2>/dev/null | grep -qiE 'fdfe:dcba:9876|fc00::/18'; then
        echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 1
    fi
    if echo "$vpn_procs" | grep -qiE 'clash|mihomo|sing-box|singbox|v2ray|nekobox|nb4a|husi|karing|matsuri|sagernet|surfboard|shadowsocks|hiddify|xray|outline|psiphon|lantern|protonvpn|expressvpn|nordvpn|surfshark|mullvad|onedotonedotonedotone'; then
        echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
        return 1
    fi

    echo "bypass" > "$AGH_DIR/vpn_mode_status" 2>/dev/null
    return 1
}

# 应用高效 DNS 重定向规则（任何必需 IPv4 规则失败立即返回非 0）
apply_rules() {
    load_runtime_config
    allow_uids=$(get_allowlist_uids)
    should_takeover_vpn_dns
    takeover_vpn=$?

    # 建立 IPv4 DNS 重定向（先幂等移除所有旧跳转再插入唯一跳转）
    while iptables -w 2 -t nat -D OUTPUT -j ADGUARD 2>/dev/null; do :; done
    iptables -w 2 -t nat -N ADGUARD 2>/dev/null
    iptables -w 2 -t nat -F ADGUARD || return 1
    iptables -w 2 -t nat -I OUTPUT 1 -j ADGUARD || return 1
    iptables -w 2 -t nat -A ADGUARD -d 127.0.0.1/32 -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" || return 1
    iptables -w 2 -t nat -A ADGUARD -d 127.0.0.1/32 -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" || return 1
    iptables -w 2 -t nat -A ADGUARD -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        iptables -w 2 -t nat -A ADGUARD -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    if [ "$takeover_vpn" -ne 0 ]; then
        iptables -w 2 -t nat -A ADGUARD -d 198.18.0.0/15 -j RETURN 2>/dev/null || return 1
        iptables -w 2 -t nat -A ADGUARD -d 172.19.0.0/16 -j RETURN 2>/dev/null || return 1
        iptables -w 2 -t nat -A ADGUARD -o tun+ -p udp --dport 53 -j RETURN 2>/dev/null || return 1
        iptables -w 2 -t nat -A ADGUARD -o tun+ -p tcp --dport 53 -j RETURN 2>/dev/null || return 1
        iptables -w 2 -t nat -A ADGUARD -o wg+ -p udp --dport 53 -j RETURN 2>/dev/null || return 1
        iptables -w 2 -t nat -A ADGUARD -o wg+ -p tcp --dport 53 -j RETURN 2>/dev/null || return 1
        iptables -w 2 -t nat -A ADGUARD -o ppp+ -p udp --dport 53 -j RETURN 2>/dev/null || return 1
        iptables -w 2 -t nat -A ADGUARD -o ppp+ -p tcp --dport 53 -j RETURN 2>/dev/null || return 1
    fi
    iptables -w 2 -t nat -A ADGUARD -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" || return 1
    iptables -w 2 -t nat -A ADGUARD -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" || return 1

    # 建立 IPv6 DNS 接管链并记录实际生效模式 (nat / filter / none)
    ip6tables -w 2 -t nat -N ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -A ADGUARD6_NAT -d ::1/128 -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null
    ip6tables -w 2 -t nat -A ADGUARD6_NAT -d ::1/128 -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null
    ip6tables -w 2 -t nat -A ADGUARD6_NAT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
    for auid in $allow_uids; do
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    if [ "$takeover_vpn" -ne 0 ]; then
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -d fc00::/18 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -d fdfe:dcba:9876::/48 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o tun+ -p udp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o tun+ -p tcp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o wg+ -p udp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o wg+ -p tcp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o ppp+ -p udp --dport 53 -j RETURN 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -o ppp+ -p tcp --dport 53 -j RETURN 2>/dev/null
    fi
    if ip6tables -w 2 -t nat -A ADGUARD6_NAT -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null && \
       ip6tables -w 2 -t nat -A ADGUARD6_NAT -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; then
        while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
        ip6tables -w 2 -t nat -I OUTPUT 1 -j ADGUARD6_NAT 2>/dev/null
        while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
        ip6tables -w 2 -F ADGUARD6 2>/dev/null
        ip6tables -w 2 -X ADGUARD6 2>/dev/null
        echo "nat" > "$IPV6_DNS_MODE_FILE" 2>/dev/null
    else
        while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
        ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
        ip6tables -w 2 -t nat -X ADGUARD6_NAT 2>/dev/null
        while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
        if ip6tables -w 2 -N ADGUARD6 2>/dev/null || ip6tables -w 2 -F ADGUARD6 2>/dev/null; then
            ip6tables -w 2 -F ADGUARD6 2>/dev/null
            ip6tables -w 2 -I OUTPUT 1 -j ADGUARD6 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -d ::1/128 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -d ::1/128 -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null
            ip6tables -w 2 -A ADGUARD6 -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null
            for auid in $allow_uids; do
                ip6tables -w 2 -A ADGUARD6 -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
            done
            if [ "$takeover_vpn" -ne 0 ]; then
                ip6tables -w 2 -A ADGUARD6 -d fc00::/18 -j RETURN 2>/dev/null
                ip6tables -w 2 -A ADGUARD6 -d fdfe:dcba:9876::/48 -j RETURN 2>/dev/null
                ip6tables -w 2 -A ADGUARD6 -o tun+ -p udp --dport 53 -j RETURN 2>/dev/null
                ip6tables -w 2 -A ADGUARD6 -o tun+ -p tcp --dport 53 -j RETURN 2>/dev/null
                ip6tables -w 2 -A ADGUARD6 -o wg+ -p udp --dport 53 -j RETURN 2>/dev/null
                ip6tables -w 2 -A ADGUARD6 -o wg+ -p tcp --dport 53 -j RETURN 2>/dev/null
                ip6tables -w 2 -A ADGUARD6 -o ppp+ -p udp --dport 53 -j RETURN 2>/dev/null
                ip6tables -w 2 -A ADGUARD6 -o ppp+ -p tcp --dport 53 -j RETURN 2>/dev/null
            fi
            if ! ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable 2>/dev/null; then
                ip6tables -w 2 -A ADGUARD6 -p udp --dport 53 -j DROP 2>/dev/null
            fi
            if ! ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j REJECT --reject-with tcp-reset 2>/dev/null; then
                ip6tables -w 2 -A ADGUARD6 -p tcp --dport 53 -j DROP 2>/dev/null
            fi
            echo "filter" > "$IPV6_DNS_MODE_FILE" 2>/dev/null
        else
            echo "none" > "$IPV6_DNS_MODE_FILE" 2>/dev/null
        fi
    fi

    # 保护本地 DNS 端口免受公共 Wi-Fi 局域网其他设备探测或滥用
    while iptables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    iptables -w 2 -t filter -N AGH_INPUT 2>/dev/null
    iptables -w 2 -t filter -F AGH_INPUT 2>/dev/null || return 1
    iptables -w 2 -t filter -A AGH_INPUT -i lo -j RETURN 2>/dev/null || return 1
    iptables -w 2 -t filter -A AGH_INPUT -p udp --dport "$redir_port" -j DROP 2>/dev/null || return 1
    iptables -w 2 -t filter -A AGH_INPUT -p tcp --dport "$redir_port" -j DROP 2>/dev/null || return 1
    iptables -w 2 -t filter -I INPUT 1 -j AGH_INPUT 2>/dev/null || return 1
    while ip6tables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -N AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -i lo -j RETURN 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -p udp --dport "$redir_port" -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -A AGH_INPUT -p tcp --dport "$redir_port" -j DROP 2>/dev/null
    ip6tables -w 2 -t filter -I INPUT 1 -j AGH_INPUT 2>/dev/null

    rebuild_dot_guard "$takeover_vpn" "$allow_uids" || return 1
    rebuild_sni "$allow_uids" || return 1
    return 0
}

# 挂载后完整性校验（与 service.sh nat_rules_healthy 完全一致）
post_apply_check() {
    port_chk="${1:-$redir_port}"
    out_jumps=$(iptables -w 2 -t nat -S OUTPUT 2>/dev/null | grep -c -- '-j ADGUARD$')
    [ "$out_jumps" -eq 1 ] || return 1

    chain_rules=$(iptables -w 2 -t nat -S ADGUARD 2>/dev/null)
    [ -n "$chain_rules" ] || return 1
    echo "$chain_rules" | grep -qE -- "-d 127\.0\.0\.1(/32)? .*-p udp .*--dport 53 .*-j REDIRECT --to-ports $port_chk" || return 1
    echo "$chain_rules" | grep -qE -- "-d 127\.0\.0\.1(/32)? .*-p tcp .*--dport 53 .*-j REDIRECT --to-ports $port_chk" || return 1
    echo "$chain_rules" | grep -qE -- "^-A ADGUARD -p udp .*--dport 53 .*-j REDIRECT --to-ports $port_chk" || return 1
    echo "$chain_rules" | grep -qE -- "^-A ADGUARD -p tcp .*--dport 53 .*-j REDIRECT --to-ports $port_chk" || return 1

    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 || return 1
    iptables -w 2 -t filter -C INPUT -j AGH_INPUT >/dev/null 2>&1 || return 1

    v6_mode=$(cat "$IPV6_DNS_MODE_FILE" 2>/dev/null)
    case "$v6_mode" in
        nat)
            ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT >/dev/null 2>&1 || return 1
            ;;
        filter)
            ip6tables -w 2 -C OUTPUT -j ADGUARD6 >/dev/null 2>&1 || return 1
            ;;
        none)
            ;;
        *)
            if ip6tables -w 2 -t nat -L OUTPUT >/dev/null 2>&1; then
                ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT >/dev/null 2>&1 || \
                    ip6tables -w 2 -C OUTPUT -j ADGUARD6 >/dev/null 2>&1 || return 1
            fi
            ;;
    esac

    if [ "${ENABLE_SNI:-1}" != "0" ]; then
        sni_mode=$(cat "$SNI_FW_MODE_FILE" 2>/dev/null)
        if [ "$sni_mode" != "unsupported" ]; then
            iptables -w 2 -t mangle -C OUTPUT -j AGH_SNI >/dev/null 2>&1 || return 1
            iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null | grep -q -- '-j NFQUEUE' || return 1
        fi
    fi
    return 0
}

# 彻底清理可能残留的热点策略路由与转发规则
clean_hotspot_rules() {
    ip rule del pref 99 2>/dev/null
    ip rule del pref 100 2>/dev/null
    ip rule del pref 101 2>/dev/null
    ip route flush table 61 2>/dev/null
    while iptables -w 2 -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; do :; done
    while iptables -w 2 -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; do :; done
}

# 彻底清理所有 DNS / DoT / SNI 接管规则并校验是否残留跳转
clean_all_rules() {
    while iptables -w 2 -t nat -D OUTPUT -j ADGUARD 2>/dev/null; do :; done
    iptables -w 2 -t nat -F ADGUARD 2>/dev/null
    iptables -w 2 -t nat -X ADGUARD 2>/dev/null
    while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
    ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
    ip6tables -w 2 -t nat -X ADGUARD6_NAT 2>/dev/null
    while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
    ip6tables -w 2 -F ADGUARD6 2>/dev/null
    ip6tables -w 2 -X ADGUARD6 2>/dev/null
    while iptables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    iptables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    iptables -w 2 -t filter -X AGH_INPUT 2>/dev/null
    while ip6tables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F AGH_INPUT 2>/dev/null
    ip6tables -w 2 -t filter -X AGH_INPUT 2>/dev/null
    while iptables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    iptables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    iptables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
    while ip6tables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
    ip6tables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
    ip6tables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
    clean_sni_rules
    clean_hotspot_rules
    rm -f "$AGH_DIR/app_pause_active" "$AGH_DIR/vpn_mode_status" "$IPV6_DNS_MODE_FILE" "$SNI_FW_MODE_FILE" 2>/dev/null

    cleanup_err=0
    iptables -w 2 -t nat -C OUTPUT -j ADGUARD >/dev/null 2>&1 && cleanup_err=1
    ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT >/dev/null 2>&1 && cleanup_err=1
    ip6tables -w 2 -C OUTPUT -j ADGUARD6 >/dev/null 2>&1 && cleanup_err=1
    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 && cleanup_err=1
    iptables -w 2 -t mangle -C OUTPUT -j AGH_SNI >/dev/null 2>&1 && cleanup_err=1
    if [ "$cleanup_err" -ne 0 ]; then
        echo "$(date '+%F %T') [CRITICAL] iptables.sh: 卸载防火墙规则失败，OUTPUT 链仍残留接管跳转！" >> "$MAIN_LOG" 2>/dev/null
        return 1
    fi
    return 0
}

# 刷新系统 DNS 缓存，仅在至少一条刷新命令返回 0 时返回成功
refresh_network() {
    flushed=0
    if command -v ndc >/dev/null 2>&1; then
        ndc resolver flushenv >/dev/null 2>&1 && flushed=1
        ndc resolver flushdefaultif >/dev/null 2>&1 && flushed=1
    fi
    if command -v cmd >/dev/null 2>&1; then
        cmd netd resolver flushdefaultif >/dev/null 2>&1 && flushed=1
    fi
    [ "$flushed" -eq 1 ] && return 0
    return 1
}

# 挂载前健康预检 (Pre-flight Check：确认核心存活且 UDP+TCP 端口真实监听，否则立即卸载防断网)
preflight_check() {
    load_runtime_config
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if agh_core_healthy "$redir_port"; then
            agh_real_pid=$(pidof AdGuardHome 2>/dev/null | awk '{print $1}')
            [ -n "$agh_real_pid" ] && echo "$agh_real_pid" > "$PID_FILE" 2>/dev/null
            echo "$(date '+%F %T') [PRE-FLIGHT] 本地 DNS 端口 ($redir_port UDP+TCP) 就绪，执行规则接管。" >> "$MAIN_LOG" 2>/dev/null
            return 0
        fi
        sleep 0.2 2>/dev/null || sleep 1
    done
    clean_all_rules
    echo "$(date '+%F %T') [WARNING] AdGuardHome 未存活或端口 ($redir_port) 未完整监听，已触发防断网安全阀卸载 NAT 规则！" >> "$MAIN_LOG" 2>/dev/null
    return 1
}

trap 'on_script_exit' EXIT
trap 'on_signal_abort INT' INT
trap 'on_signal_abort TERM' TERM

case "${1:-}" in
    clean|--clean)
        if ! acquire_op_lock 15; then
            echo "$(date '+%F %T') [ERROR] iptables.sh --clean: 获取操作锁超时，放弃无锁清理。" >> "$MAIN_LOG" 2>/dev/null
            exit 1
        fi
        clean_legacy_conflicts
        clean_all_rules || exit 1
        exit 0
        ;;
    disable|stop|--disable|--stop)
        : > "$SESSION_STOP_FILE" 2>/dev/null
        if ! acquire_op_lock 15; then
            echo "$(date '+%F %T') [WARN] iptables.sh --stop: 停止请求已记录，当前操作尚未结束（等待操作锁超时）。" >> "$MAIN_LOG" 2>/dev/null
            echo "停止请求已记录，当前操作尚未结束"
            echo "AGH_REPAIR_RESULT status=pending stage=stop_lock_busy branch=iptables_stop dns_flushed=0"
            exit 1
        fi
        : > "$SESSION_STOP_FILE" 2>/dev/null
        clean_legacy_conflicts
        cleanup_ok=0
        clean_all_rules && cleanup_ok=1
        if pidof AdGuardHome >/dev/null 2>&1; then
            killall -15 AdGuardHome 2>/dev/null
            sleep 1
            pidof AdGuardHome >/dev/null 2>&1 && killall -9 AdGuardHome 2>/dev/null
        fi
        rm -f "$PID_FILE" 2>/dev/null
        dns_flushed=0
        refresh_network && dns_flushed=1
        if [ "$cleanup_ok" -ne 1 ]; then
            echo "AGH_REPAIR_RESULT status=error stage=stop_cleanup_failed branch=iptables_stop dns_flushed=$dns_flushed"
            exit 1
        fi
        echo "AGH_REPAIR_RESULT status=ok stage=stopped branch=iptables_stop dns_flushed=$dns_flushed"
        exit 0
        ;;
    --reload|--apply-allowlist)
        if ! acquire_op_lock 15; then
            echo "AGH_REPAIR_RESULT status=error stage=lock_timeout branch=iptables_reload dns_flushed=0"
            exit 1
        fi
        rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
              "$SESSION_STOP_FILE" "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
        load_runtime_config
        if agh_core_healthy "$redir_port"; then
            clean_legacy_conflicts
            clean_hotspot_rules
            if apply_rules && post_apply_check "$redir_port"; then
                dns_flushed=0
                refresh_network && dns_flushed=1
                echo "AGH_REPAIR_RESULT status=ok stage=completed branch=iptables_reload dns_flushed=$dns_flushed"
                exit 0
            fi
            echo "$(date '+%F %T') [ERROR] iptables.sh --reload: 规则挂载或挂载后校验失败，执行安全清理！" >> "$MAIN_LOG" 2>/dev/null
            clean_all_rules
            echo "AGH_REPAIR_RESULT status=error stage=firewall_apply_failed branch=iptables_reload dns_flushed=0"
            exit 1
        fi
        clean_all_rules
        echo "AGH_REPAIR_RESULT status=error stage=core_unhealthy branch=iptables_reload dns_flushed=0"
        exit 1
        ;;
    enable|--enable)
        if ! acquire_op_lock 15; then
            echo "AGH_REPAIR_RESULT status=error stage=lock_timeout branch=iptables_enable dns_flushed=0"
            exit 1
        fi
        clean_legacy_conflicts
        clean_hotspot_rules
        if preflight_check; then
            if apply_rules && post_apply_check "$redir_port"; then
                dns_flushed=0
                refresh_network && dns_flushed=1
                echo "AGH_REPAIR_RESULT status=ok stage=completed branch=iptables_enable dns_flushed=$dns_flushed"
                exit 0
            fi
            echo "$(date '+%F %T') [ERROR] iptables.sh --enable: 规则挂载或挂载后校验失败，执行安全清理！" >> "$MAIN_LOG" 2>/dev/null
        fi
        clean_all_rules
        echo "AGH_REPAIR_RESULT status=error stage=firewall_apply_failed branch=iptables_enable dns_flushed=0"
        exit 1
        ;;
    *)
        rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
              "$SESSION_STOP_FILE" "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
        if [ -f "$MODDIR/service.sh" ]; then
            if [ "$OP_LOCK_OWNED" = "1" ]; then
                export AGH_OP_LOCK_EXEC_TRANSFER=1
                OP_LOCK_OWNED=0
            fi
            trap - EXIT INT TERM
            exec "$SH_BIN" "$MODDIR/service.sh" --repair
        fi
        if acquire_op_lock 10; then
            clean_all_rules
        fi
        echo "AGH_REPAIR_RESULT status=error stage=service_missing branch=iptables_default dns_flushed=0"
        exit 1
        ;;
esac
