#!/system/bin/sh
# ==============================================================================
# AdGuard Home GoGoGo - 统一核心控制与软重启自愈守护引擎 (service.sh)
# 特性：
# 1. 基于内核 flock 的双层锁架构：长期守护实例锁 (FD 8) 与短期生命周期操作锁 (FD 9)，锁文件 inode 恒定，PID 文件仅作诊断
# 2. 严格区分正常退出清理与 INT/TERM 信号终止处理：先终止并 wait 回收活跃子进程，再释放自身持有的锁
# 3. 后台长寿命进程 (AdGuardHome / --watchdog / 辅助异步任务) 显式关闭 FD 8 与 FD 9，杜绝锁描述符泄露
# 4. 软重启无损复用健康核心（保留缓存与内存统计）；修复/重启显式验证「核心就绪 + 规则挂载 + 挂载后自检」并真实上报结果
# ==============================================================================

trap '' HUP

ADGPATH="${ADGPATH:-/data/adb/modules/AdGuardHome}"
case "$0" in
    /*) MODDIR="${0%/*}" ;;
    *)  MODDIR="$ADGPATH" ;;
esac
[ -d "$MODDIR" ] || MODDIR="$ADGPATH"
SELF_SCRIPT="$MODDIR/service.sh"
[ -f "$SELF_SCRIPT" ] || SELF_SCRIPT="$0"

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
MAIN_LOG="$AGH_DIR/agh.log"
PID_FILE="$BIN_DIR/AdGuardHome.pid"
CA_BUNDLE="$BIN_DIR/cacerts.pem"
BAK_YAML="$BIN_DIR/AdGuardHome.yaml.bak"
MODULES_DIR="${MODULES_DIR:-/data/adb/modules}"
AGH_GID=23333
PROC_DIR="${AGH_PROC_DIR:-/proc}"
export PATH="/data/adb/ksu/bin:/data/adb/ap/bin:/data/adb/magisk:$PATH"

SH_BIN="${SH_BIN:-/system/bin/sh}"
[ -x "$SH_BIN" ] || SH_BIN="/bin/sh"

# 探测 Magisk / KernelSU / APatch 内置完整 BusyBox
find_busybox() {
    if [ -n "${BB_BIN_OVERRIDE:-}" ] && [ -x "$BB_BIN_OVERRIDE" ]; then
        echo "$BB_BIN_OVERRIDE"
        return 0
    fi
    for bb in \
        /data/adb/ksu/bin/busybox \
        /data/adb/ap/bin/busybox \
        /data/adb/magisk/busybox \
        /debug_ramdisk/.magisk/busybox/busybox \
        /sbin/.magisk/busybox/busybox; do
        [ -x "$bb" ] && { echo "$bb"; return 0; }
    done
    command -v busybox 2>/dev/null && return 0
    return 1
}
BB_BIN="$(find_busybox)"
if [ -n "$BB_BIN" ]; then
    command -v awk >/dev/null 2>&1 || awk() { "$BB_BIN" awk "$@"; }
    command -v pidof >/dev/null 2>&1 || pidof() { "$BB_BIN" pidof "$@"; }
    command -v killall >/dev/null 2>&1 || killall() { "$BB_BIN" killall "$@"; }
fi

# 兼容第三方魔改 ROM 的安全休眠封装
safe_sleep() {
    if sleep "$1" >/dev/null 2>&1; then
        return 0
    elif [ -n "$BB_BIN" ] && "$BB_BIN" sleep "$1" >/dev/null 2>&1; then
        return 0
    elif [ -x /system/bin/toybox ] && /system/bin/toybox sleep "$1" >/dev/null 2>&1; then
        return 0
    elif [ -x /system/bin/toolbox ] && /system/bin/toolbox sleep "$1" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 初始化运行状态与锁目录（支持 RUN_DIR 覆盖以便隔离测试）
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

WATCHDOG_LOCK_FILE="$RUN_DIR/agh_watchdog.flock"
WATCHDOG_PID_FILE="$RUN_DIR/agh_watchdog.pid"
OP_LOCK_FILE="$RUN_DIR/agh_op.flock"
OP_LOCK_DIAG_PID_FILE="$RUN_DIR/agh_op.pid"
SESSION_STOP_FILE="$RUN_DIR/agh_manual_stop"
IPV6_DNS_MODE_FILE="$RUN_DIR/agh_ipv6_dns_mode"
SNI_FW_MODE_FILE="$RUN_DIR/agh_sni_fw_mode"

# 系统语言检测
locale=$(getprop persist.sys.locale 2>/dev/null)
[ -z "$locale" ] && locale="zh"
case "$locale" in zh*) lang=zh ;; *) lang=en ;; esac

log_msg() {
    echo "$(date '+%F %T') $1" >> "$MAIN_LOG" 2>/dev/null
    if [ -f "$MAIN_LOG" ] && [ "$(wc -c < "$MAIN_LOG" 2>/dev/null || echo 0)" -ge 102400 ]; then
        : > "$MAIN_LOG" 2>/dev/null
    fi
}

# ==============================================================================
# 内核 flock 能力探测与自检（严禁退化为有竞态的 mkdir + rm -rf 目录锁）
# ==============================================================================
FLOCK_CMD_TYPE=""
resolve_flock_cmd() {
    [ -n "$FLOCK_CMD_TYPE" ] && return 0
    if [ -n "${FLOCK_BIN:-}" ] && [ -x "$FLOCK_BIN" ]; then
        FLOCK_CMD_TYPE="custom"
        return 0
    fi
    if command -v flock >/dev/null 2>&1; then
        FLOCK_CMD_TYPE="direct"
        return 0
    fi
    if [ -n "$BB_BIN" ] && "$BB_BIN" flock --help >/dev/null 2>&1; then
        FLOCK_CMD_TYPE="busybox"
        return 0
    fi
    if [ -x /system/bin/toybox ] && /system/bin/toybox flock --help >/dev/null 2>&1; then
        FLOCK_CMD_TYPE="toybox"
        return 0
    fi
    return 1
}

run_flock() {
    resolve_flock_cmd || return 1
    case "$FLOCK_CMD_TYPE" in
        custom)  "$FLOCK_BIN" "$@" ;;
        direct)  flock "$@" ;;
        busybox) "$BB_BIN" flock "$@" ;;
        toybox)  /system/bin/toybox flock "$@" ;;
        *)       return 1 ;;
    esac
}

FLOCK_VERIFIED=0
verify_flock_support() {
    [ "$FLOCK_VERIFIED" = "1" ] && return 0
    resolve_flock_cmd || {
        log_msg "[FATAL] 未找到可用 flock 工具，拒绝无锁执行修改操作"
        return 1
    }
    probe_f="$RUN_DIR/.agh_flock_verify.$$"
    if ! (
        exec 7>>"$probe_f" 2>/dev/null || exit 1
        run_flock -n 7 || exit 1
        # 验证另一独立打开的描述符无法再次获取排他锁
        if ( exec 7>>"$probe_f" 2>/dev/null && run_flock -n 7 ); then
            exit 1
        fi
        exit 0
    ); then
        rm -f "$probe_f" 2>/dev/null
        log_msg "[FATAL] 当前环境 flock 排他语义自检未通过，拒绝无锁继续"
        return 1
    fi
    rm -f "$probe_f" 2>/dev/null
    FLOCK_VERIFIED=1
    return 0
}

# ==============================================================================
# 信号处理与受控子进程回收（严格区分 EXIT 与 INT/TERM）
# ==============================================================================
WATCHDOG_LOCK_OWNED=0
OP_LOCK_OWNED=0
ABORTED_BY_SIGNAL=0
CLEANUP_DONE=0
ACTIVE_CHILD_PID=""

# 运行可能修改共享状态的同步子命令：支持信号中断时先终止并 wait 回收子进程，再释放操作锁
run_sync_child() {
    [ "$ABORTED_BY_SIGNAL" = "1" ] && return 143
    "$@" 8>&- &
    ACTIVE_CHILD_PID=$!
    wait "$ACTIVE_CHILD_PID" 2>/dev/null
    child_rc=$?
    ACTIVE_CHILD_PID=""
    if [ "$ABORTED_BY_SIGNAL" = "1" ]; then
        exit 143
    fi
    return "$child_rc"
}

terminate_active_child() {
    if [ -n "$ACTIVE_CHILD_PID" ]; then
        target_child="$ACTIVE_CHILD_PID"
        if kill -0 "$target_child" 2>/dev/null; then
            kill -15 "$target_child" 2>/dev/null || true
            c_wait=0
            while [ "$c_wait" -lt 20 ] && kill -0 "$target_child" 2>/dev/null; do
                safe_sleep 0.1 || sleep 1
                c_wait=$((c_wait + 1))
            done
            if kill -0 "$target_child" 2>/dev/null; then
                kill -9 "$target_child" 2>/dev/null || true
            fi
        fi
        wait "$target_child" 2>/dev/null || true
        ACTIVE_CHILD_PID=""
    fi
}

# ==============================================================================
# 锁机制 1：长期守护实例内核锁 (FD 8 -> WATCHDOG_LOCK_FILE)
# 锁文件 inode 恒定不删除；进程退出后由内核自动释放 FD 8；PID 文件仅作诊断
# ==============================================================================
watchdog_alive() {
    [ "$WATCHDOG_LOCK_OWNED" = "1" ] && return 0
    verify_flock_support || return 1
    (
        exec 8>>"$WATCHDOG_LOCK_FILE" 2>/dev/null || exit 1
        if run_flock -n 8; then
            exit 1
        fi
        exit 0
    )
}

acquire_watchdog_lock() {
    [ "$WATCHDOG_LOCK_OWNED" = "1" ] && return 0
    verify_flock_support || return 1
    exec 8>>"$WATCHDOG_LOCK_FILE" 2>/dev/null || return 1
    if ! run_flock -n 8; then
        exec 8>&- 2>/dev/null || true
        return 1
    fi
    WATCHDOG_LOCK_OWNED=1
    printf '%s\n' "$$" > "$WATCHDOG_PID_FILE" 2>/dev/null
    return 0
}

release_watchdog_lock() {
    if [ "$WATCHDOG_LOCK_OWNED" = "1" ]; then
        if [ "$(cat "$WATCHDOG_PID_FILE" 2>/dev/null)" = "$$" ]; then
            rm -f "$WATCHDOG_PID_FILE" 2>/dev/null
        fi
        run_flock -u 8 2>/dev/null || true
        exec 8>&- 2>/dev/null || true
        WATCHDOG_LOCK_OWNED=0
    fi
}

# ==============================================================================
# 锁机制 2：短期生命周期操作内核锁 (FD 9 -> OP_LOCK_FILE)
# 支持已持锁父进程同步调用继承 (AGH_OP_LOCK_HELD=1) 与 exec 权属移交 (AGH_OP_LOCK_EXEC_TRANSFER=1)
# ==============================================================================
has_op_lock_context() {
    [ "$OP_LOCK_OWNED" = "1" ] && return 0
    if [ "${AGH_OP_LOCK_HELD:-0}" = "1" ] && { true >&9; } 2>/dev/null; then
        return 0
    fi
    return 1
}

acquire_op_lock() {
    max_wait="${1:-15}"
    [ "$ABORTED_BY_SIGNAL" = "1" ] && return 1
    if [ "$OP_LOCK_OWNED" = "1" ]; then
        return 0
    fi
    # exec 转交模式：接收父进程在 FD 9 上已持有的内核锁所有权
    if [ "${AGH_OP_LOCK_EXEC_TRANSFER:-0}" = "1" ] && { true >&9; } 2>/dev/null; then
        OP_LOCK_OWNED=1
        unset AGH_OP_LOCK_EXEC_TRANSFER
        export AGH_OP_LOCK_HELD=1
        printf '%s\n' "$$" > "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null
        return 0
    fi
    # 同步子进程共享锁模式：父进程已持有 FD 9，子进程在父进程锁保护下运行且退出时不释放父进程锁
    if [ "${AGH_OP_LOCK_HELD:-0}" = "1" ] && { true >&9; } 2>/dev/null; then
        OP_LOCK_OWNED=0
        return 0
    fi

    verify_flock_support || return 1
    exec 9>>"$OP_LOCK_FILE" 2>/dev/null || return 1

    waited=0
    step_max=$((max_wait * 5))
    [ "$step_max" -lt 1 ] && step_max=1
    while [ "$waited" -lt "$step_max" ]; do
        if [ "$ABORTED_BY_SIGNAL" = "1" ]; then
            exec 9>&- 2>/dev/null || true
            return 1
        fi
        if run_flock -n 9; then
            OP_LOCK_OWNED=1
            export AGH_OP_LOCK_HELD=1
            printf '%s\n' "$$" > "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null
            return 0
        fi
        if safe_sleep 0.2; then
            waited=$((waited + 1))
        else
            sleep 1
            waited=$((waited + 5))
        fi
    done

    holder_diag=$(cat "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null)
    exec 9>&- 2>/dev/null || true
    log_msg "[WARN] 等待操作锁超时 (${max_wait}s, 当前诊断持有者 PID=${holder_diag:-unknown})"
    return 1
}

release_op_lock() {
    if [ "$OP_LOCK_OWNED" = "1" ]; then
        if [ "$(cat "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null)" = "$$" ]; then
            rm -f "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null
        fi
        run_flock -u 9 2>/dev/null || true
        exec 9>&- 2>/dev/null || true
        OP_LOCK_OWNED=0
        unset AGH_OP_LOCK_HELD
    fi
}

cleanup_owned_resources() {
    [ "$CLEANUP_DONE" = "1" ] && return 0
    CLEANUP_DONE=1
    terminate_active_child
    release_op_lock
    release_watchdog_lock
}

on_signal_abort() {
    ABORTED_BY_SIGNAL=1
    cleanup_owned_resources
    trap - EXIT INT TERM
    exit 143
}

trap 'cleanup_owned_resources' EXIT
trap 'on_signal_abort INT' INT
trap 'on_signal_abort TERM' TERM

# 单次合并读取运行期配置，避免一轮巡检中反复解析 config.prop
load_runtime_config() {
    redir_port=55453
    ENABLE_SNI=1
    VPN_DNS_TAKEOVER=auto
    RUN_MODE=overseas
    PROXY_URL=""
    STOPPED=0
    MANUAL_STOP=0
    if [ -f "$SCRIPT_DIR/config.prop" ]; then
        . "$SCRIPT_DIR/config.prop"
    fi
    redir_port=${redir_port:-55453}
    ENABLE_SNI=${ENABLE_SNI:-1}
    VPN_DNS_TAKEOVER=${VPN_DNS_TAKEOVER:-auto}
    RUN_MODE=${RUN_MODE:-overseas}
    case "$RUN_MODE" in
        cn|CN) active_mode="cn" ;;
        *)     active_mode="overseas" ;;
    esac
    PROXY_URL_CLEAN=""
    if [ -n "$PROXY_URL" ]; then
        old_ifs="$IFS"
        IFS=" \"'	
"
        for tok in $PROXY_URL; do
            PROXY_URL_CLEAN="${PROXY_URL_CLEAN}${tok}"
        done
        IFS="$old_ifs"
    fi
}

# 系统「私人 DNS (Private DNS / DoT 853)」状态备份、自动关闭防逃逸与无损恢复闭环
PRIV_DNS_BAK="$AGH_DIR/private_dns.bak"
ensure_private_dns_off() {
    cur_mode=$(settings get global private_dns_mode 2>/dev/null)
    case "$cur_mode" in
        ''|null|off) return 0 ;;
    esac
    if [ ! -f "$PRIV_DNS_BAK" ]; then
        cur_spec=$(settings get global private_dns_specifier 2>/dev/null)
        printf 'mode=%s\nspec=%s\n' "$cur_mode" "$cur_spec" > "$PRIV_DNS_BAK" 2>/dev/null
    fi
    settings put global private_dns_mode off >/dev/null 2>&1
}

restore_private_dns() {
    [ -f "$PRIV_DNS_BAK" ] || return 0
    bak_mode=$(sed -n 's/^mode=//p' "$PRIV_DNS_BAK" 2>/dev/null | head -n 1)
    bak_spec=$(sed -n 's/^spec=//p' "$PRIV_DNS_BAK" 2>/dev/null | head -n 1)
    if [ -n "$bak_mode" ] && [ "$bak_mode" != "null" ]; then
        settings put global private_dns_mode "$bak_mode" >/dev/null 2>&1
    fi
    if [ -n "$bak_spec" ] && [ "$bak_spec" != "null" ]; then
        settings put global private_dns_specifier "$bak_spec" >/dev/null 2>&1
    fi
    rm -f "$PRIV_DNS_BAK" 2>/dev/null
}

# 清理因文件锁导致的 App 卸载残留目录 (*==deleted==)，与高频关键健康检查解耦
clean_deleted_app_dirs() {
    for d in /data/data/*==deleted== /data/user/0/*==deleted== /data/user/*/*==deleted==; do
        if [ -d "$d" ]; then
            chattr -R -i "$d" 2>/dev/null
            rm -rf "$d" 2>/dev/null
        fi
    done
}

# 脱离 Manager App su -c 派生的应用级 cgroup (uid_10xxx) 与 Freezer 冻结组，迁入根 cgroup
escape_app_cgroup() {
    target_pid="${1:-$$}"
    for cg in \
        /sys/fs/cgroup/cgroup.procs \
        /sys/fs/cgroup/freezer/cgroup.procs \
        /dev/freezer/cgroup.procs \
        /dev/cpuset/cgroup.procs \
        /dev/cpuset/tasks \
        /dev/cpuctl/cgroup.procs \
        /dev/cpuctl/tasks \
        /dev/stune/cgroup.procs \
        /dev/stune/tasks \
        /acct/cgroup.procs \
        /acct/tasks; do
        [ -w "$cg" ] && echo "$target_pid" > "$cg" 2>/dev/null
    done
}
escape_app_cgroup "$$"

# 主动清理所有手动停止锁标记（仅在已持有操作锁的显式启动 / 修复 / 切换流程中调用）
clear_stop_locks() {
    rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
          "$SESSION_STOP_FILE" "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" \
          "$AGH_DIR/app_pause_active" 2>/dev/null
    if [ -f "$SCRIPT_DIR/config.prop" ]; then
        if grep -qE '^(STOPPED|MANUAL_STOP)=' "$SCRIPT_DIR/config.prop" 2>/dev/null; then
            sed -i '/^STOPPED=/d; /^MANUAL_STOP=/d' "$SCRIPT_DIR/config.prop" 2>/dev/null
        fi
    fi
}

is_module_disabled() {
    [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ] || [ -f "$ADGPATH/disable" ] || [ -f "$ADGPATH/remove" ]
}

is_manually_stopped() {
    is_module_disabled && return 0
    [ -f "$SESSION_STOP_FILE" ] && return 0
    [ -f /dev/shm/agh_manual_stop ] && return 0
    [ -f "$AGH_DIR/run/agh_manual_stop" ] && return 0
    [ -f "$AGH_DIR/manual_stop" ] && return 0
    [ -f "$AGH_DIR/stopped" ] && return 0
    [ -f "$AGH_DIR/app_pause_active" ] && return 0
    if [ "${STOPPED:-0}" = "1" ] || [ "${MANUAL_STOP:-0}" = "1" ]; then
        return 0
    fi
    if [ -f "$SCRIPT_DIR/config.prop" ] && grep -qE '^(STOPPED|MANUAL_STOP)=1$' "$SCRIPT_DIR/config.prop" 2>/dev/null; then
        return 0
    fi
    return 1
}

# ==============================================================================
# 核心健康检查：验证进程真实身份 (/proc/<pid>/comm)、有效 GID (Gid: 23333) 及 UDP+TCP DNS 端口监听
# ==============================================================================
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

# 内部函数（假定调用者已持有操作锁）
stop_agh_wait() {
    has_op_lock_context || return 1
    if pidof AdGuardHome >/dev/null 2>&1; then
        killall -15 AdGuardHome 2>/dev/null || {
            for p in $(pidof AdGuardHome 2>/dev/null); do kill -15 "$p" 2>/dev/null; done
        }
        if safe_sleep 0.1; then
            w=0
            while [ "$w" -lt 20 ]; do
                pidof AdGuardHome >/dev/null 2>&1 || break
                safe_sleep 0.1
                w=$((w + 1))
            done
        else
            w=0
            while [ "$w" -lt 2 ]; do
                pidof AdGuardHome >/dev/null 2>&1 || break
                sleep 1
                w=$((w + 1))
            done
        fi
        if pidof AdGuardHome >/dev/null 2>&1; then
            killall -9 AdGuardHome 2>/dev/null || {
                for p in $(pidof AdGuardHome 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
            }
            safe_sleep 0.3 || sleep 1
        fi
    fi
    rm -f "$PID_FILE" 2>/dev/null
    return 0
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

port_is_free() {
    if [ "$2" = "udp" ]; then
        ! udp_port_listening "$1"
    else
        ! tcp_port_listening "$1"
    fi
}

agh_core_healthy() {
    check_port="${1:-${redir_port:-55453}}"
    agh_running && udp_port_listening "$check_port" && tcp_port_listening "$check_port"
}

# 检查是否仍残留模块挂载的 OUTPUT 劫持跳转规则
has_residual_firewall_jumps() {
    iptables -w 2 -t nat -C OUTPUT -j ADGUARD >/dev/null 2>&1 && return 0
    iptables -w 2 -t mangle -C OUTPUT -j AGH_SNI >/dev/null 2>&1 && return 0
    ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT >/dev/null 2>&1 && return 0
    ip6tables -w 2 -t filter -C OUTPUT -j ADGUARD6 >/dev/null 2>&1 && return 0
    return 1
}

# 防断网安全阀（内部函数，假定调用者已持有操作锁）：卸载所有劫持规则并验证是否真实清理干净
disarm_nat_safety_valve() {
    has_op_lock_context || return 1
    clean_rc=0
    if [ -f "$SCRIPT_DIR/iptables.sh" ]; then
        run_sync_child "$SH_BIN" "$SCRIPT_DIR/iptables.sh" clean >/dev/null 2>&1 || clean_rc=1
    else
        while iptables -w 2 -t nat -D OUTPUT -j ADGUARD 2>/dev/null; do :; done
        iptables -w 2 -t nat -F ADGUARD 2>/dev/null
        iptables -w 2 -t nat -X ADGUARD 2>/dev/null
        while ip6tables -w 2 -t nat -D OUTPUT -j ADGUARD6_NAT 2>/dev/null; do :; done
        ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null
        ip6tables -w 2 -t nat -X ADGUARD6_NAT 2>/dev/null
        while ip6tables -w 2 -D OUTPUT -j ADGUARD6 2>/dev/null; do :; done
        ip6tables -w 2 -F ADGUARD6 2>/dev/null
        ip6tables -w 2 -X ADGUARD6 2>/dev/null
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
    fi
    if [ "$clean_rc" -ne 0 ] || has_residual_firewall_jumps; then
        log_msg "[CRITICAL] 防火墙规则清理未完全成功，OUTPUT 链可能仍存在残留跳转，请检查 iptables 状态！"
        return 1
    fi
    return 0
}

# 刷新系统 DNS 缓存并真实检查命令执行结果（不盲目用 || true 宣称已清理）
flush_dns_cache() {
    flushed_any=0
    if command -v ndc >/dev/null 2>&1; then
        ndc resolver flushenv >/dev/null 2>&1 && flushed_any=1
        ndc resolver flushdefaultif >/dev/null 2>&1 && flushed_any=1
    fi
    if command -v cmd >/dev/null 2>&1; then
        cmd netd resolver flushdefaultif >/dev/null 2>&1 && flushed_any=1
    fi
    [ "$flushed_any" -eq 1 ]
}

# 构建 Android 系统与 APEX Conscrypt 根证书合并包
build_ca_bundle() {
    temp="$CA_BUNDLE.tmp"
    if [ -s "$CA_BUNDLE" ]; then
        for cert_dir in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/etc/security/cacerts /data/misc/keychain/cacerts-added; do
            [ -d "$cert_dir" ] || continue
            bundle_mtime=$(stat -c %Y "$CA_BUNDLE" 2>/dev/null)
            source_mtime=$(stat -c %Y "$cert_dir" 2>/dev/null)
            if [ -n "$bundle_mtime" ] && [ -n "$source_mtime" ] && [ "$bundle_mtime" -ge "$source_mtime" ]; then
                return 0
            fi
        done
    fi
    rm -f "$temp" 2>/dev/null
    for cert_dir in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/etc/security/cacerts /data/misc/keychain/cacerts-added; do
        [ -d "$cert_dir" ] || continue
        for cert in "$cert_dir"/*; do
            [ -f "$cert" ] || continue
            grep -q '^-----BEGIN CERTIFICATE-----' "$cert" 2>/dev/null || continue
            cat "$cert" >> "$temp" 2>/dev/null
            echo "" >> "$temp"
        done
    done
    if [ -s "$temp" ]; then
        chmod 600 "$temp" 2>/dev/null
        mv -f "$temp" "$CA_BUNDLE" 2>/dev/null
    else
        rm -f "$temp" 2>/dev/null
    fi
}

# 以 setsid + BusyBox/util-linux nsenter 切入 PID 1 根命名空间与专属 GID 23333
# 关键：显式关闭 FD 8 与 FD 9 (8>&- 9>&-)，杜绝 AdGuardHome 核心进程意外继承守护锁或短期操作锁！
spawn_agh_in_root_ns() {
    escape_app_cgroup "$$"
    TRUE_BIN="/system/bin/true"
    [ -x "$TRUE_BIN" ] || TRUE_BIN="true"

    SETSID_CMD=""
    if [ -n "$BB_BIN" ] && "$BB_BIN" setsid "$TRUE_BIN" >/dev/null 2>&1; then
        SETSID_CMD="$BB_BIN setsid"
    elif command -v setsid >/dev/null 2>&1; then
        SETSID_CMD="setsid"
    fi

    if [ -n "$BB_BIN" ]; then
        if "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        elif "$BB_BIN" nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        elif "$BB_BIN" nsenter -t 1 -m -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        elif "$BB_BIN" nsenter -t 1 -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD "$BB_BIN" nsenter -t 1 -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        fi
    fi

    if command -v nsenter >/dev/null 2>&1; then
        if nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        elif nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        elif nsenter -t 1 -m -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -n -G "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        elif nsenter -G "$AGH_GID" -t 1 "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -G "$AGH_GID" -t 1 "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        elif command -v setpriv >/dev/null 2>&1 && \
             nsenter -t 1 -m -u -i -n setpriv --egid "$AGH_GID" --rgid "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            $SETSID_CMD nsenter -t 1 -m -u -i -n setpriv --egid "$AGH_GID" --rgid "$AGH_GID" "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
            SPAWN_PID=$!
            return 0
        fi
    fi

    $SETSID_CMD "$@" </dev/null >/dev/null 2>&1 8>&- 9>&- &
    SPAWN_PID=$!
    return 0
}

# 校验配置文件有效性
verify_or_restore_yaml() {
    check_f="$1"
    [ -s "$check_f" ] || return 1
    grep -q '^schema_version:' "$check_f" 2>/dev/null || return 1
    grep -q '^dns:' "$check_f" 2>/dev/null || return 1
    grep -q '^user_rules:' "$check_f" 2>/dev/null || return 1
    if [ -x "$BIN_DIR/AdGuardHome" ]; then
        "$BIN_DIR/AdGuardHome" --version >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            "$BIN_DIR/AdGuardHome" --check-config -c "$check_f" -w "$BIN_DIR" >/dev/null 2>&1 || return 1
        fi
    fi
    return 0
}

# 内部函数（假定调用者已持有操作锁）：首次安装缺少配置时可初始化；已有配置损坏且无有效备份时不得静默当成首次安装
ensure_valid_config() {
    has_op_lock_context || return 1
    if [ -e "$BIN_DIR/AdGuardHome.yaml" ]; then
        if verify_or_restore_yaml "$BIN_DIR/AdGuardHome.yaml"; then
            cp -f "$BIN_DIR/AdGuardHome.yaml" "$BAK_YAML" 2>/dev/null
            return 0
        fi
        # 已有配置存在但校验失败：仅允许从已验证备份恢复，严禁静默用默认模板覆盖！
        for bak_candidate in "$BAK_YAML" "$AGH_DIR/backup/AdGuardHome.yaml"; do
            if [ -s "$bak_candidate" ] && verify_or_restore_yaml "$bak_candidate"; then
                cp -f "$bak_candidate" "$BIN_DIR/AdGuardHome.yaml.restore.tmp" 2>/dev/null && \
                    mv -f "$BIN_DIR/AdGuardHome.yaml.restore.tmp" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
                cp -f "$BIN_DIR/AdGuardHome.yaml" "$BAK_YAML" 2>/dev/null
                log_msg "[WARN] 主配置校验未通过，已从已验证备份 ($bak_candidate) 无损恢复用户配置"
                return 0
            fi
        done
        log_msg "[ERROR] 现有 AdGuardHome.yaml 损坏且无有效备份可恢复，拒绝静默重置为默认模板"
        return 1
    fi

    # 主配置完全不存在：先检查是否有已验证备份，否则作为首次安装从模板初始化
    for bak_candidate in "$BAK_YAML" "$AGH_DIR/backup/AdGuardHome.yaml"; do
        if [ -s "$bak_candidate" ] && verify_or_restore_yaml "$bak_candidate"; then
            cp -f "$bak_candidate" "$BIN_DIR/AdGuardHome.yaml.restore.tmp" 2>/dev/null && \
                mv -f "$BIN_DIR/AdGuardHome.yaml.restore.tmp" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
            cp -f "$BIN_DIR/AdGuardHome.yaml" "$BAK_YAML" 2>/dev/null
            log_msg "[INFO] 主配置缺失，已从备份 ($bak_candidate) 恢复用户配置"
            return 0
        fi
    done

    if [ -s "$BIN_DIR/AdGuardHome_${active_mode}.yaml" ]; then
        cp -f "$BIN_DIR/AdGuardHome_${active_mode}.yaml" "$BIN_DIR/AdGuardHome.yaml.init.tmp" 2>/dev/null && \
            mv -f "$BIN_DIR/AdGuardHome.yaml.init.tmp" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
        if verify_or_restore_yaml "$BIN_DIR/AdGuardHome.yaml"; then
            cp -f "$BIN_DIR/AdGuardHome.yaml" "$BAK_YAML" 2>/dev/null
            log_msg "[INFO] 首次安装缺少配置，已从预设模板初始化配置 (mode=$active_mode)"
            return 0
        fi
    fi
    return 1
}

# 内部函数（假定调用者已持有操作锁）：按当前配置拉起核心并确认 UDP + TCP DNS 端口真实就绪
ensure_agh_started() {
    has_op_lock_context || return 1
    [ "$ABORTED_BY_SIGNAL" = "1" ] && return 1
    load_runtime_config
    if is_manually_stopped; then
        disarm_nat_safety_valve >/dev/null 2>&1 || true
        stop_agh_wait >/dev/null 2>&1 || true
        return 1
    fi
    if agh_core_healthy "$redir_port"; then
        return 0
    fi

    disarm_nat_safety_valve >/dev/null 2>&1 || true
    stop_agh_wait

    if ! ensure_valid_config; then
        log_msg "[ERROR] AdGuardHome.yaml 校验与恢复失败，中止启动以保护配置"
        return 1
    fi

    build_ca_bundle

    cfg_dns=$(awk '/^dns:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*port:[[:space:]]*[0-9]+/{sub(/.*port:[[:space:]]*/, ""); print; exit}' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null)
    cfg_http=$(sed -n 's/^[[:space:]]*address:[[:space:]]*127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
    [ -n "$cfg_dns" ] || cfg_dns=55453
    [ -n "$cfg_http" ] || cfg_http=43000

    MAX_TRIES=3
    try_count=0
    while [ "$try_count" -lt "$MAX_TRIES" ]; do
        [ "$ABORTED_BY_SIGNAL" = "1" ] && return 1
        if is_manually_stopped; then
            disarm_nat_safety_valve >/dev/null 2>&1 || true
            stop_agh_wait >/dev/null 2>&1 || true
            return 1
        fi
        try_count=$((try_count + 1))
        if [ "$try_count" -eq 1 ] && port_is_free "$cfg_dns" udp && port_is_free "$cfg_dns" tcp && port_is_free "$cfg_http" tcp; then
            R1="$cfg_dns"
            R2="$cfg_http"
        elif [ "$try_count" -eq 1 ] && port_is_free 55453 udp && port_is_free 55453 tcp && port_is_free 43000 tcp; then
            R1=55453
            R2=43000
        else
            rand_seed=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | tr -d ' ')
            [ -z "$rand_seed" ] && rand_seed="${RANDOM:-12345}"
            R1=$((30000 + (rand_seed % 25000)))
            R2=$((30000 + ((rand_seed + 7919) % 25000)))
        fi

        if [ "$R1" != "$cfg_dns" ] || [ "$R2" != "$cfg_http" ]; then
            sed -i "/^dns:/,/^[^[:space:]]/ s/^\([[:space:]]*port:\) [0-9]*/\1 $R1/; s/^\([[:space:]]*address:\) 127\.0\.0\.1:[0-9]*/\1 127.0.0.1:$R2/" "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null
            cp -f "$BIN_DIR/AdGuardHome.yaml" "$BAK_YAML" 2>/dev/null
        fi
        if [ "$R1" != "$redir_port" ]; then
            sed -i "s/^redir_port=.*/redir_port=$R1/" "$SCRIPT_DIR/config.prop" 2>/dev/null
            redir_port="$R1"
        fi

        AGH_TZ="$(getprop persist.sys.timezone 2>/dev/null)"
        [ -n "$AGH_TZ" ] && export TZ="$AGH_TZ"
        export SSL_CERT_DIR="/system/etc/security/cacerts/"
        [ -s "$CA_BUNDLE" ] && export SSL_CERT_FILE="$CA_BUNDLE"

        SPAWN_PID=""
        spawn_agh_in_root_ns "$BIN_DIR/AdGuardHome" \
            -c "$BIN_DIR/AdGuardHome.yaml" \
            -w "$BIN_DIR" \
            --no-check-update \
            --no-etc-hosts \
            --crash-log "$AGH_DIR/crash.log" \
            --logfile discard
        [ -n "$SPAWN_PID" ] && echo "$SPAWN_PID" > "$PID_FILE"

        ready=0
        if safe_sleep 0.2; then
            step=0
            while [ "$step" -lt 40 ]; do
                [ "$ABORTED_BY_SIGNAL" = "1" ] && { stop_agh_wait; return 1; }
                if agh_core_healthy "$R1"; then
                    ready=1
                    break
                fi
                safe_sleep 0.2
                step=$((step + 1))
            done
        else
            step=0
            while [ "$step" -lt 8 ]; do
                [ "$ABORTED_BY_SIGNAL" = "1" ] && { stop_agh_wait; return 1; }
                if agh_core_healthy "$R1"; then
                    ready=1
                    break
                fi
                sleep 1
                step=$((step + 1))
            done
        fi

        if [ "$ready" -eq 1 ] && agh_core_healthy "$R1"; then
            if is_manually_stopped; then
                stop_agh_wait
                disarm_nat_safety_valve >/dev/null 2>&1 || true
                return 1
            fi
            agh_real_pid=$(cat "$PID_FILE" 2>/dev/null)
            [ -n "$agh_real_pid" ] && escape_app_cgroup "$agh_real_pid"
            if [ "$lang" = "zh" ]; then
                log_msg "[INFO] AdGuardHome 核心已就绪 (mode=$active_mode, PID=${agh_real_pid:-unknown}, GID=$AGH_GID, DNS=$R1, HTTP=$R2)"
            else
                log_msg "[INFO] AdGuardHome ready (mode=$active_mode, PID=${agh_real_pid:-unknown}, GID=$AGH_GID, DNS=$R1, HTTP=$R2)"
            fi
            return 0
        fi

        stop_agh_wait
    done

    if disarm_nat_safety_valve; then
        if [ "$lang" = "zh" ]; then
            log_msg "[FATAL] AdGuardHome 连续启动失败 $MAX_TRIES 次，已卸载模块防火墙规则。"
        else
            log_msg "[FATAL] AdGuardHome failed after $MAX_TRIES attempts, module firewall rules unmounted."
        fi
    else
        log_msg "[FATAL] AdGuardHome 连续启动失败 $MAX_TRIES 次，且防火墙规则回退清理失败，请立即检查系统 netfilter 状态！"
    fi
    return 1
}

# 仅读取模块自有链检查防火墙健康状态（避免全表扫描，覆盖 UDP+TCP 53 重定向、DoT、记录的 IPv6 模式及 SNI 链）
nat_rules_healthy() {
    check_port="${redir_port:-55453}"
    check_sni="${ENABLE_SNI:-1}"

    # 1. IPv4 nat OUTPUT 跳转与 ADGUARD 自有链检查（覆盖 UDP 53 与 TCP 53）
    nat_out_dump=$(iptables -w 2 -t nat -S OUTPUT 2>/dev/null) || return 1
    jump_cnt=$(printf '%s\n' "$nat_out_dump" | grep -c -- '^-A OUTPUT -j ADGUARD$')
    [ "$jump_cnt" -eq 1 ] || return 1

    adg_chain=$(iptables -w 2 -t nat -S ADGUARD 2>/dev/null) || return 1
    printf '%s\n' "$adg_chain" | grep -qE -- "^-A ADGUARD -d 127\.0\.0\.1/32 -p udp .*--dport 53 -j REDIRECT --to-ports ${check_port}([[:space:]]|\$)" || return 1
    printf '%s\n' "$adg_chain" | grep -qE -- "^-A ADGUARD -d 127\.0\.0\.1/32 -p tcp .*--dport 53 -j REDIRECT --to-ports ${check_port}([[:space:]]|\$)" || return 1
    printf '%s\n' "$adg_chain" | grep -q -- "--gid-owner $AGH_GID -j RETURN" || return 1
    printf '%s\n' "$adg_chain" | grep -qE -- "^-A ADGUARD .*-p udp .*--dport 53 -j REDIRECT --to-ports ${check_port}([[:space:]]|\$)" || return 1
    printf '%s\n' "$adg_chain" | grep -qE -- "^-A ADGUARD .*-p tcp .*--dport 53 -j REDIRECT --to-ports ${check_port}([[:space:]]|\$)" || return 1

    # 2. filter 表 ADGUARD_DOT 与 AGH_INPUT 检查
    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 || return 1
    iptables -w 2 -t filter -C INPUT -j AGH_INPUT >/dev/null 2>&1 || return 1

    # 3. IPv6 接管链检查（依据挂载时记录的实际内核能力模式，避免不支持 ip6tables nat 的内核无限重挂）
    v6_mode=$(cat "$IPV6_DNS_MODE_FILE" 2>/dev/null)
    if [ "$v6_mode" = "nat" ]; then
        ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT >/dev/null 2>&1 || return 1
        adg6_chain=$(ip6tables -w 2 -t nat -S ADGUARD6_NAT 2>/dev/null) || return 1
        printf '%s\n' "$adg6_chain" | grep -qE -- "^-A ADGUARD6_NAT .*-p udp .*--dport 53 -j REDIRECT --to-ports ${check_port}([[:space:]]|\$)" || return 1
        printf '%s\n' "$adg6_chain" | grep -qE -- "^-A ADGUARD6_NAT .*-p tcp .*--dport 53 -j REDIRECT --to-ports ${check_port}([[:space:]]|\$)" || return 1
    elif [ "$v6_mode" = "filter" ]; then
        ip6tables -w 2 -t filter -C OUTPUT -j ADGUARD6 >/dev/null 2>&1 || return 1
    fi

    # 4. mangle 表 AGH_SNI 自有链检查
    if [ "$check_sni" = "1" ]; then
        sni_fw_mode=$(cat "$SNI_FW_MODE_FILE" 2>/dev/null)
        if [ "$sni_fw_mode" != "unsupported" ]; then
            mangle_out=$(iptables -w 2 -t mangle -S OUTPUT 2>/dev/null) || return 1
            sni_jump_cnt=$(printf '%s\n' "$mangle_out" | grep -c -- '^-A OUTPUT -j AGH_SNI$')
            [ "$sni_jump_cnt" -eq 1 ] || return 1
            sni_chain=$(iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null) || return 1
            printf '%s\n' "$sni_chain" | grep -qE -- "^-A AGH_SNI .*-m owner --gid-owner ${AGH_GID} -j RETURN([[:space:]]|\$)" || return 1
            printf '%s\n' "$sni_chain" | grep -qE -- "^-A AGH_SNI .*-p tcp .*--dport 443 .*-j NFQUEUE .*--queue-bypass" || return 1
            printf '%s\n' "$sni_chain" | grep -qE -- "^-A AGH_SNI .*-p tcp .*--dport 8443 .*-j NFQUEUE .*--queue-bypass" || return 1
        fi
    fi
    return 0
}

# 内部函数（假定调用者已持有操作锁）：幂等重挂网络转发规则并强制执行应用后自检
remount_nat_rules() {
    has_op_lock_context || return 1
    [ "$ABORTED_BY_SIGNAL" = "1" ] && return 1
    reason="${1:-heal}"
    load_runtime_config
    if is_manually_stopped; then
        disarm_nat_safety_valve >/dev/null 2>&1 || true
        return 1
    fi
    if ! agh_core_healthy "${redir_port:-55453}"; then
        disarm_nat_safety_valve >/dev/null 2>&1 || true
        return 1
    fi
    run_sync_child "$SH_BIN" "$SCRIPT_DIR/iptables.sh" clean >/dev/null 2>&1 || true
    if run_sync_child "$SH_BIN" "$SCRIPT_DIR/iptables.sh" enable >/dev/null 2>&1 && nat_rules_healthy; then
        sni_fw_mode=$(cat "$SNI_FW_MODE_FILE" 2>/dev/null)
        log_msg "[WATCHDOG] 已完成防火墙规则幂等重挂并通过自检 (reason=$reason, DNS=${redir_port:-55453}, SNI=${sni_fw_mode:-auto})"
        return 0
    fi
    log_msg "[ERROR] 防火墙规则挂载或应用后检查失败 (reason=$reason)，正在释放无效接管"
    if ! disarm_nat_safety_valve; then
        log_msg "[CRITICAL] 防火墙挂载失败后的回退清理亦失败 (reason=$reason)！"
    fi
    return 1
}

# 按需单次诊断 SNI / NFQUEUE 与 connbytes 状态（零后台轮询）
diagnose_sni_state() {
    load_runtime_config
    sni_yaml_enabled=$(awk '/^sni_filter:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*enabled:[[:space:]]*(true|false)/{sub(/.*enabled:[[:space:]]*/, ""); print; exit}' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null)
    sni_queue=$(awk '/^sni_filter:/{f=1;next} f&&/^[^[:space:]]/{f=0} f&&/^[[:space:]]*queue_num:[[:space:]]*[0-9]+/{sub(/.*queue_num:[[:space:]]*/, ""); print; exit}' "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null)
    [ -n "$sni_queue" ] || sni_queue=0
    sni_fw_mode=$(cat "$SNI_FW_MODE_FILE" 2>/dev/null)

    v4_sni_rules=$(iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null | grep -- '-j NFQUEUE' | wc -l | tr -d ' ')
    v4_connbytes=$(iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null | grep -- 'connbytes' | wc -l | tr -d ' ')
    v6_sni_rules=$(ip6tables -w 2 -t mangle -S AGH_SNI 2>/dev/null | grep -- '-j NFQUEUE' | wc -l | tr -d ' ')
    v6_connbytes=$(ip6tables -w 2 -t mangle -S AGH_SNI 2>/dev/null | grep -- 'connbytes' | wc -l | tr -d ' ')

    nfq_bound="unknown"
    nfq_line=""
    if [ -r /proc/net/netfilter/nfnetlink_queue ]; then
        nfq_line=$(awk -v q="$sni_queue" '$1 == q {print $0}' /proc/net/netfilter/nfnetlink_queue 2>/dev/null)
        if [ -n "$nfq_line" ]; then
            nfq_bound="bound"
        else
            nfq_bound="unbound"
        fi
    else
        nfq_bound="proc_unavailable"
    fi

    printf 'SNI_DIAG: ENABLE_SNI=%s yaml_enabled=%s queue_num=%s fw_mode=%s v4_nfq=%s(connbytes=%s) v6_nfq=%s(connbytes=%s) nfq_kernel=%s\n' \
        "$ENABLE_SNI" "${sni_yaml_enabled:-true}" "$sni_queue" "${sni_fw_mode:-unknown}" \
        "$v4_sni_rules" "$v4_connbytes" "$v6_sni_rules" "$v6_connbytes" "$nfq_bound"
    [ -n "$nfq_line" ] && printf 'SNI_NFQUEUE_PROC: %s\n' "$nfq_line"
    return 0
}

detect_vpn_iface() {
    for iface in /sys/class/net/tun* /sys/class/net/wg* /sys/class/net/ppp*; do
        if [ -d "$iface" ]; then
            echo "on"
            return 0
        fi
    done
    echo "off"
}

# 在根命名空间与独立会话中确保全局唯一后台守护循环在线（显式关闭 FD 8 与 FD 9）
start_singleton_watchdog() {
    if watchdog_alive; then
        return 0
    fi
    escape_app_cgroup "$$"
    TRUE_BIN="/system/bin/true"
    [ -x "$TRUE_BIN" ] || TRUE_BIN="true"
    SETSID_CMD=""
    if [ -n "$BB_BIN" ] && "$BB_BIN" setsid "$TRUE_BIN" >/dev/null 2>&1; then
        SETSID_CMD="$BB_BIN setsid"
    elif command -v setsid >/dev/null 2>&1; then
        SETSID_CMD="setsid"
    fi
    if [ -n "$BB_BIN" ] && "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F "$TRUE_BIN" >/dev/null 2>&1; then
        $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 8>&- 9>&- &
    elif [ -n "$BB_BIN" ] && "$BB_BIN" nsenter -t 1 -m -n "$TRUE_BIN" >/dev/null 2>&1; then
        $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -n "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 8>&- 9>&- &
    elif command -v nsenter >/dev/null 2>&1 && nsenter -t 1 -m -n "$TRUE_BIN" >/dev/null 2>&1; then
        $SETSID_CMD nsenter -t 1 -m -n "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 8>&- 9>&- &
    else
        $SETSID_CMD "$SH_BIN" "$SELF_SCRIPT" --watchdog </dev/null >/dev/null 2>&1 8>&- 9>&- &
    fi
    safe_sleep 0.1 || true
}

# ==============================================================================
# 子命令 0：按需单次诊断接口 (--diag-sni)
# ==============================================================================
if [ "$1" = "--diag-sni" ] || [ "$1" = "diag-sni" ]; then
    diagnose_sni_state
    exit 0
fi

# ==============================================================================
# 子命令 0b：供已持有操作锁的父脚本 (switch_mode.sh) 同步调用的内部原语
# ==============================================================================
if [ "$1" = "--internal-stop-under-lock" ]; then
    has_op_lock_context || exit 1
    disarm_nat_safety_valve || true
    stop_agh_wait || exit 1
    exit 0
fi

if [ "$1" = "--internal-start-and-mount-under-lock" ]; then
    has_op_lock_context || exit 1
    reason_arg="${2:-mode-switch}"
    ensure_private_dns_off
    start_singleton_watchdog
    if ensure_agh_started && remount_nat_rules "$reason_arg"; then
        exit 0
    fi
    disarm_nat_safety_valve >/dev/null 2>&1 || true
    exit 1
fi

# ==============================================================================
# 子命令 1：独立后台单例巡检守护模式 (--watchdog)
# 每 30 秒低功耗巡检一次，零 Wakelock，操作锁仅在需要恢复时短暂获取，休眠期间绝不持有操作锁
# ==============================================================================
if [ "$1" = "--watchdog" ]; then
    escape_app_cgroup "$$"
    if ! acquire_watchdog_lock; then
        exit 0
    fi

    vpn_last=$(detect_vpn_iface)
    cleaned_when_disabled=0
    watchdog_tick=0
    fail_streak=0
    backoff_remaining=0
    WATCHDOG_INTERVAL="${AGH_WATCHDOG_INTERVAL:-30}"

    while [ "$ABORTED_BY_SIGNAL" = "0" ]; do
        safe_sleep "$WATCHDOG_INTERVAL" || exit 0
        [ "$ABORTED_BY_SIGNAL" = "1" ] && break
        watchdog_tick=$((watchdog_tick + 1))

        # 软重启过渡期间等待 Android 系统服务与 netd 初始化就绪
        boot_ok=$(getprop sys.boot_completed 2>/dev/null)
        [ -z "$boot_ok" ] || [ "$boot_ok" = "1" ] || continue

        load_runtime_config

        # 1. 严格尊重手动停止或模块禁用状态：绝不擅自重启核心或挂载规则
        if is_manually_stopped; then
            fail_streak=0
            backoff_remaining=0
            if is_module_disabled && [ "$cleaned_when_disabled" -eq 0 ]; then
                if acquire_op_lock 5; then
                    disarm_nat_safety_valve >/dev/null 2>&1 || true
                    stop_agh_wait
                    restore_private_dns
                    cleaned_when_disabled=1
                    log_msg "[WATCHDOG] 检测到模块已禁用 ($MODDIR/disable)，已清理规则并进入静默状态"
                    release_op_lock
                fi
            fi
            continue
        fi
        cleaned_when_disabled=0

        # 1b. 防系统「私人 DNS」绕过；卸载残留目录 (*==deleted==) 拆分为每 20 轮 (~10 分钟) 低频维护一次
        ensure_private_dns_off
        if [ $((watchdog_tick % 20)) -eq 0 ]; then
            clean_deleted_app_dirs
        fi

        # 2. 核心与端口健康检查：软重启后若核心仍健康则直接复用原进程（保留缓存与内存统计）
        vpn_now=$(detect_vpn_iface)
        core_ok=0
        if agh_core_healthy "$redir_port"; then
            core_ok=1
            fail_streak=0
            backoff_remaining=0
        fi

        if [ "$core_ok" -eq 0 ]; then
            if [ "$backoff_remaining" -gt 0 ]; then
                backoff_remaining=$((backoff_remaining - 1))
                continue
            fi
            if acquire_op_lock 5; then
                load_runtime_config
                if is_manually_stopped; then
                    release_op_lock
                    continue
                fi
                if ! agh_core_healthy "$redir_port"; then
                    disarm_nat_safety_valve >/dev/null 2>&1 || true
                    log_msg "[WATCHDOG] 检测到 AdGuardHome 未运行或端口未完整监听，正在按当前模式恢复核心 (streak=$((fail_streak + 1)))..."
                    if ensure_agh_started && remount_nat_rules "core-recovered"; then
                        vpn_last="$vpn_now"
                        fail_streak=0
                        backoff_remaining=0
                    else
                        fail_streak=$((fail_streak + 1))
                        case "$fail_streak" in
                            1) backoff_remaining=0 ;;
                            2) backoff_remaining=1 ;;
                            3) backoff_remaining=3 ;;
                            *) backoff_remaining=9 ;;
                        esac
                        log_msg "[WATCHDOG] 核心或防火墙恢复失败 (连续第 ${fail_streak} 次)，退避 $((backoff_remaining * 30)) 秒后重试"
                    fi
                fi
                release_op_lock
            fi
            continue
        fi

        # 3. 核心健康时检查防火墙规则与 VPN 状态变化：正常运行时零重挂，仅在缺失或 VPN 变化时短暂加锁重挂
        if [ "$vpn_now" != "$vpn_last" ]; then
            if acquire_op_lock 5; then
                if ! is_manually_stopped; then
                    if remount_nat_rules "vpn-$vpn_now"; then
                        vpn_last="$vpn_now"
                    fi
                fi
                release_op_lock
            fi
        elif ! nat_rules_healthy; then
            if acquire_op_lock 5; then
                if ! is_manually_stopped && ! nat_rules_healthy; then
                    if remount_nat_rules "nat-missing"; then
                        vpn_last="$vpn_now"
                    fi
                fi
                release_op_lock
            fi
        fi

        # 4. 仅当用户配置了非空 PROXY_URL 订阅链接时，执行单次同步
        if [ -n "$PROXY_URL_CLEAN" ] && [ -f "$SCRIPT_DIR/ProxyConfig.sh" ]; then
            "$SH_BIN" "$SCRIPT_DIR/ProxyConfig.sh" --once >/dev/null 2>&1 8>&- 9>&-
        fi
    done
    exit 0
fi

# ==============================================================================
# 子命令 2：热重启核心接口 (--restart)
# 必须同时满足：核心检查成功 AND 必要规则应用成功 AND 应用后检查成功
# ==============================================================================
if [ "$1" = "restart" ] || [ "$1" = "--restart" ]; then
    acquire_op_lock 15 || {
        echo "AGH_REPAIR_RESULT status=error stage=lock_timeout branch=service_restart dns_flushed=0"
        exit 1
    }
    clear_stop_locks
    ensure_private_dns_off
    clean_deleted_app_dirs
    disarm_nat_safety_valve >/dev/null 2>&1 || true
    stop_agh_wait
    start_singleton_watchdog
    if ensure_agh_started; then
        if remount_nat_rules "mode-switch"; then
            flush_ok=0
            if flush_dns_cache; then
                flush_ok=1
            fi
            echo "AGH_REPAIR_RESULT status=ok stage=complete branch=service_restart dns_flushed=$flush_ok"
            exit 0
        else
            echo "AGH_REPAIR_RESULT status=error stage=firewall_mount branch=service_restart dns_flushed=0"
            exit 2
        fi
    fi
    if disarm_nat_safety_valve; then
        echo "AGH_REPAIR_RESULT status=error stage=core_start branch=service_restart dns_flushed=0"
    else
        echo "AGH_REPAIR_RESULT status=error stage=core_start_and_cleanup_failed branch=service_restart dns_flushed=0"
    fi
    exit 1
fi

# ==============================================================================
# 子命令 3：一键修复 / 网络刷新接口 (--repair，供 Manager App 显式修复调用)
# 必须同时满足：核心检查成功 AND 必要规则应用成功 AND 应用后检查成功
# ==============================================================================
if [ "$1" = "repair" ] || [ "$1" = "--repair" ]; then
    acquire_op_lock 15 || {
        echo "AGH_REPAIR_RESULT status=error stage=lock_timeout branch=service_repair dns_flushed=0"
        exit 1
    }
    clear_stop_locks
    ensure_private_dns_off
    clean_deleted_app_dirs
    start_singleton_watchdog
    if ensure_agh_started; then
        if remount_nat_rules "manual-repair"; then
            flush_ok=0
            if flush_dns_cache; then
                flush_ok=1
            fi
            echo "AGH_REPAIR_RESULT status=ok stage=complete branch=service_repair dns_flushed=$flush_ok"
            exit 0
        else
            echo "AGH_REPAIR_RESULT status=error stage=firewall_mount branch=service_repair dns_flushed=0"
            exit 2
        fi
    fi
    if disarm_nat_safety_valve; then
        echo "AGH_REPAIR_RESULT status=error stage=core_start branch=service_repair dns_flushed=0"
    else
        echo "AGH_REPAIR_RESULT status=error stage=core_start_and_cleanup_failed branch=service_repair dns_flushed=0"
    fi
    exit 1
fi

# ==============================================================================
# 子命令 4：显式手动停止 / 启动接口 (stop / start)
# 先记录停止意图；未取得锁时不得直接拆装规则或杀核心，必须报告“停止请求已记录，当前操作尚未结束”
# ==============================================================================
if [ "$1" = "stop" ] || [ "$1" = "--stop" ]; then
    : > "$SESSION_STOP_FILE" 2>/dev/null
    if ! acquire_op_lock 15; then
        log_msg "[WARN] 停止请求已记录，当前操作尚未结束"
        echo "AGH_STOP_RESULT status=pending message=停止请求已记录，当前操作尚未结束"
        exit 1
    fi
    : > "$SESSION_STOP_FILE" 2>/dev/null
    clean_ok=1
    disarm_nat_safety_valve || clean_ok=0
    stop_agh_wait
    restore_private_dns
    flush_dns_cache >/dev/null 2>&1 || true
    if [ "$clean_ok" -eq 1 ]; then
        log_msg "[INFO] 已收到手动停止指令，核心与防火墙规则已卸下，守护进程保持静默"
        echo "AGH_STOP_RESULT status=ok"
        exit 0
    else
        log_msg "[ERROR] 已停止核心，但部分防火墙规则卸载失败，请检查系统 iptables 状态"
        echo "AGH_STOP_RESULT status=error stage=cleanup_failed"
        exit 1
    fi
fi

if [ "$1" = "start" ] || [ "$1" = "--start" ]; then
    acquire_op_lock 15 || exit 1
    clear_stop_locks
else
    acquire_op_lock 15 || exit 1
fi

# ==============================================================================
# 默认启动入口（开机或软重启由 Magisk / KernelSU / APatch 自动触发）
# ==============================================================================
find "$ADGPATH" "$SCRIPT_DIR" -type f -name "*.sh" -exec chattr -i {} \; 2>/dev/null

# 检查冲突的 hosts 模块并中止启动
found_hosts=false
for module in "$MODULES_DIR"/*; do
    [ -d "$module" ] && [ -f "$module/system/etc/hosts" ] && {
        found_hosts=true
        touch "$module/remove"
    }
done
if [ "$found_hosts" = true ]; then
    disarm_nat_safety_valve >/dev/null 2>&1 || true
    if [ "$lang" = "zh" ]; then
        log_msg "[ERROR] 检测到 hosts 模块，AdGuardHome 启动已中止"
    else
        log_msg "[ERROR] Hosts module detected, AdGuardHome startup aborted"
    fi
    exit 1
fi

load_runtime_config
if is_manually_stopped; then
    disarm_nat_safety_valve >/dev/null 2>&1 || true
    start_singleton_watchdog
    exit 0
fi

ensure_private_dns_off
clean_deleted_app_dirs

if ! ensure_agh_started; then
    disarm_nat_safety_valve >/dev/null 2>&1 || true
    start_singleton_watchdog
    exit 1
fi

if ! nat_rules_healthy; then
    if ! remount_nat_rules "startup"; then
        start_singleton_watchdog
        exit 1
    fi
fi

[ -f "$SCRIPT_DIR/NoAdsService.sh" ] && "$SH_BIN" "$SCRIPT_DIR/NoAdsService.sh" >/dev/null 2>&1 8>&- 9>&- &
if [ -n "$PROXY_URL_CLEAN" ] && [ -f "$SCRIPT_DIR/ProxyConfig.sh" ]; then
    "$SH_BIN" "$SCRIPT_DIR/ProxyConfig.sh" --once >/dev/null 2>&1 8>&- 9>&- &
fi

start_singleton_watchdog
exit 0
