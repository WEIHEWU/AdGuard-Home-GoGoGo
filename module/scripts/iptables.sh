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

SCRIPT_LABEL="iptables.sh"
SH_BIN="${SH_BIN:-/system/bin/sh}"
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
BUSYBOX_BIN="$BB_BIN"
if [ -n "$BB_BIN" ]; then
    command -v awk >/dev/null 2>&1 || awk() { "$BB_BIN" awk "$@"; }
    command -v pidof >/dev/null 2>&1 || pidof() { "$BB_BIN" pidof "$@"; }
    command -v killall >/dev/null 2>&1 || killall() { "$BB_BIN" killall "$@"; }
fi

safe_sleep() {
    if sleep "$1" >/dev/null 2>&1 7>&- 8>&- 9>&-; then
        return 0
    elif [ -n "$BB_BIN" ] && "$BB_BIN" sleep "$1" >/dev/null 2>&1 7>&- 8>&- 9>&-; then
        return 0
    elif [ -x /system/bin/toybox ] && /system/bin/toybox sleep "$1" >/dev/null 2>&1 7>&- 8>&- 9>&-; then
        return 0
    elif [ -x /system/bin/toolbox ] && /system/bin/toolbox sleep "$1" >/dev/null 2>&1 7>&- 8>&- 9>&-; then
        return 0
    fi
    return 1
}

resolve_abs_path() {
    p="$1"
    case "$p" in
        /*) printf '%s\n' "$p" ;;
        *)  printf '%s/%s\n' "$(pwd 2>/dev/null || echo /)" "$p" ;;
    esac
}

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
RUN_DIR="$(cd "$RUN_DIR" 2>/dev/null && pwd || resolve_abs_path "$RUN_DIR")"

OP_LOCK_FILE="$(resolve_abs_path "$RUN_DIR/agh_op.flock")"
OP_LOCK_DIAG_PID_FILE="$(resolve_abs_path "$RUN_DIR/agh_op.pid")"
OP_PID_FILE="$OP_LOCK_DIAG_PID_FILE"
SESSION_STOP_FILE="$(resolve_abs_path "$RUN_DIR/agh_manual_stop")"
IPV6_DNS_MODE_FILE="$(resolve_abs_path "$RUN_DIR/agh_ipv6_dns_mode")"
SNI_FW_MODE_FILE="$(resolve_abs_path "$RUN_DIR/agh_sni_fw_mode")"
SNI_QUEUE_NUM_FILE="$(resolve_abs_path "$RUN_DIR/agh_sni_queue_num")"

if [ -f "$SCRIPT_DIR/diag_log.sh" ]; then
    . "$SCRIPT_DIR/diag_log.sh"
elif [ -f "${MODDIR:-/data/adb/modules/AdGuardHome}/scripts/diag_log.sh" ]; then
    . "${MODDIR:-/data/adb/modules/AdGuardHome}/scripts/diag_log.sh"
fi

log_msg() {
    if command -v agh_log_always >/dev/null 2>&1; then
        agh_log_always "$1"
    else
        echo "$(date '+%F %T') $1" >> "$MAIN_LOG" 2>/dev/null || true
    fi
}

# 显式初始化单调时钟基准（必须在父 Shell 直接调用，严禁放入 $(...) 子命令替换中）
init_monotonic_clock() {
    if [ -n "${AGH_MONO_CLOCK_SOURCE:-}" ]; then
        case "$AGH_MONO_CLOCK_SOURCE" in
            uptime|perl_epoch|date_epoch)
                case "${AGH_MONO_BASE_SEC:-}" in
                    ''|*[!0-9]*) ;;
                    *)
                        export AGH_MONO_CLOCK_SOURCE AGH_MONO_BASE_SEC
                        return 0
                        ;;
                esac
                ;;
            unavailable)
                export AGH_MONO_CLOCK_SOURCE
                return 1
                ;;
        esac
    fi

    _mc_up_f="${AGH_UPTIME_FILE:-/proc/uptime}"
    if [ -r "$_mc_up_f" ]; then
        _mc_sec=""
        _mc_frac=""
        IFS='. ' read -r _mc_sec _mc_frac _mc_rest < "$_mc_up_f" 2>/dev/null || true
        case "${_mc_sec:-}" in
            ''|*[!0-9]*) ;;
            *)
                while :; do
                    case "$_mc_sec" in
                        0[0-9]*) _mc_sec="${_mc_sec#0}" ;;
                        *) break ;;
                    esac
                done
                AGH_MONO_CLOCK_SOURCE="uptime"
                AGH_MONO_BASE_SEC="$_mc_sec"
                export AGH_MONO_CLOCK_SOURCE AGH_MONO_BASE_SEC
                return 0
                ;;
        esac
    fi

    if [ "${AGH_DISABLE_FALLBACK_CLOCK:-0}" != "1" ]; then
        _mc_sec=$(date +%s 2>/dev/null || true)
        case "${_mc_sec:-}" in
            ''|*[!0-9]*) ;;
            *)
                while :; do
                    case "$_mc_sec" in
                        0[0-9]*) _mc_sec="${_mc_sec#0}" ;;
                        *) break ;;
                    esac
                done
                if command -v perl >/dev/null 2>&1 && perl -MTime::HiRes=time -e 'exit 0' >/dev/null 2>&1; then
                    AGH_MONO_CLOCK_SOURCE="perl_epoch"
                else
                    AGH_MONO_CLOCK_SOURCE="date_epoch"
                fi
                AGH_MONO_BASE_SEC="$_mc_sec"
                export AGH_MONO_CLOCK_SOURCE AGH_MONO_BASE_SEC
                return 0
                ;;
        esac
    fi

    AGH_MONO_CLOCK_SOURCE="unavailable"
    AGH_MONO_BASE_SEC=""
    export AGH_MONO_CLOCK_SOURCE AGH_MONO_BASE_SEC
    return 1
}

# 仅读取已初始化的时间基准并输出相对毫秒（不修改 AGH_MONO_BASE_SEC / AGH_MONO_CLOCK_SOURCE）
mono_now_ms() {
    case "${AGH_MONO_CLOCK_SOURCE:-unavailable}" in
        uptime)
            case "${AGH_MONO_BASE_SEC:-}" in
                ''|*[!0-9]*) printf 'unavailable\n'; return 1 ;;
            esac
            _mn_up_f="${AGH_UPTIME_FILE:-/proc/uptime}"
            [ -r "$_mn_up_f" ] || { printf 'unavailable\n'; return 1; }
            _mn_sec=""
            _mn_frac=""
            IFS='. ' read -r _mn_sec _mn_frac _mn_rest < "$_mn_up_f" 2>/dev/null || true
            case "${_mn_sec:-}" in
                ''|*[!0-9]*) printf 'unavailable\n'; return 1 ;;
            esac
            while :; do
                case "$_mn_sec" in
                    0[0-9]*) _mn_sec="${_mn_sec#0}" ;;
                    *) break ;;
                esac
            done
            _mn_frac="${_mn_frac:-0}"
            case "$_mn_frac" in
                ''|*[!0-9]*) _mn_frac=0 ;;
            esac
            case "$_mn_frac" in
                ?) _mn_cs="${_mn_frac}0" ;;
                *) _mn_cs=$(printf '%.2s' "$_mn_frac") ;;
            esac
            case "$_mn_cs" in
                0[0-9]) _mn_cs="${_mn_cs#0}" ;;
            esac
            [ -n "$_mn_cs" ] || _mn_cs=0
            printf '%s\n' $(((_mn_sec - AGH_MONO_BASE_SEC) * 1000 + _mn_cs * 10))
            return 0
            ;;
        perl_epoch)
            case "${AGH_MONO_BASE_SEC:-}" in
                ''|*[!0-9]*) printf 'unavailable\n'; return 1 ;;
            esac
            perl -MTime::HiRes=time -e 'my $t=time(); my $b=$ENV{AGH_MONO_BASE_SEC}; printf "%.0f\n", ($t-$b)*1000;' 2>/dev/null && return 0
            printf 'unavailable\n'
            return 1
            ;;
        date_epoch)
            case "${AGH_MONO_BASE_SEC:-}" in
                ''|*[!0-9]*) printf 'unavailable\n'; return 1 ;;
            esac
            _mn_sec=$(date +%s 2>/dev/null || true)
            case "${_mn_sec:-}" in
                ''|*[!0-9]*) printf 'unavailable\n'; return 1 ;;
            esac
            while :; do
                case "$_mn_sec" in
                    0[0-9]*) _mn_sec="${_mn_sec#0}" ;;
                    *) break ;;
                esac
            done
            printf '%s\n' $(((_mn_sec - AGH_MONO_BASE_SEC) * 1000))
            return 0
            ;;
        *)
            printf 'unavailable\n'
            return 1
            ;;
    esac
}

is_signed_int() {
    case "${1:-}" in
        ''|'-') return 1 ;;
        -[0-9]*)
            _isi_rest="${1#-}"
            case "$_isi_rest" in ''|*[!0-9]*) return 1 ;; esac
            return 0
            ;;
        *[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

log_stage_timing() {
    [ -n "${AGH_SWITCH_OP_ID:-}" ] || return 0
    _lt_name="$1"
    _lt_status="$2"
    _lt_start="${3:-unavailable}"
    _lt_end="${4:-unavailable}"
    _lt_detail="${5:-}"
    _lt_src="${AGH_MONO_CLOCK_SOURCE:-unavailable}"

    if ! is_signed_int "$_lt_start" || ! is_signed_int "$_lt_end"; then
        if [ -n "$_lt_detail" ]; then
            log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=${_lt_name} status=${_lt_status} elapsed_ms=unavailable clock_error=read_failed source=${_lt_src} ${_lt_detail}"
        else
            log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=${_lt_name} status=${_lt_status} elapsed_ms=unavailable clock_error=read_failed source=${_lt_src}"
        fi
        return 0
    fi

    _lt_elapsed=$((_lt_end - _lt_start))
    if [ "$_lt_elapsed" -lt 0 ]; then
        if [ -n "$_lt_detail" ]; then
            log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=${_lt_name} status=${_lt_status} elapsed_ms=invalid clock_error=negative_delta start_ms=${_lt_start} end_ms=${_lt_end} delta_ms=${_lt_elapsed} source=${_lt_src} ${_lt_detail}"
        else
            log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=${_lt_name} status=${_lt_status} elapsed_ms=invalid clock_error=negative_delta start_ms=${_lt_start} end_ms=${_lt_end} delta_ms=${_lt_elapsed} source=${_lt_src}"
        fi
        return 0
    fi

    if [ "$_lt_status" = "ok" ] || [ "$_lt_status" = "skipped" ]; then
        if command -v agh_diag_debug_active >/dev/null 2>&1; then
            agh_diag_debug_active || return 0
        fi
    fi
    if [ -n "$_lt_detail" ]; then
        log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=${_lt_name} status=${_lt_status} elapsed_ms=${_lt_elapsed} ${_lt_detail}"
    else
        log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=${_lt_name} status=${_lt_status} elapsed_ms=${_lt_elapsed}"
    fi
}

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
    if [ "${AGH_OP_LOCK_HELD:-0}" = "1" ] && { [ "${AGH_TX_TARGET_MODE:-}" = "cn" ] || [ "${AGH_TX_TARGET_MODE:-}" = "overseas" ]; }; then
        if has_op_lock_context; then
            RUN_MODE="$AGH_TX_TARGET_MODE"
        fi
    fi
}
load_runtime_config

# ==============================================================================
# 内核 flock 能力统一探测与三步独立进程竞争自检（与 service.sh / switch_mode.sh 完全一致）
# 关键兼容性修复：Android /system/bin/sh (mksh) 会对 FD > 2 自动设置 FD_CLOEXEC，
# 因此先在当前 shell 打开长寿命描述符 (exec FD<>lockfile)，调用外部 flock 时统一通过
# 0<&FD 重定向到 FD 0 (stdin) 执行，使 dup2(FD, 0) 在子进程中合法保留内核锁绑定。
# 统一工具选择顺序：custom($FLOCK_BIN) -> busybox -> system(PATH flock) -> toybox
# ==============================================================================
FLOCK_VERIFIED=0
FLOCK_RESOLVED_KIND=""
FLOCK_RESOLVED_BIN=""
FLOCK_RESOLVED_TARGET=""
FLOCK_RESOLVED_SUBCMD=""
FLOCK_RESOLVED_IMPL=""
FLOCK_RESOLVED_ARGS="-n 0 / -u 0 (0<&FD)"
FLOCK_RESOLVED_CMD_STR=""
FLOCK_VERIFY_STEPS=""
FLOCK_LAST_DIAG=""

resolve_symlink_target() {
    bin_p="$1"
    if command -v readlink >/dev/null 2>&1; then
        t=$(readlink -f "$bin_p" 2>/dev/null || readlink "$bin_p" 2>/dev/null || true)
        [ -n "$t" ] && { printf '%s\n' "$t"; return 0; }
    fi
    printf '%s\n' "$bin_p"
}

detect_flock_impl_source() {
    c_kind="$1"
    c_bin="$2"
    c_target="$3"
    case "$c_kind" in
        busybox) echo "busybox"; return 0 ;;
        toybox)  echo "toybox"; return 0 ;;
    esac
    case "${c_bin} ${c_target}" in
        *busybox*) echo "busybox"; return 0 ;;
        *toybox*)  echo "toybox"; return 0 ;;
    esac
    h_txt=$("$c_bin" --help 2>&1 | head -n 5 || true)
    case "$h_txt" in
        *BusyBox*|*busybox*) echo "busybox"; return 0 ;;
        *Toybox*|*toybox*)   echo "toybox"; return 0 ;;
        *util-linux*)        echo "util-linux"; return 0 ;;
    esac
    if [ "$c_kind" = "custom" ]; then
        echo "custom"
    else
        echo "system"
    fi
}

exec_flock_on_fd() {
    c_bin="$1"
    c_sub="$2"
    f_flag="$3"
    f_fd="$4"
    if [ -n "$c_sub" ]; then
        case "$f_fd" in
            6) "$c_bin" "$c_sub" "$f_flag" 0 0<&6 >/dev/null 2>&1 ;;
            7) "$c_bin" "$c_sub" "$f_flag" 0 0<&7 >/dev/null 2>&1 ;;
            8) "$c_bin" "$c_sub" "$f_flag" 0 0<&8 >/dev/null 2>&1 ;;
            9) "$c_bin" "$c_sub" "$f_flag" 0 0<&9 >/dev/null 2>&1 ;;
            *) return 1 ;;
        esac
    else
        case "$f_fd" in
            6) "$c_bin" "$f_flag" 0 0<&6 >/dev/null 2>&1 ;;
            7) "$c_bin" "$f_flag" 0 0<&7 >/dev/null 2>&1 ;;
            8) "$c_bin" "$f_flag" 0 0<&8 >/dev/null 2>&1 ;;
            9) "$c_bin" "$f_flag" 0 0<&9 >/dev/null 2>&1 ;;
            *) return 1 ;;
        esac
    fi
}

run_flock_nb() {
    verify_flock_support >/dev/null 2>&1 || return 1
    exec_flock_on_fd "$FLOCK_RESOLVED_BIN" "$FLOCK_RESOLVED_SUBCMD" -n "$1"
}

run_flock_unlock() {
    [ "$FLOCK_VERIFIED" = "1" ] || return 0
    exec_flock_on_fd "$FLOCK_RESOLVED_BIN" "$FLOCK_RESOLVED_SUBCMD" -u "$1"
}

is_file_kernel_locked() {
    chk_file="$1"
    [ -e "$chk_file" ] || return 1
    verify_flock_support >/dev/null 2>&1 || return 2
    (
        exec 6<>"$chk_file" 2>/dev/null || exit 2
        if run_flock_nb 6; then
            run_flock_unlock 6 || true
            exec 6<&- 6>&- 2>/dev/null || true
            exit 1
        fi
        exec 6<&- 6>&- 2>/dev/null || true
        exit 0
    ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&-
}

test_flock_candidate_3step() {
    c_kind="$1"
    c_bin="$2"
    c_sub="$3"
    c_target=$(resolve_symlink_target "$c_bin")
    c_impl=$(detect_flock_impl_source "$c_kind" "$c_bin" "$c_target")
    if [ -n "$c_sub" ]; then
        c_cmd="${c_bin} ${c_sub} -n 0 0<&FD"
    else
        c_cmd="${c_bin} -n 0 0<&FD"
    fi

    probe_f="$RUN_DIR/.agh_flock_verify.$$.${c_kind}"
    probe_ready="${probe_f}.ready"
    probe_release="${probe_f}.release"
    rm -f "$probe_f" "$probe_ready" "$probe_release" 2>/dev/null

    "$SH_BIN" -c '
        pf="$1"; ready="$2"; rel="$3"; cbin="$4"; csub="$5"; bb="$6"
        exec 7<>"$pf" 2>/dev/null || exit 11
        if [ -n "$csub" ]; then
            "$cbin" "$csub" -n 0 0<&7 >/dev/null 2>&1 || { exec 7<&- 7>&- 2>/dev/null || true; exit 12; }
        else
            "$cbin" -n 0 0<&7 >/dev/null 2>&1 || { exec 7<&- 7>&- 2>/dev/null || true; exit 12; }
        fi
        printf "%s\n" "$$" > "$ready" 2>/dev/null || { exec 7<&- 7>&- 2>/dev/null || true; exit 13; }
        w=0
        while [ ! -f "$rel" ] && [ "$w" -lt 60 ]; do
            sleep 0.05 2>/dev/null || { [ -n "$bb" ] && "$bb" sleep 0.05 2>/dev/null; } || /system/bin/toybox sleep 0.05 2>/dev/null || sleep 1
            w=$((w + 1))
        done
        if [ -n "$csub" ]; then
            "$cbin" "$csub" -u 0 0<&7 >/dev/null 2>&1 || true
        else
            "$cbin" -u 0 0<&7 >/dev/null 2>&1 || true
        fi
        exec 7<&- 7>&- 2>/dev/null || true
        exit 0
    ' _ "$probe_f" "$probe_ready" "$probe_release" "$c_bin" "$c_sub" "${BB_BIN:-}" </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
    p1_pid=$!

    w_rdy=0
    while [ ! -f "$probe_ready" ] && kill -0 "$p1_pid" 2>/dev/null && [ "$w_rdy" -lt 40 ]; do
        safe_sleep 0.05 || sleep 1 7>&- 8>&- 9>&-
        w_rdy=$((w_rdy + 1))
    done

    step1_rc="1"
    step2_rc="skip"
    step3_rc="skip"

    if [ ! -f "$probe_ready" ]; then
        : > "$probe_release" 2>/dev/null
        w_exit=0
        while kill -0 "$p1_pid" 2>/dev/null && [ "$w_exit" -lt 20 ]; do
            safe_sleep 0.05 || sleep 1 7>&- 8>&- 9>&-
            w_exit=$((w_exit + 1))
        done
        kill -0 "$p1_pid" 2>/dev/null && kill -9 "$p1_pid" 2>/dev/null || true
        wait "$p1_pid" 2>/dev/null
        step1_rc=$?
        [ "$step1_rc" -eq 0 ] && step1_rc=1
        rm -f "$probe_f" "$probe_ready" "$probe_release" 2>/dev/null
        LAST_CAND_REPORT="${c_kind}[${c_impl}]:${c_cmd}|step1=${step1_rc},step2=${step2_rc},step3=${step3_rc}"
        return 1
    fi

    "$SH_BIN" -c '
        pf="$1"; cbin="$2"; csub="$3"
        exec 7<>"$pf" 2>/dev/null || exit 21
        if [ -n "$csub" ]; then
            if "$cbin" "$csub" -n 0 0<&7 >/dev/null 2>&1; then
                "$cbin" "$csub" -u 0 0<&7 >/dev/null 2>&1 || true
                exec 7<&- 7>&- 2>/dev/null || true
                exit 0
            fi
        else
            if "$cbin" -n 0 0<&7 >/dev/null 2>&1; then
                "$cbin" -u 0 0<&7 >/dev/null 2>&1 || true
                exec 7<&- 7>&- 2>/dev/null || true
                exit 0
            fi
        fi
        exec 7<&- 7>&- 2>/dev/null || true
        exit 1
    ' _ "$probe_f" "$c_bin" "$c_sub" </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&-
    step2_rc=$?

    : > "$probe_release" 2>/dev/null
    w_exit=0
    while kill -0 "$p1_pid" 2>/dev/null && [ "$w_exit" -lt 20 ]; do
        safe_sleep 0.05 || sleep 1 7>&- 8>&- 9>&-
        w_exit=$((w_exit + 1))
    done
    kill -0 "$p1_pid" 2>/dev/null && kill -9 "$p1_pid" 2>/dev/null || true
    wait "$p1_pid" 2>/dev/null
    step1_rc=$?

    "$SH_BIN" -c '
        pf="$1"; cbin="$2"; csub="$3"
        exec 7<>"$pf" 2>/dev/null || exit 31
        if [ -n "$csub" ]; then
            "$cbin" "$csub" -n 0 0<&7 >/dev/null 2>&1 || { exec 7<&- 7>&- 2>/dev/null || true; exit 1; }
            "$cbin" "$csub" -u 0 0<&7 >/dev/null 2>&1 || true
        else
            "$cbin" -n 0 0<&7 >/dev/null 2>&1 || { exec 7<&- 7>&- 2>/dev/null || true; exit 1; }
            "$cbin" -u 0 0<&7 >/dev/null 2>&1 || true
        fi
        exec 7<&- 7>&- 2>/dev/null || true
        exit 0
    ' _ "$probe_f" "$c_bin" "$c_sub" </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&-
    step3_rc=$?

    rm -f "$probe_f" "$probe_ready" "$probe_release" 2>/dev/null
    LAST_CAND_REPORT="${c_kind}[${c_impl}]:${c_cmd}|step1=${step1_rc},step2=${step2_rc},step3=${step3_rc}"

    if [ "$step1_rc" -eq 0 ] && [ "$step2_rc" -eq 1 ] && [ "$step3_rc" -eq 0 ]; then
        FLOCK_VERIFIED=1
        FLOCK_RESOLVED_KIND="$c_kind"
        FLOCK_RESOLVED_BIN="$c_bin"
        FLOCK_RESOLVED_TARGET="$c_target"
        FLOCK_RESOLVED_SUBCMD="$c_sub"
        FLOCK_RESOLVED_IMPL="$c_impl"
        FLOCK_RESOLVED_CMD_STR="$c_cmd"
        FLOCK_VERIFY_STEPS="step1=${step1_rc},step2=${step2_rc},step3=${step3_rc}"
        return 0
    fi
    return 1
}

try_reuse_parent_verified_flock() {
    [ -n "${AGH_DIAG_VERIFIED_FLOCK_BIN:-}" ] || return 1
    _r_kind=""
    _r_bin=""
    _r_sub=""
    if [ -n "${FLOCK_BIN:-}" ] && [ -x "$FLOCK_BIN" ]; then
        _r_kind="custom"; _r_bin="$FLOCK_BIN"; _r_sub=""
    elif [ -n "${BB_BIN:-}" ] && [ -x "$BB_BIN" ]; then
        _r_kind="busybox"; _r_bin="$BB_BIN"; _r_sub="flock"
    else
        _r_sys=$(command -v flock 2>/dev/null || true)
        if [ -n "$_r_sys" ] && [ -x "$_r_sys" ]; then
            _r_kind="system"; _r_bin="$_r_sys"; _r_sub=""
        else
            _r_tb="/system/bin/toybox"
            [ -x "$_r_tb" ] || _r_tb=$(command -v toybox 2>/dev/null || true)
            if [ -n "$_r_tb" ] && [ -x "$_r_tb" ]; then
                _r_kind="toybox"; _r_bin="$_r_tb"; _r_sub="flock"
            fi
        fi
    fi
    [ -n "$_r_bin" ] || return 1
    [ "$_r_bin" = "${AGH_DIAG_VERIFIED_FLOCK_BIN:-}" ] || return 1
    [ "$_r_sub" = "${AGH_DIAG_VERIFIED_FLOCK_SUBCMD:-}" ] || return 1

    _r_target=$(resolve_symlink_target "$_r_bin")
    _r_impl=$(detect_flock_impl_source "$_r_kind" "$_r_bin" "$_r_target")
    if [ -n "$_r_sub" ]; then
        _r_cmd="${_r_bin} ${_r_sub} -n 0 0<&FD"
    else
        _r_cmd="${_r_bin} -n 0 0<&FD"
    fi

    FLOCK_VERIFIED=1
    FLOCK_RESOLVED_KIND="$_r_kind"
    FLOCK_RESOLVED_BIN="$_r_bin"
    FLOCK_RESOLVED_TARGET="$_r_target"
    FLOCK_RESOLVED_SUBCMD="$_r_sub"
    FLOCK_RESOLVED_IMPL="$_r_impl"
    FLOCK_RESOLVED_CMD_STR="$_r_cmd"
    FLOCK_VERIFY_STEPS="${AGH_DIAG_VERIFIED_FLOCK_STEPS:-step1=0,step2=1,step3=0}"
    return 0
}

verify_flock_support() {
    [ "$FLOCK_VERIFIED" = "1" ] && return 0
    if [ -n "${AGH_DIAG_VERIFIED_FLOCK_BIN:-}" ] && try_reuse_parent_verified_flock; then
        return 0
    fi
    FLOCK_LAST_DIAG=""

    if [ -n "${FLOCK_BIN:-}" ] && [ -x "$FLOCK_BIN" ]; then
        if test_flock_candidate_3step "custom" "$FLOCK_BIN" ""; then
            return 0
        fi
        FLOCK_LAST_DIAG="${FLOCK_LAST_DIAG:+${FLOCK_LAST_DIAG}; }${LAST_CAND_REPORT}"
    fi

    if [ -n "${BB_BIN:-}" ] && [ -x "$BB_BIN" ]; then
        if test_flock_candidate_3step "busybox" "$BB_BIN" "flock"; then
            return 0
        fi
        FLOCK_LAST_DIAG="${FLOCK_LAST_DIAG:+${FLOCK_LAST_DIAG}; }${LAST_CAND_REPORT}"
    fi

    sys_flock=$(command -v flock 2>/dev/null || true)
    if [ -n "$sys_flock" ] && [ -x "$sys_flock" ]; then
        if test_flock_candidate_3step "system" "$sys_flock" ""; then
            return 0
        fi
        FLOCK_LAST_DIAG="${FLOCK_LAST_DIAG:+${FLOCK_LAST_DIAG}; }${LAST_CAND_REPORT}"
    fi

    toybox_bin="/system/bin/toybox"
    [ -x "$toybox_bin" ] || toybox_bin=$(command -v toybox 2>/dev/null || true)
    if [ -n "$toybox_bin" ] && [ -x "$toybox_bin" ]; then
        if test_flock_candidate_3step "toybox" "$toybox_bin" "flock"; then
            return 0
        fi
        FLOCK_LAST_DIAG="${FLOCK_LAST_DIAG:+${FLOCK_LAST_DIAG}; }${LAST_CAND_REPORT}"
    fi

    [ -n "$FLOCK_LAST_DIAG" ] || FLOCK_LAST_DIAG="no_flock_binary_found"
    log_msg "[FATAL] ${SCRIPT_LABEL}: 当前环境 flock 排他语义自检未通过，拒绝无锁继续 (${FLOCK_LAST_DIAG})"
    return 1
}

OP_LOCK_OWNED=0
OP_LOCK_INHERITED=0
ABORTED_BY_SIGNAL=0
ACTIVE_CHILD_PID=""

is_trusted_flock_bin() {
    cand_p="${1:-}"
    [ -n "$cand_p" ] && [ -x "$cand_p" ] || return 1
    [ "$cand_p" = "${FLOCK_BIN:-}" ] && return 0
    [ "$cand_p" = "${BB_BIN:-}" ] && return 0
    sys_f=$(command -v flock 2>/dev/null || true)
    [ -n "$sys_f" ] && [ "$cand_p" = "$sys_f" ] && return 0
    [ "$cand_p" = "/system/bin/toybox" ] && return 0
    path_tb=$(command -v toybox 2>/dev/null || true)
    [ -n "$path_tb" ] && [ "$cand_p" = "$path_tb" ] && return 0
    return 1
}

PARENT_LOCK_VERIFIED=0
verify_parent_op_lock_held() {
    [ "${AGH_OP_LOCK_HELD:-0}" = "1" ] || return 1
    parent_holder="${AGH_OP_LOCK_HOLDER_PID:-}"
    case "$parent_holder" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if ! kill -0 "$parent_holder" 2>/dev/null && [ ! -d "$PROC_DIR/$parent_holder" ]; then
        return 1
    fi
    diag_pid=$(cat "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null | tr -d '\r[:space:]')
    [ "$diag_pid" = "$parent_holder" ] || return 1
    if [ "$PARENT_LOCK_VERIFIED" = "1" ]; then
        return 0
    fi
    if [ "$FLOCK_VERIFIED" != "1" ] && is_trusted_flock_bin "${AGH_TX_FLOCK_BIN:-}"; then
        FLOCK_RESOLVED_BIN="$AGH_TX_FLOCK_BIN"
        FLOCK_RESOLVED_SUBCMD="${AGH_TX_FLOCK_SUBCMD:-}"
        FLOCK_RESOLVED_KIND="${AGH_TX_FLOCK_KIND:-system}"
        FLOCK_RESOLVED_IMPL="${AGH_TX_FLOCK_IMPL:-system}"
        FLOCK_RESOLVED_TARGET="${AGH_TX_FLOCK_TARGET:-$AGH_TX_FLOCK_BIN}"
        FLOCK_RESOLVED_CMD_STR="${AGH_TX_FLOCK_CMD_STR:-}"
        FLOCK_VERIFY_STEPS="${AGH_TX_FLOCK_VERIFY_STEPS:-inherited}"
        FLOCK_VERIFIED=1
        if ! is_file_kernel_locked "$OP_LOCK_FILE"; then
            FLOCK_VERIFIED=0
            verify_flock_support >/dev/null 2>&1 || return 1
            is_file_kernel_locked "$OP_LOCK_FILE" || return 1
        fi
    else
        verify_flock_support >/dev/null 2>&1 || return 1
        is_file_kernel_locked "$OP_LOCK_FILE" || return 1
    fi
    PARENT_LOCK_VERIFIED=1
    return 0
}

has_op_lock_context() {
    [ "$OP_LOCK_OWNED" = "1" ] && return 0
    verify_parent_op_lock_held && return 0
    return 1
}

diagnose_op_lock_timeout() {
    wait_secs="${1:-15}"
    kernel_locked="no"
    if [ -e "$OP_LOCK_FILE" ] && is_file_kernel_locked "$OP_LOCK_FILE"; then
        kernel_locked="yes"
    fi

    holder_pid="unknown"
    diag_reason=""
    if [ ! -e "$OP_LOCK_DIAG_PID_FILE" ]; then
        if [ "$kernel_locked" = "yes" ]; then
            diag_reason="检测到锁被占用，且没有诊断记录 (no_diag_record)"
        else
            diag_reason="没有诊断记录，且当前锁已释放 (no_diag_record, lock_free)"
        fi
    elif [ ! -r "$OP_LOCK_DIAG_PID_FILE" ]; then
        if [ "$kernel_locked" = "yes" ]; then
            diag_reason="检测到锁被占用，但诊断记录不可读 (diag_unreadable)"
        else
            diag_reason="诊断记录不可读，且当前锁未占用 (diag_unreadable)"
        fi
    else
        raw_pid=$(cat "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null)
        cat_rc=$?
        raw_pid=$(printf '%s' "$raw_pid" | tr -d '\r[:space:]')
        if [ "$cat_rc" -ne 0 ]; then
            if [ "$kernel_locked" = "yes" ]; then
                diag_reason="检测到锁被占用，但读取诊断记录失败 (diag_unreadable)"
            else
                diag_reason="诊断记录不可读 (diag_unreadable)"
            fi
        elif [ -z "$raw_pid" ]; then
            if [ "$kernel_locked" = "yes" ]; then
                diag_reason="检测到锁被占用，但诊断记录为空 (no_diag_record)"
            else
                diag_reason="没有诊断记录(文件为空) (no_diag_record)"
            fi
        else
            case "$raw_pid" in
                *[!0-9]*)
                    if [ "$kernel_locked" = "yes" ]; then
                        diag_reason="检测到锁被占用，诊断记录格式异常 (diag_invalid)"
                    else
                        diag_reason="诊断记录格式异常 (diag_invalid)"
                    fi
                    ;;
                *)
                    holder_pid="$raw_pid"
                    if kill -0 "$holder_pid" 2>/dev/null || [ -d "$PROC_DIR/$holder_pid" ]; then
                        if [ "$kernel_locked" = "yes" ]; then
                            diag_reason="检测到锁被占用，持有进程存活 (lock_held_by_active_pid)"
                        else
                            diag_reason="诊断进程存活但内核锁当前空闲 (pid_alive_lock_free)"
                        fi
                    else
                        if [ "$kernel_locked" = "yes" ]; then
                            diag_reason="检测到锁被占用，但记录的PID不在进程表中 (lock_held_pid_missing)"
                        else
                            diag_reason="诊断PID已退出且锁已空闲 (stale_pid_lock_free)"
                        fi
                    fi
                    ;;
            esac
        fi
    fi

    log_msg "[WARN] ${SCRIPT_LABEL}: timed out waiting for operation lock (lock_file=${OP_LOCK_FILE}, flock_cmd=\"${FLOCK_RESOLVED_CMD_STR}\", waited=${wait_secs}s, holder_pid=${holder_pid}, kernel_locked=${kernel_locked}, reason=${diag_reason})"
}

acquire_op_lock() {
    max_wait="${1:-15}"
    [ "$ABORTED_BY_SIGNAL" = "1" ] && return 1
    if [ "$OP_LOCK_OWNED" = "1" ]; then
        return 0
    fi
    if [ "${AGH_OP_LOCK_HELD:-0}" = "1" ]; then
        if verify_parent_op_lock_held; then
            OP_LOCK_OWNED=0
            OP_LOCK_INHERITED=1
            return 0
        fi
        log_msg "[ERROR] ${SCRIPT_LABEL}: 检测到父进程锁继承标记 (AGH_OP_LOCK_HELD=1)，但未能验证父进程 (${AGH_OP_LOCK_HOLDER_PID:-unknown}) 实际持有操作锁，拒绝继承。"
        return 1
    fi
    verify_flock_support || return 1
    exec 9<>"$OP_LOCK_FILE" 2>/dev/null || {
        log_msg "[ERROR] ${SCRIPT_LABEL}: 无法打开操作锁文件 ${OP_LOCK_FILE}"
        return 1
    }
    waited=0
    step_max=$((max_wait * 5))
    [ "$step_max" -lt 1 ] && step_max=1
    while [ "$waited" -lt "$step_max" ]; do
        if [ "$ABORTED_BY_SIGNAL" = "1" ]; then
            exec 9>&- 2>/dev/null || true
            return 1
        fi
        if run_flock_nb 9; then
            OP_LOCK_OWNED=1
            OP_LOCK_INHERITED=0
            export AGH_OP_LOCK_HELD=1
            export AGH_OP_LOCK_HOLDER_PID="$$"
            printf '%s\n' "$$" > "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null
            return 0
        fi
        if safe_sleep 0.2; then
            waited=$((waited + 1))
        else
            sleep 1 7>&- 8>&- 9>&-
            waited=$((waited + 5))
        fi
    done
    exec 9>&- 2>/dev/null || true
    diagnose_op_lock_timeout "$max_wait"
    return 1
}

release_op_lock() {
    if [ "$OP_LOCK_OWNED" = "1" ]; then
        if [ "$(cat "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null | tr -d '\r[:space:]')" = "$$" ]; then
            rm -f "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null
        fi
        run_flock_unlock 9 || true
        exec 9>&- 2>/dev/null || true
        OP_LOCK_OWNED=0
        OP_LOCK_INHERITED=0
        unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID \
              AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE \
              AGH_TX_FLOCK_BIN AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_KIND AGH_TX_FLOCK_IMPL \
              AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS \
              AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED
    fi
}

terminate_active_child() {
    if [ -n "$ACTIVE_CHILD_PID" ]; then
        cpid="$ACTIVE_CHILD_PID"
        ACTIVE_CHILD_PID=""
        if kill -0 "$cpid" 2>/dev/null; then
            kill -TERM "$cpid" 2>/dev/null || true
            for _w in 1 2 3 4 5 6 7 8 9 10; do
                kill -0 "$cpid" 2>/dev/null || break
                safe_sleep 0.1 || sleep 1 7>&- 8>&- 9>&-
            done
            kill -0 "$cpid" 2>/dev/null && kill -KILL "$cpid" 2>/dev/null || true
            wait "$cpid" 2>/dev/null || true
        fi
    fi
}

on_script_exit() {
    terminate_active_child
    release_op_lock
}

on_signal_abort() {
    sig_name="${1:-TERM}"
    ABORTED_BY_SIGNAL=1
    trap - EXIT INT TERM
    log_msg "[WARN] ${SCRIPT_LABEL} (PID $$) received $sig_name, terminating active child and aborting."
    terminate_active_child
    release_op_lock
    exit 143
}

diagnose_flock_state() {
    brief_arg="${1:-}"
    if ! verify_flock_support; then
        if [ "$brief_arg" = "--brief" ]; then
            printf 'FLOCK_BRIEF script=%s status=FAIL impl=none bin=none cmd="" verify_steps=fail diag="%s"\n' \
                "$SCRIPT_LABEL" "$FLOCK_LAST_DIAG"
        else
            printf 'AGH_FLOCK_DIAG script=%s status=FAIL reason=no_compatible_flock diag="%s"\n' \
                "$SCRIPT_LABEL" "$FLOCK_LAST_DIAG"
        fi
        return 1
    fi
    if [ "$brief_arg" = "--brief" ]; then
        printf 'FLOCK_BRIEF script=%s status=PASS impl=%s bin=%s target=%s args="%s" verify_steps=%s\n' \
            "$SCRIPT_LABEL" "$FLOCK_RESOLVED_IMPL" "$FLOCK_RESOLVED_BIN" "$FLOCK_RESOLVED_TARGET" \
            "$FLOCK_RESOLVED_ARGS" "$FLOCK_VERIFY_STEPS"
        return 0
    fi
    printf 'RUN_PATHS run_dir=%s op_lock_file=%s op_diag_pid_file=%s\n' "$RUN_DIR" "$OP_LOCK_FILE" "$OP_LOCK_DIAG_PID_FILE"
    printf 'SELECTED_FLOCK script=%s kind=%s impl=%s bin=%s target=%s subcmd="%s" args="%s" cmd="%s" verify_steps=%s\n' \
        "$SCRIPT_LABEL" "$FLOCK_RESOLVED_KIND" "$FLOCK_RESOLVED_IMPL" "$FLOCK_RESOLVED_BIN" \
        "$FLOCK_RESOLVED_TARGET" "${FLOCK_RESOLVED_SUBCMD:-none}" "$FLOCK_RESOLVED_ARGS" \
        "$FLOCK_RESOLVED_CMD_STR" "$FLOCK_VERIFY_STEPS"
    printf 'AGH_FLOCK_DIAG script=%s status=PASS impl=%s bin=%s\n' \
        "$SCRIPT_LABEL" "$FLOCK_RESOLVED_IMPL" "$FLOCK_RESOLVED_BIN"
    return 0
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
    while ip6tables -w 2 -D OUTPUT -p tcp --dport 853 -j DROP 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 853 -j DROP 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 53 -j DROP 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p tcp --dport 53 -j DROP 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null; do :; done
    while ip6tables -w 2 -D OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null; do :; done
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

# 首包级低功耗 mangle 表 SNI 队列规则（仅查 TLS 握手前 8 包 + 强制 --queue-bypass + 严禁修改任何 sysctl 内核参数）
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
        rm -f "$SNI_QUEUE_NUM_FILE" 2>/dev/null
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
    v4_sni_gid_ok=0
    if iptables -w 2 -t mangle -A AGH_SNI -m owner --gid-owner "$AGH_GID" -j RETURN 2>/dev/null; then
        v4_sni_gid_ok=1
    fi
    for auid in $allow_uids; do
        iptables -w 2 -t mangle -A AGH_SNI -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
    done
    for net in $LAN_BYPASS_IPV4; do
        iptables -w 2 -t mangle -A AGH_SNI -d "$net" -j RETURN || return 1
    done
    v4_ports_ok=0
    v4_ports_fail=0
    v4_connbytes_ok=0
    for sni_port in 443 8443; do
        if iptables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
            -m connbytes --connbytes 1:8 --connbytes-dir original --connbytes-mode packets \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
            v4_ports_ok=$((v4_ports_ok + 1))
            v4_connbytes_ok=$((v4_connbytes_ok + 1))
        elif iptables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
            -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
            v4_ports_ok=$((v4_ports_ok + 1))
        else
            v4_ports_fail=$((v4_ports_fail + 1))
        fi
    done

    if [ "$v4_ports_ok" -eq 0 ]; then
        # 内核完全不支持 IPv4 mangle NFQUEUE：作为可选能力按 unsupported 处理
        clean_sni_rules
        echo "unsupported" > "$SNI_FW_MODE_FILE" 2>/dev/null
        rm -f "$SNI_QUEUE_NUM_FILE" 2>/dev/null
        return 0
    fi
    if [ "$v4_ports_fail" -ne 0 ] || [ "$v4_sni_gid_ok" -ne 1 ]; then
        # 部分端口失败或缺少核心 GID 豁免属于半残挂载，严禁伪报成功
        clean_sni_rules
        return 1
    fi

    if [ "$v4_connbytes_ok" -eq 2 ]; then
        v4_sni_mode="connbytes"
    else
        v4_sni_mode="fallback"
    fi
    if ! (iptables -w 2 -t mangle -C OUTPUT -j AGH_SNI 2>/dev/null || \
          iptables -w 2 -t mangle -I OUTPUT 1 -j AGH_SNI); then
        clean_sni_rules
        return 1
    fi
    echo "$v4_sni_mode" > "$SNI_FW_MODE_FILE" 2>/dev/null
    printf '%s\n' "$sni_queue" > "$SNI_QUEUE_NUM_FILE" 2>/dev/null

    # --- IPv6 mangle 表 AGH_SNI 链配置（仅当内核支持 mangle AGH_SNI 时执行规则注入） ---
    ip6tables -w 2 -t mangle -N AGH_SNI 2>/dev/null
    if ip6tables -w 2 -t mangle -F AGH_SNI 2>/dev/null; then
        v6_gid_ok=0
        ip6tables -w 2 -t mangle -A AGH_SNI -o lo -j RETURN 2>/dev/null
        ip6tables -w 2 -t mangle -A AGH_SNI -m owner --gid-owner "$AGH_GID" -j RETURN 2>/dev/null && v6_gid_ok=1
        for auid in $allow_uids; do
            ip6tables -w 2 -t mangle -A AGH_SNI -m owner --uid-owner "$auid" -j RETURN 2>/dev/null
        done
        for net in $LAN_BYPASS_IPV6; do
            ip6tables -w 2 -t mangle -A AGH_SNI -d "$net" -j RETURN 2>/dev/null
        done
        v6_ports_ok=0
        for sni_port in 443 8443; do
            if ip6tables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
                -m connbytes --connbytes 1:8 --connbytes-dir original --connbytes-mode packets \
                -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
                v6_ports_ok=$((v6_ports_ok + 1))
            elif ip6tables -w 2 -t mangle -A AGH_SNI -p tcp --dport "$sni_port" \
                -j NFQUEUE --queue-num "$sni_queue" --queue-bypass 2>/dev/null; then
                v6_ports_ok=$((v6_ports_ok + 1))
            fi
        done
        if [ "$v6_gid_ok" -eq 1 ] && [ "$v6_ports_ok" -eq 2 ]; then
            ip6tables -w 2 -t mangle -C OUTPUT -j AGH_SNI 2>/dev/null || \
                ip6tables -w 2 -t mangle -I OUTPUT 1 -j AGH_SNI 2>/dev/null
        else
            while ip6tables -w 2 -t mangle -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
            ip6tables -w 2 -t mangle -F AGH_SNI 2>/dev/null
            ip6tables -w 2 -t mangle -X AGH_SNI 2>/dev/null
        fi
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
    if ip6tables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null; then
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
    fi
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

    sys_net_dir="${AGH_SYS_NET_DIR:-/sys/class/net}"
    has_vpn=0
    for iface in "$sys_net_dir"/tun* "$sys_net_dir"/wg* "$sys_net_dir"/ppp*; do
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

    op_country=$(getprop gsm.operator.iso-country 2>/dev/null 7>&- 8>&- 9>&- | tr 'A-Z' 'a-z')
    op_mcc=$(getprop gsm.operator.numeric 2>/dev/null 7>&- 8>&- 9>&-)
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
    v6_nat_ready=0
    ip6tables -w 2 -t nat -N ADGUARD6_NAT 2>/dev/null
    if ip6tables -w 2 -t nat -F ADGUARD6_NAT 2>/dev/null; then
        v6_nat_gid_ok=0
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -d ::1/128 -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -d ::1/128 -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null
        ip6tables -w 2 -t nat -A ADGUARD6_NAT -m owner --uid-owner 0 --gid-owner "$AGH_GID" -j RETURN 2>/dev/null && v6_nat_gid_ok=1
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
        if [ "$v6_nat_gid_ok" -eq 1 ] && \
           ip6tables -w 2 -t nat -A ADGUARD6_NAT -p udp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null && \
           ip6tables -w 2 -t nat -A ADGUARD6_NAT -p tcp --dport 53 -j REDIRECT --to-ports "$redir_port" 2>/dev/null; then
            v6_nat_ready=1
        fi
    fi

    if [ "$v6_nat_ready" -eq 1 ]; then
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
    if ip6tables -w 2 -t filter -F AGH_INPUT 2>/dev/null; then
        ip6tables -w 2 -t filter -A AGH_INPUT -i lo -j RETURN 2>/dev/null
        ip6tables -w 2 -t filter -A AGH_INPUT -p udp --dport "$redir_port" -j DROP 2>/dev/null
        ip6tables -w 2 -t filter -A AGH_INPUT -p tcp --dport "$redir_port" -j DROP 2>/dev/null
        ip6tables -w 2 -t filter -I INPUT 1 -j AGH_INPUT 2>/dev/null
    fi

    rebuild_dot_guard "$takeover_vpn" "$allow_uids" || return 1
    rebuild_sni "$allow_uids" || return 1
    return 0
}

# 挂载后完整性校验（覆盖并强于 service.sh nat_rules_healthy，作为单次权威应用后检查）
post_apply_check() {
    port_chk="${1:-$redir_port}"
    nat_out_dump=$(iptables -w 2 -t nat -S OUTPUT 2>/dev/null) || return 1
    out_jumps=$(printf '%s\n' "$nat_out_dump" | grep -c -- '^-A OUTPUT -j ADGUARD$')
    [ "$out_jumps" -eq 1 ] || return 1

    chain_rules=$(iptables -w 2 -t nat -S ADGUARD 2>/dev/null) || return 1
    [ -n "$chain_rules" ] || return 1
    printf '%s\n' "$chain_rules" | grep -qE -- "^-A ADGUARD -d 127\.0\.0\.1(/32)? .*-p udp .*--dport 53 .*-j REDIRECT --to-ports ${port_chk}([[:space:]]|\$)" || return 1
    printf '%s\n' "$chain_rules" | grep -qE -- "^-A ADGUARD -d 127\.0\.0\.1(/32)? .*-p tcp .*--dport 53 .*-j REDIRECT --to-ports ${port_chk}([[:space:]]|\$)" || return 1
    adg_gid_ln=$(printf '%s\n' "$chain_rules" | grep -n -- "--gid-owner $AGH_GID -j RETURN" | head -n 1 | cut -d: -f1)
    [ -n "$adg_gid_ln" ] || return 1
    adg_udp_ln=$(printf '%s\n' "$chain_rules" | grep -nE -- "^-A ADGUARD -p udp .*--dport 53 .*-j REDIRECT --to-ports ${port_chk}([[:space:]]|\$)" | head -n 1 | cut -d: -f1)
    adg_tcp_ln=$(printf '%s\n' "$chain_rules" | grep -nE -- "^-A ADGUARD -p tcp .*--dport 53 .*-j REDIRECT --to-ports ${port_chk}([[:space:]]|\$)" | head -n 1 | cut -d: -f1)
    [ -n "$adg_udp_ln" ] && [ -n "$adg_tcp_ln" ] || return 1
    [ "$adg_gid_ln" -lt "$adg_udp_ln" ] && [ "$adg_gid_ln" -lt "$adg_tcp_ln" ] || return 1

    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 || return 1
    iptables -w 2 -t filter -C INPUT -j AGH_INPUT >/dev/null 2>&1 || return 1

    v6_mode=$(cat "$IPV6_DNS_MODE_FILE" 2>/dev/null)
    case "$v6_mode" in
        nat)
            ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT >/dev/null 2>&1 || return 1
            adg6_chain=$(ip6tables -w 2 -t nat -S ADGUARD6_NAT 2>/dev/null) || return 1
            adg6_gid_ln=$(printf '%s\n' "$adg6_chain" | grep -n -- "--gid-owner $AGH_GID -j RETURN" | head -n 1 | cut -d: -f1)
            [ -n "$adg6_gid_ln" ] || return 1
            adg6_udp_ln=$(printf '%s\n' "$adg6_chain" | grep -nE -- "^-A ADGUARD6_NAT -p udp .*--dport 53 .*-j REDIRECT --to-ports ${port_chk}([[:space:]]|\$)" | head -n 1 | cut -d: -f1)
            adg6_tcp_ln=$(printf '%s\n' "$adg6_chain" | grep -nE -- "^-A ADGUARD6_NAT -p tcp .*--dport 53 .*-j REDIRECT --to-ports ${port_chk}([[:space:]]|\$)" | head -n 1 | cut -d: -f1)
            [ -n "$adg6_udp_ln" ] && [ -n "$adg6_tcp_ln" ] || return 1
            [ "$adg6_gid_ln" -lt "$adg6_udp_ln" ] && [ "$adg6_gid_ln" -lt "$adg6_tcp_ln" ] || return 1
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
            exp_sni_queue=$(sed -n 's/^[[:space:]]*queue_num:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
                "$BIN_DIR/AdGuardHome.yaml" 2>/dev/null | head -n 1)
            [ -n "$exp_sni_queue" ] || exp_sni_queue=0

            mangle_out=$(iptables -w 2 -t mangle -S OUTPUT 2>/dev/null) || return 1
            sni_jump_cnt=$(printf '%s\n' "$mangle_out" | grep -c -- '^-A OUTPUT -j AGH_SNI$')
            [ "$sni_jump_cnt" -eq 1 ] || return 1

            sni_chain=$(iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null) || return 1
            [ -n "$sni_chain" ] || return 1

            sni_gid_ln=$(printf '%s\n' "$sni_chain" | grep -nE -- "^-A AGH_SNI .*-m owner .*--gid-owner ${AGH_GID}([[:space:]]|\$).*-j RETURN([[:space:]]|\$)" | head -n 1 | cut -d: -f1)
            first_nfq_ln=$(printf '%s\n' "$sni_chain" | grep -nE -- "-j NFQUEUE([[:space:]]|\$)" | head -n 1 | cut -d: -f1)
            [ -n "$sni_gid_ln" ] && [ -n "$first_nfq_ln" ] || return 1
            [ "$sni_gid_ln" -lt "$first_nfq_ln" ] || return 1

            for chk_sni_port in 443 8443; do
                port_rule=$(printf '%s\n' "$sni_chain" | grep -E -- "^-A AGH_SNI -p tcp .*--dport ${chk_sni_port}([[:space:]]|\$)" | grep -E -- "-j NFQUEUE([[:space:]]|\$)" | head -n 1)
                [ -n "$port_rule" ] || return 1
                if [ "$exp_sni_queue" = "0" ]; then
                    # queue_num=0 为 NFQUEUE 默认队列，Linux/Android iptables -S 默认省略 --queue-num 0；仅需确保未挂载到非 0 队列
                    printf '%s\n' "$port_rule" | grep -qE -- "--queue-num [1-9][0-9]*" && return 1
                else
                    printf '%s\n' "$port_rule" | grep -qE -- "--queue-num ${exp_sni_queue}([[:space:]]|\$)" || return 1
                fi
                printf '%s\n' "$port_rule" | grep -qE -- "--queue-bypass([[:space:]]|\$)" || return 1
                if [ "$sni_mode" = "connbytes" ]; then
                    printf '%s\n' "$port_rule" | grep -q -- "connbytes" || return 1
                    printf '%s\n' "$port_rule" | grep -q -- "1:8" || return 1
                fi
            done
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
    rm -f "$AGH_DIR/app_pause_active" "$AGH_DIR/vpn_mode_status" "$IPV6_DNS_MODE_FILE" "$SNI_FW_MODE_FILE" "$SNI_QUEUE_NUM_FILE" 2>/dev/null

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
        ndc resolver flushenv >/dev/null 2>&1 7>&- 8>&- 9>&- && flushed=1
        ndc resolver flushdefaultif >/dev/null 2>&1 7>&- 8>&- 9>&- && flushed=1
    fi
    if command -v cmd >/dev/null 2>&1; then
        cmd netd resolver flushdefaultif >/dev/null 2>&1 7>&- 8>&- 9>&- && flushed=1
    fi
    [ "$flushed" -eq 1 ] && return 0
    return 1
}

# 挂载前健康预检 (Pre-flight Check：确认核心存活且 UDP+TCP 端口真实监听，否则立即卸载防断网)
preflight_check() {
    load_runtime_config
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if agh_core_healthy "$redir_port"; then
            agh_real_pid=$(pidof AdGuardHome 2>/dev/null 7>&- 8>&- 9>&- | awk '{print $1}')
            [ -n "$agh_real_pid" ] && echo "$agh_real_pid" > "$PID_FILE" 2>/dev/null
            echo "$(date '+%F %T') [PRE-FLIGHT] 本地 DNS 端口 ($redir_port UDP+TCP) 就绪，执行规则接管。" >> "$MAIN_LOG" 2>/dev/null
            return 0
        fi
        sleep 0.2 2>/dev/null 7>&- 8>&- 9>&- || sleep 1 7>&- 8>&- 9>&-
    done
    clean_all_rules
    echo "$(date '+%F %T') [WARNING] AdGuardHome 未存活或端口 ($redir_port) 未完整监听，已触发防断网安全阀卸载 NAT 规则！" >> "$MAIN_LOG" 2>/dev/null
    return 1
}

trap 'on_script_exit' EXIT
trap 'on_signal_abort INT' INT
trap 'on_signal_abort TERM' TERM

case "${1:-}" in
    --diag-flock|diag-flock)
        diagnose_flock_state "${2:-}"
        exit $?
        ;;
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
        if pidof AdGuardHome >/dev/null 2>&1 7>&- 8>&- 9>&-; then
            killall -15 AdGuardHome 2>/dev/null 7>&- 8>&- 9>&-
            sleep 1 7>&- 8>&- 9>&-
            pidof AdGuardHome >/dev/null 2>&1 7>&- 8>&- 9>&- && killall -9 AdGuardHome 2>/dev/null 7>&- 8>&- 9>&-
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
        if [ "${AGH_OP_LOCK_HELD:-0}" != "1" ] || [ "${AGH_TX_PRECLEANED:-0}" != "1" ] || ! has_op_lock_context; then
            clean_legacy_conflicts
            clean_hotspot_rules
        fi
        if preflight_check; then
            if apply_rules; then
                [ -n "${AGH_SWITCH_OP_ID:-}" ] && [ -z "${AGH_MONO_CLOCK_SOURCE:-}" ] && { init_monotonic_clock || true; }
                t_post_start=$(mono_now_ms || true)
                if post_apply_check "$redir_port"; then
                    t_post_end=$(mono_now_ms || true)
                    log_stage_timing "post_mount_check" "ok" "$t_post_start" "$t_post_end" "port=$redir_port"
                    dns_flushed=0
                    refresh_network && dns_flushed=1
                    echo "AGH_REPAIR_RESULT status=ok stage=completed branch=iptables_enable dns_flushed=$dns_flushed"
                    exit 0
                fi
                t_post_end=$(mono_now_ms || true)
                log_stage_timing "post_mount_check" "error" "$t_post_start" "$t_post_end" "port=$redir_port"
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
            release_op_lock
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
