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

SCRIPT_LABEL="service.sh"
resolve_abs_path() {
    p="$1"
    case "$p" in
        /*) printf '%s\n' "$p" ;;
        *)  printf '%s/%s\n' "$(pwd 2>/dev/null || echo /)" "$p" ;;
    esac
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
RUN_DIR="$(cd "$RUN_DIR" 2>/dev/null && pwd || resolve_abs_path "$RUN_DIR")"
export RUN_DIR

WATCHDOG_LOCK_FILE="$(resolve_abs_path "$RUN_DIR/agh_watchdog.flock")"
WATCHDOG_PID_FILE="$(resolve_abs_path "$RUN_DIR/agh_watchdog.pid")"
OP_LOCK_FILE="$(resolve_abs_path "$RUN_DIR/agh_op.flock")"
OP_LOCK_DIAG_PID_FILE="$(resolve_abs_path "$RUN_DIR/agh_op.pid")"
SESSION_STOP_FILE="$(resolve_abs_path "$RUN_DIR/agh_manual_stop")"
IPV6_DNS_MODE_FILE="$(resolve_abs_path "$RUN_DIR/agh_ipv6_dns_mode")"
SNI_FW_MODE_FILE="$(resolve_abs_path "$RUN_DIR/agh_sni_fw_mode")"
SNI_QUEUE_NUM_FILE="$(resolve_abs_path "$RUN_DIR/agh_sni_queue_num")"

# 系统语言检测
locale=$(getprop persist.sys.locale 2>/dev/null)
[ -z "$locale" ] && locale="zh"
case "$locale" in zh*) lang=zh ;; *) lang=en ;; esac

if [ -f "$SCRIPT_DIR/diag_log.sh" ]; then
    . "$SCRIPT_DIR/diag_log.sh"
elif [ -f "$MODDIR/scripts/diag_log.sh" ]; then
    . "$MODDIR/scripts/diag_log.sh"
fi

log_msg() {
    if command -v agh_log_always >/dev/null 2>&1; then
        agh_log_always "$1"
    else
        echo "$(date '+%F %T') $1" >> "$MAIN_LOG" 2>/dev/null || true
    fi
}

file_hash() {
    hf="$1"
    [ -f "$hf" ] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        set -- $(sha256sum "$hf" 2>/dev/null)
        [ -n "${1:-}" ] && { printf '%s\n' "$1"; return 0; }
    elif command -v shasum >/dev/null 2>&1; then
        set -- $(shasum -a 256 "$hf" 2>/dev/null)
        [ -n "${1:-}" ] && { printf '%s\n' "$1"; return 0; }
    elif command -v md5sum >/dev/null 2>&1; then
        set -- $(md5sum "$hf" 2>/dev/null)
        [ -n "${1:-}" ] && { printf '%s\n' "$1"; return 0; }
    else
        set -- $(cksum "$hf" 2>/dev/null)
        [ -n "${1:-}" ] && [ -n "${2:-}" ] && { printf '%s_%s\n' "$1" "$2"; return 0; }
    fi
    return 1
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

# ==============================================================================
# 内核 flock 能力统一探测与三步独立进程竞争自检（严禁退化为有竞态的目录锁）
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

    # 步骤 1：第 1 个独立进程打开并持有排他锁一段短时间（关闭管道与锁 FD 防挂起）
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
        safe_sleep 0.05 || sleep 1
        w_rdy=$((w_rdy + 1))
    done

    step1_rc="1"
    step2_rc="skip"
    step3_rc="skip"

    if [ ! -f "$probe_ready" ]; then
        : > "$probe_release" 2>/dev/null
        w_exit=0
        while kill -0 "$p1_pid" 2>/dev/null && [ "$w_exit" -lt 20 ]; do
            safe_sleep 0.05 || sleep 1
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

    # 步骤 2：第 2 个独立进程重新打开同一锁文件尝试非阻塞加锁，必须失败 (step2_rc=1)
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

    # 通知第 1 个进程释放锁并等待其彻底退出（超时强制回收防挂起）
    : > "$probe_release" 2>/dev/null
    w_exit=0
    while kill -0 "$p1_pid" 2>/dev/null && [ "$w_exit" -lt 20 ]; do
        safe_sleep 0.05 || sleep 1
        w_exit=$((w_exit + 1))
    done
    kill -0 "$p1_pid" 2>/dev/null && kill -9 "$p1_pid" 2>/dev/null || true
    wait "$p1_pid" 2>/dev/null
    step1_rc=$?

    # 步骤 3：释放后第 3 个独立进程重新打开同一锁文件非阻塞获取，必须成功 (step3_rc=0)
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

verify_flock_support() {
    [ "$FLOCK_VERIFIED" = "1" ] && return 0
    FLOCK_LAST_DIAG=""

    # 1. custom ($FLOCK_BIN)
    if [ -n "${FLOCK_BIN:-}" ] && [ -x "$FLOCK_BIN" ]; then
        if test_flock_candidate_3step "custom" "$FLOCK_BIN" ""; then
            return 0
        fi
        FLOCK_LAST_DIAG="${FLOCK_LAST_DIAG:+${FLOCK_LAST_DIAG}; }${LAST_CAND_REPORT}"
    fi

    # 2. busybox ($BB_BIN flock)
    if [ -n "${BB_BIN:-}" ] && [ -x "$BB_BIN" ]; then
        if test_flock_candidate_3step "busybox" "$BB_BIN" "flock"; then
            return 0
        fi
        FLOCK_LAST_DIAG="${FLOCK_LAST_DIAG:+${FLOCK_LAST_DIAG}; }${LAST_CAND_REPORT}"
    fi

    # 3. system (PATH 中的 standalone flock)
    sys_flock=$(command -v flock 2>/dev/null || true)
    if [ -n "$sys_flock" ] && [ -x "$sys_flock" ]; then
        if test_flock_candidate_3step "system" "$sys_flock" ""; then
            return 0
        fi
        FLOCK_LAST_DIAG="${FLOCK_LAST_DIAG:+${FLOCK_LAST_DIAG}; }${LAST_CAND_REPORT}"
    fi

    # 4. toybox (/system/bin/toybox flock 或 PATH toybox)
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

# ==============================================================================
# 信号处理与受控子进程回收（严格区分 EXIT 与 INT/TERM）
# ==============================================================================
WATCHDOG_LOCK_OWNED=0
OP_LOCK_OWNED=0
OP_LOCK_INHERITED=0
ABORTED_BY_SIGNAL=0
CLEANUP_DONE=0
ACTIVE_CHILD_PID=""

# 运行可能修改共享状态的同步子命令：显式关闭 7/8/9 锁描述符，通过父锁校验上下文协同运行
run_sync_child() {
    [ "$ABORTED_BY_SIGNAL" = "1" ] && return 143
    "$@" 7>&- 8>&- 9>&- &
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
    verify_flock_support >/dev/null 2>&1 || return 1
    is_file_kernel_locked "$WATCHDOG_LOCK_FILE"
}

acquire_watchdog_lock() {
    [ "$WATCHDOG_LOCK_OWNED" = "1" ] && return 0
    verify_flock_support || return 1
    exec 8<>"$WATCHDOG_LOCK_FILE" 2>/dev/null || return 1
    if ! run_flock_nb 8; then
        exec 8>&- 2>/dev/null || true
        return 1
    fi
    WATCHDOG_LOCK_OWNED=1
    printf '%s\n' "$$" > "$WATCHDOG_PID_FILE" 2>/dev/null
    return 0
}

release_watchdog_lock() {
    if [ "$WATCHDOG_LOCK_OWNED" = "1" ]; then
        if [ "$(cat "$WATCHDOG_PID_FILE" 2>/dev/null | tr -d '\r[:space:]')" = "$$" ]; then
            rm -f "$WATCHDOG_PID_FILE" 2>/dev/null
        fi
        run_flock_unlock 8 || true
        exec 8>&- 2>/dev/null || true
        WATCHDOG_LOCK_OWNED=0
    fi
}

# ==============================================================================
# 锁机制 2：短期生命周期操作内核锁 (FD 9 -> OP_LOCK_FILE)
# 仅在成功获取内核锁后写入诊断 PID；子进程验证父进程确实持锁且退出时不解锁父锁
# ==============================================================================
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
    # 同步子进程受父进程锁保护模式：确认父进程确实持有内核锁，子进程运行且退出时不解锁父锁
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
            sleep 1
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
    case "${AGH_TX_TARGET_MODE:-}" in
        cn|overseas)
            if [ "${AGH_OP_LOCK_HELD:-0}" = "1" ] && has_op_lock_context; then
                RUN_MODE="$AGH_TX_TARGET_MODE"
            fi
            ;;
    esac
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
case "${1:-}" in
    --diag-flock|diag-flock|--diag-sni|diag-sni) ;;
    *) escape_app_cgroup "$$" ;;
esac

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
    if [ -r "$SCRIPT_DIR/config.prop" ]; then
        while IFS= read -r _cfg_line || [ -n "$_cfg_line" ]; do
            case "$_cfg_line" in
                STOPPED=1|MANUAL_STOP=1) return 0 ;;
            esac
        done < "$SCRIPT_DIR/config.prop"
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

# 检查是否仍残留模块挂载的 OUTPUT/INPUT 劫持跳转规则
has_residual_firewall_jumps() {
    iptables -w 2 -t nat -C OUTPUT -j ADGUARD >/dev/null 2>&1 && return 0
    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 && return 0
    iptables -w 2 -t filter -C INPUT -j AGH_INPUT >/dev/null 2>&1 && return 0
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
        while iptables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
        iptables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
        iptables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
        while ip6tables -w 2 -t filter -D OUTPUT -j ADGUARD_DOT 2>/dev/null; do :; done
        ip6tables -w 2 -t filter -F ADGUARD_DOT 2>/dev/null
        ip6tables -w 2 -t filter -X ADGUARD_DOT 2>/dev/null
        while iptables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
        iptables -w 2 -t filter -F AGH_INPUT 2>/dev/null
        iptables -w 2 -t filter -X AGH_INPUT 2>/dev/null
        while ip6tables -w 2 -t filter -D INPUT -j AGH_INPUT 2>/dev/null; do :; done
        ip6tables -w 2 -t filter -F AGH_INPUT 2>/dev/null
        ip6tables -w 2 -t filter -X AGH_INPUT 2>/dev/null
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
        bundle_mtime=$(stat -c %Y "$CA_BUNDLE" 2>/dev/null)
        max_source_mtime=0
        for cert_dir in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts /apex/com.android.conscrypt/etc/security/cacerts /data/misc/keychain/cacerts-added; do
            [ -d "$cert_dir" ] || continue
            source_mtime=$(stat -c %Y "$cert_dir" 2>/dev/null)
            case "$source_mtime" in
                ''|*[!0-9]*) continue ;;
            esac
            if [ "$source_mtime" -gt "$max_source_mtime" ]; then
                max_source_mtime="$source_mtime"
            fi
        done
        if [ -n "$bundle_mtime" ] && [ "$max_source_mtime" -gt 0 ] && [ "$bundle_mtime" -ge "$max_source_mtime" ]; then
            return 0
        fi
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

reset_spawn_priority() {
    _rsp_pid="${1:-}"
    case "$_rsp_pid" in
        ''|*[!0-9]*) return 0 ;;
    esac
    renice -n 0 -p "$_rsp_pid" >/dev/null 2>&1 || \
        renice 0 "$_rsp_pid" >/dev/null 2>&1 || \
        { [ -n "$BB_BIN" ] && "$BB_BIN" renice 0 "$_rsp_pid" >/dev/null 2>&1; } || true
}

# 以 setsid + BusyBox/util-linux nsenter 切入 PID 1 根命名空间与专属 GID 23333
# 关键：显式关闭 FD 7/8/9 并清理锁继承环境变量，杜绝 AdGuardHome 核心进程意外继承守护锁或操作锁！
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
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        elif "$BB_BIN" nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        elif "$BB_BIN" nsenter -t 1 -m -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD "$BB_BIN" nsenter -t 1 -m -n -G "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        elif "$BB_BIN" nsenter -t 1 -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD "$BB_BIN" nsenter -t 1 -G "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        fi
    fi

    if command -v nsenter >/dev/null 2>&1; then
        if nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD nsenter -t 1 -m -u -i -n -p -F -G "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        elif nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD nsenter -t 1 -m -u -i -n -G "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        elif nsenter -t 1 -m -n -G "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD nsenter -t 1 -m -n -G "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        elif nsenter -G "$AGH_GID" -t 1 "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD nsenter -G "$AGH_GID" -t 1 "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        elif command -v setpriv >/dev/null 2>&1 && \
             nsenter -t 1 -m -u -i -n setpriv --egid "$AGH_GID" --rgid "$AGH_GID" "$TRUE_BIN" >/dev/null 2>&1; then
            ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD nsenter -t 1 -m -u -i -n setpriv --egid "$AGH_GID" --rgid "$AGH_GID" "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
            SPAWN_PID=$!
            reset_spawn_priority "$SPAWN_PID"
            return 0
        fi
    fi

    ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD "$@" ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
    SPAWN_PID=$!
    reset_spawn_priority "$SPAWN_PID"
    return 0
}

# 校验配置文件有效性（同一次持锁事务内若已对相同 SHA-256 的目标文件跑过 --check-config，则免重复加载 23 万规则）
verify_or_restore_yaml() {
    check_f="$1"
    [ -s "$check_f" ] || return 1
    grep -q '^schema_version:' "$check_f" 2>/dev/null || return 1
    grep -q '^dns:' "$check_f" 2>/dev/null || return 1
    grep -q '^user_rules:' "$check_f" 2>/dev/null || return 1
    if [ -n "${AGH_TX_VALIDATED_YAML_SHA:-}" ] && [ "$check_f" = "${AGH_TX_VALIDATED_YAML_FILE:-}" ] && has_op_lock_context; then
        cur_chk_sha=$(file_hash "$check_f" 2>/dev/null || true)
        if [ -n "$cur_chk_sha" ] && [ "$cur_chk_sha" = "$AGH_TX_VALIDATED_YAML_SHA" ]; then
            return 0
        fi
    fi
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

    if [ "${AGH_TX_PRECLEANED:-0}" != "1" ] && has_residual_firewall_jumps; then
        disarm_nat_safety_valve >/dev/null 2>&1 || true
    fi
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

# 仅使用系统主链 -C + 自有小链单链 -S 纯 Shell 解析核验防火墙健康状态（无 -L、无主链 -S、无 grep，覆盖 UDP+TCP 53、GID 防环回、DoT、IPv6 及 SNI 链）
nat_rules_healthy() {
    check_port="${redir_port:-55453}"
    check_sni="${ENABLE_SNI:-1}"

    # 1. IPv4 nat OUTPUT 主链跳转 (-C) 与 ADGUARD 自有链单链核验 (-S，纯 Shell 解析，0 grep)
    iptables -w 2 -t nat -C OUTPUT -j ADGUARD >/dev/null 2>&1 || return 1
    _adg_chain="$(iptables -w 2 -t nat -S ADGUARD 2>/dev/null || true)"
    [ -n "$_adg_chain" ] || return 1
    _adg_lo_udp=0
    _adg_lo_tcp=0
    _adg_gid=0
    _adg_udp=0
    _adg_tcp=0
    _nrh_old_ifs="$IFS"
    IFS='
'
    set -f
    for _adg_line in $_adg_chain; do
        case "$_adg_line" in
            *"-A ADGUARD -d 127.0.0.1"*"-p udp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port"|*"-A ADGUARD -d 127.0.0.1"*"-p udp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port "*)
                _adg_lo_udp=1 ;;
            *"-A ADGUARD -d 127.0.0.1"*"-p tcp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port"|*"-A ADGUARD -d 127.0.0.1"*"-p tcp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port "*)
                _adg_lo_tcp=1 ;;
            *"-A ADGUARD "*"--gid-owner $AGH_GID "*"-j RETURN"*)
                _adg_gid=1 ;;
            "-A ADGUARD -p udp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port"|"-A ADGUARD -p udp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port "*)
                _adg_udp=1 ;;
            "-A ADGUARD -p tcp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port"|"-A ADGUARD -p tcp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port "*)
                _adg_tcp=1 ;;
        esac
    done
    set +f
    IFS="$_nrh_old_ifs"
    [ "$_adg_lo_udp" -eq 1 ] && [ "$_adg_lo_tcp" -eq 1 ] && [ "$_adg_gid" -eq 1 ] && \
        [ "$_adg_udp" -eq 1 ] && [ "$_adg_tcp" -eq 1 ] || return 1

    # 2. filter 表 ADGUARD_DOT 与 AGH_INPUT 主链跳转检查 (-C)
    iptables -w 2 -t filter -C OUTPUT -j ADGUARD_DOT >/dev/null 2>&1 || return 1
    iptables -w 2 -t filter -C INPUT -j AGH_INPUT >/dev/null 2>&1 || return 1

    # 3. IPv6 接管链精确检查（依据挂载时记录的实际内核能力模式，避免不支持 ip6tables nat 的内核无限重挂）
    v6_mode=""
    [ -r "$IPV6_DNS_MODE_FILE" ] && { IFS= read -r v6_mode < "$IPV6_DNS_MODE_FILE" 2>/dev/null || v6_mode=""; }
    if [ "$v6_mode" = "nat" ]; then
        ip6tables -w 2 -t nat -C OUTPUT -j ADGUARD6_NAT >/dev/null 2>&1 || return 1
        _adg6_chain="$(ip6tables -w 2 -t nat -S ADGUARD6_NAT 2>/dev/null || true)"
        [ -n "$_adg6_chain" ] || return 1
        _adg6_gid=0
        _adg6_udp=0
        _adg6_tcp=0
        _nrh_old_ifs="$IFS"
        IFS='
'
        set -f
        for _adg6_line in $_adg6_chain; do
            case "$_adg6_line" in
                "-A ADGUARD6_NAT "*"-m owner "*"--gid-owner $AGH_GID "*"-j RETURN"*)
                    _adg6_gid=1 ;;
                "-A ADGUARD6_NAT -p udp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port"|"-A ADGUARD6_NAT -p udp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port "*)
                    [ "$_adg6_gid" -eq 1 ] && _adg6_udp=1 ;;
                "-A ADGUARD6_NAT -p tcp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port"|"-A ADGUARD6_NAT -p tcp "*"--dport 53 "*"-j REDIRECT --to-ports $check_port "*)
                    [ "$_adg6_gid" -eq 1 ] && _adg6_tcp=1 ;;
            esac
        done
        set +f
        IFS="$_nrh_old_ifs"
        [ "$_adg6_gid" -eq 1 ] && [ "$_adg6_udp" -eq 1 ] && [ "$_adg6_tcp" -eq 1 ] || return 1
    elif [ "$v6_mode" = "filter" ]; then
        ip6tables -w 2 -t filter -C OUTPUT -j ADGUARD6 >/dev/null 2>&1 || return 1
    fi

    # 4. mangle 表 AGH_SNI 自有链检查（OUTPUT 跳转用 -C，AGH_SNI 用单链 -S 纯 Shell 解析，规避 iptables-nft -C 对 connbytes+NFQUEUE 的误判）
    if [ "$check_sni" = "1" ]; then
        sni_fw_mode=""
        [ -r "$SNI_FW_MODE_FILE" ] && { IFS= read -r sni_fw_mode < "$SNI_FW_MODE_FILE" 2>/dev/null || sni_fw_mode=""; }
        if [ "$sni_fw_mode" != "unsupported" ] && [ "$sni_fw_mode" != "disabled" ]; then
            sni_queue="0"
            if [ -r "$SNI_QUEUE_NUM_FILE" ]; then
                IFS= read -r sni_queue < "$SNI_QUEUE_NUM_FILE" 2>/dev/null || sni_queue="0"
            fi
            case "$sni_queue" in
                ''|*[!0-9]*) sni_queue="0" ;;
            esac

            iptables -w 2 -t mangle -C OUTPUT -j AGH_SNI >/dev/null 2>&1 || return 1
            _sni_chain="$(iptables -w 2 -t mangle -S AGH_SNI 2>/dev/null || true)"
            [ -n "$_sni_chain" ] || return 1
            _sni_gid=0
            _sni_has_443=0
            _sni_has_8443=0
            _nrh_old_ifs="$IFS"
            IFS='
'
            set -f
            for _sni_line in $_sni_chain; do
                case "$_sni_line" in
                    *"-A AGH_SNI "*"-m owner "*"--gid-owner $AGH_GID "*"-j RETURN"*)
                        _sni_gid=1 ;;
                    *"-A AGH_SNI "*"-p tcp "*"-j NFQUEUE"*"--queue-bypass"*)
                        if [ "$sni_fw_mode" = "connbytes" ]; then
                            case "$_sni_line" in
                                *"connbytes"*"1:8"*) ;;
                                *) continue ;;
                            esac
                        fi
                        if [ "$sni_queue" = "0" ]; then
                            case "$_sni_line" in
                                *"--queue-num "[1-9]*) continue ;;
                            esac
                        else
                            case "$_sni_line" in
                                *"--queue-num $sni_queue "*|*"--queue-num $sni_queue") ;;
                                *) continue ;;
                            esac
                        fi
                        case "$_sni_line" in
                            *"--dport 443 "*) _sni_has_443=1 ;;
                            *"--dport 8443 "*) _sni_has_8443=1 ;;
                        esac
                        ;;
                esac
            done
            set +f
            IFS="$_nrh_old_ifs"
            [ "$_sni_gid" -eq 1 ] && [ "$_sni_has_443" -eq 1 ] && [ "$_sni_has_8443" -eq 1 ] || return 1
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
    if [ "${AGH_TX_PRECLEANED:-0}" != "1" ] || has_residual_firewall_jumps; then
        run_sync_child "$SH_BIN" "$SCRIPT_DIR/iptables.sh" clean >/dev/null 2>&1 || true
    fi
    [ -n "${AGH_SWITCH_OP_ID:-}" ] && [ -z "${AGH_MONO_CLOCK_SOURCE:-}" ] && { init_monotonic_clock || true; }
    t_mount_start=$(mono_now_ms || true)
    if run_sync_child "$SH_BIN" "$SCRIPT_DIR/iptables.sh" enable >/dev/null 2>&1; then
        t_mount_end=$(mono_now_ms || true)
        log_stage_timing "mount_firewall" "ok" "$t_mount_start" "$t_mount_end" "reason=$reason"
        sni_fw_mode=$(cat "$SNI_FW_MODE_FILE" 2>/dev/null)
        log_msg "[WATCHDOG] 已完成防火墙规则幂等重挂并通过完整自检 (reason=$reason, mode=$active_mode, DNS=${redir_port:-55453}, SNI=${sni_fw_mode:-auto})"
        return 0
    fi
    t_mount_end=$(mono_now_ms || true)
    log_stage_timing "mount_firewall" "error" "$t_mount_start" "$t_mount_end" "reason=$reason"
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

detect_vpn_iface_fast() {
    _vpn_sys_net="${AGH_SYS_NET_DIR:-/sys/class/net}"
    VPN_IFACE_STATE="off"
    for iface in "$_vpn_sys_net"/tun* "$_vpn_sys_net"/wg* "$_vpn_sys_net"/ppp*; do
        if [ -d "$iface" ]; then
            VPN_IFACE_STATE="on"
            return 0
        fi
    done
    return 0
}

detect_vpn_iface() {
    detect_vpn_iface_fast
    printf '%s\n' "$VPN_IFACE_STATE"
}

# 纯 Shell 极速检测目标 PID 是否仍真实存活（校验目录存在、comm 匹配且未处于 Z 僵尸/X 死亡状态，零外部 fork）
is_pid_alive_fast() {
    _alive_pid="$1"
    _alive_exp_comm="${2:-}"
    case "$_alive_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ -d "$PROC_DIR/$_alive_pid" ] || return 1
    if [ -n "$_alive_exp_comm" ]; then
        if [ -r "$PROC_DIR/$_alive_pid/comm" ]; then
            IFS= read -r _alive_comm < "$PROC_DIR/$_alive_pid/comm" 2>/dev/null || _alive_comm=""
            [ "$_alive_comm" = "$_alive_exp_comm" ] || return 1
        else
            return 1
        fi
    fi
    if [ -r "$PROC_DIR/$_alive_pid/status" ]; then
        while IFS= read -r _status_line; do
            case "$_status_line" in
                State:*)
                    case "$_status_line" in
                        *[ZX]*) return 1 ;;
                    esac
                    break
                    ;;
            esac
        done < "$PROC_DIR/$_alive_pid/status"
    fi
    return 0
}

is_agh_pid_alive_fast() {
    is_pid_alive_fast "$1" "AdGuardHome"
}

NETD_PID=""
NETD_COMM=""
NETD_TRACKING_ACTIVE=0
SYS_SERVER_PID=""
SYS_SERVER_COMM=""
SYS_SERVER_TRACKING_ACTIVE=0
SYS_SERVER_EVER_SEEN=0
AGH_PID=""

resolve_agh_pid() {
    AGH_PID=""
    if [ -r "$PID_FILE" ]; then
        IFS= read -r _rap_p < "$PID_FILE" 2>/dev/null || _rap_p=""
        if is_agh_pid_alive_fast "$_rap_p"; then
            AGH_PID="$_rap_p"
            return 0
        fi
    fi
    if agh_running && [ -r "$PID_FILE" ]; then
        IFS= read -r _rap_p < "$PID_FILE" 2>/dev/null || _rap_p=""
        if is_pid_alive_fast "$_rap_p" "AdGuardHome"; then
            AGH_PID="$_rap_p"
        fi
    fi
    [ -n "$AGH_PID" ]
}

# 共享查找辅助：通过覆写文件 / 系统属性 / pidof / /proc/<pid>/comm 解析系统守护进程 PID（结果写入 RESOLVED_PID / RESOLVED_COMM）
resolve_proc_pid_by_comm() {
    _rpb_comm_target="$1"
    _rpb_override_file="${2:-}"
    _rpb_prop_name="${3:-}"
    RESOLVED_PID=""
    RESOLVED_COMM=""

    if [ -n "$_rpb_override_file" ] && [ -r "$_rpb_override_file" ]; then
        IFS= read -r _rpb_p < "$_rpb_override_file" 2>/dev/null || _rpb_p=""
        is_pid_alive_fast "$_rpb_p" "" || _rpb_p=""
    else
        _rpb_p=""
    fi

    if [ -z "$_rpb_p" ] && [ -n "$_rpb_prop_name" ]; then
        _rpb_p=$(getprop "$_rpb_prop_name" 2>/dev/null || true)
        is_pid_alive_fast "$_rpb_p" "$_rpb_comm_target" || _rpb_p=""
    fi

    if [ -z "$_rpb_p" ]; then
        for _rpb_cand in $(pidof "$_rpb_comm_target" 2>/dev/null); do
            if is_pid_alive_fast "$_rpb_cand" "$_rpb_comm_target"; then
                _rpb_p="$_rpb_cand"
                break
            fi
        done
    fi

    if [ -z "$_rpb_p" ]; then
        for _rpb_cf in "$PROC_DIR"/[0-9]*/comm; do
            [ -r "$_rpb_cf" ] || continue
            IFS= read -r _rpb_comm < "$_rpb_cf" 2>/dev/null || continue
            if [ "$_rpb_comm" = "$_rpb_comm_target" ]; then
                _rpb_dir="${_rpb_cf%/comm}"
                _rpb_cand="${_rpb_dir##*/}"
                if is_pid_alive_fast "$_rpb_cand" "$_rpb_comm_target"; then
                    _rpb_p="$_rpb_cand"
                    break
                fi
            fi
        done
    fi

    [ -n "$_rpb_p" ] || return 1
    RESOLVED_PID="$_rpb_p"
    if [ -r "$PROC_DIR/$_rpb_p/comm" ]; then
        IFS= read -r RESOLVED_COMM < "$PROC_DIR/$_rpb_p/comm" 2>/dev/null || RESOLVED_COMM="$_rpb_comm_target"
    else
        RESOLVED_COMM=""
    fi
    return 0
}

resolve_netd_pid() {
    NETD_PID=""
    NETD_COMM=""
    NETD_TRACKING_ACTIVE=0
    if resolve_proc_pid_by_comm "netd" "${AGH_NETD_PID_FILE:-}" "init.svc_debug_pid.netd"; then
        NETD_PID="$RESOLVED_PID"
        NETD_COMM="${RESOLVED_COMM:-}"
        NETD_TRACKING_ACTIVE=1
        return 0
    fi
    return 1
}

resolve_sys_server_pid() {
    SYS_SERVER_PID=""
    SYS_SERVER_COMM=""
    SYS_SERVER_TRACKING_ACTIVE=0
    if resolve_proc_pid_by_comm "system_server" "${AGH_SYS_SERVER_PID_FILE:-}" ""; then
        SYS_SERVER_PID="$RESOLVED_PID"
        SYS_SERVER_COMM="${RESOLVED_COMM:-}"
        SYS_SERVER_TRACKING_ACTIVE=1
        SYS_SERVER_EVER_SEEN=1
        return 0
    fi
    return 1
}

refresh_watchdog_cached_pids() {
    resolve_agh_pid || true
    resolve_netd_pid || true
    resolve_sys_server_pid || true
}

# 在根命名空间与独立会话中以最低调度优先级 (nice 19) 确保全局唯一后台守护循环在线（显式关闭 FD 7/8/9 并清理锁继承环境）
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
    NICE_CMD=""
    if [ -n "$BB_BIN" ] && "$BB_BIN" nice -n 19 "$TRUE_BIN" >/dev/null 2>&1; then
        NICE_CMD="$BB_BIN nice -n 19"
    elif command -v nice >/dev/null 2>&1 && nice -n 19 "$TRUE_BIN" >/dev/null 2>&1; then
        NICE_CMD="nice -n 19"
    fi
    if [ -n "$BB_BIN" ] && "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F "$TRUE_BIN" >/dev/null 2>&1; then
        ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD $NICE_CMD "$BB_BIN" nsenter -t 1 -m -u -i -n -p -F "$SH_BIN" "$SELF_SCRIPT" --watchdog ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
    elif [ -n "$BB_BIN" ] && "$BB_BIN" nsenter -t 1 -m -n "$TRUE_BIN" >/dev/null 2>&1; then
        ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD $NICE_CMD "$BB_BIN" nsenter -t 1 -m -n "$SH_BIN" "$SELF_SCRIPT" --watchdog ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
    elif command -v nsenter >/dev/null 2>&1 && nsenter -t 1 -m -n "$TRUE_BIN" >/dev/null 2>&1; then
        ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD $NICE_CMD nsenter -t 1 -m -n "$SH_BIN" "$SELF_SCRIPT" --watchdog ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
    else
        ( unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID AGH_TX_TARGET_MODE AGH_SWITCH_OP_ID AGH_MONO_BASE_SEC AGH_MONO_CLOCK_SOURCE AGH_TX_FLOCK_KIND AGH_TX_FLOCK_BIN AGH_TX_FLOCK_TARGET AGH_TX_FLOCK_SUBCMD AGH_TX_FLOCK_IMPL AGH_TX_FLOCK_CMD_STR AGH_TX_FLOCK_VERIFY_STEPS AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED; exec $SETSID_CMD $NICE_CMD "$SH_BIN" "$SELF_SCRIPT" --watchdog ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
    fi
    _wd_wait=0
    while [ "$_wd_wait" -lt 20 ]; do
        if [ -s "$WATCHDOG_PID_FILE" ] && watchdog_alive; then
            break
        fi
        safe_sleep 0.05 || sleep 1
        _wd_wait=$((_wd_wait + 1))
    done
}

# ==============================================================================
# 只读 flock 诊断接口 (--diag-flock)：零修改正式锁、YAML、config.prop 或防火墙
# ==============================================================================
diagnose_flock_state() {
    brief_arg="${1:-}"
    sh_target=$(resolve_symlink_target "$SH_BIN")

    if ! verify_flock_support; then
        if [ "$brief_arg" = "--brief" ]; then
            printf 'FLOCK_BRIEF script=%s status=FAIL impl=none bin=none cmd="" verify_steps=fail diag="%s"\n' \
                "$SCRIPT_LABEL" "$FLOCK_LAST_DIAG"
        else
            printf 'SHELL_INFO sh_bin=%s sh_target=%s ksh_version="%s"\n' "$SH_BIN" "$sh_target" "${KSH_VERSION:-posix}"
            printf 'RUN_PATHS run_dir=%s op_lock_file=%s op_diag_pid_file=%s watchdog_lock_file=%s\n' \
                "$RUN_DIR" "$OP_LOCK_FILE" "$OP_LOCK_DIAG_PID_FILE" "$WATCHDOG_LOCK_FILE"
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

    printf 'SHELL_INFO sh_bin=%s sh_target=%s ksh_version="%s"\n' "$SH_BIN" "$sh_target" "${KSH_VERSION:-posix}"
    printf 'RUN_PATHS run_dir=%s op_lock_file=%s op_diag_pid_file=%s watchdog_lock_file=%s\n' \
        "$RUN_DIR" "$OP_LOCK_FILE" "$OP_LOCK_DIAG_PID_FILE" "$WATCHDOG_LOCK_FILE"
    printf 'SELECTED_FLOCK script=%s kind=%s impl=%s bin=%s target=%s subcmd="%s" args="%s" cmd="%s" verify_steps=%s\n' \
        "$SCRIPT_LABEL" "$FLOCK_RESOLVED_KIND" "$FLOCK_RESOLVED_IMPL" "$FLOCK_RESOLVED_BIN" \
        "$FLOCK_RESOLVED_TARGET" "${FLOCK_RESOLVED_SUBCMD:-none}" "$FLOCK_RESOLVED_ARGS" \
        "$FLOCK_RESOLVED_CMD_STR" "$FLOCK_VERIFY_STEPS"

    # 1. 验证三脚本 (service.sh / switch_mode.sh / iptables.sh) 工具选择一致性
    consistency_status="PASS"
    switch_bin_path="$SCRIPT_DIR/switch_mode.sh"
    [ -f "$switch_bin_path" ] || switch_bin_path="${SELF_SCRIPT%/*}/scripts/switch_mode.sh"
    ipt_bin_path="$SCRIPT_DIR/iptables.sh"
    [ -f "$ipt_bin_path" ] || ipt_bin_path="${SELF_SCRIPT%/*}/scripts/iptables.sh"

    for sub_script in "$switch_bin_path" "$ipt_bin_path"; do
        [ -f "$sub_script" ] || continue
        sub_out=$("$SH_BIN" "$sub_script" --diag-flock --brief </dev/null 2>/dev/null || true)
        printf '%s\n' "$sub_out"
        sub_status=$(printf '%s\n' "$sub_out" | sed -n 's/.*status=\([^ ]*\).*/\1/p' | head -n 1)
        sub_impl=$(printf '%s\n' "$sub_out" | sed -n 's/.*impl=\([^ ]*\).*/\1/p' | head -n 1)
        sub_bin=$(printf '%s\n' "$sub_out" | sed -n 's/.*bin=\([^ ]*\).*/\1/p' | head -n 1)
        if [ "$sub_status" != "PASS" ] || [ "$sub_impl" != "$FLOCK_RESOLVED_IMPL" ] || [ "$sub_bin" != "$FLOCK_RESOLVED_BIN" ]; then
            consistency_status="FAIL"
        fi
    done

    # 2. 父子锁验证测试（仅使用独立临时锁文件，不触碰正式锁；显式重定向并关闭管道/锁 FD 防挂起）
    pc_status="PASS"
    pc_file="$RUN_DIR/.agh_flock_pc_diag.$$"
    pc_pid_f="${pc_file}.pid"
    rm -f "$pc_file" "$pc_pid_f" 2>/dev/null
    (
        exec 7<>"$pc_file" 2>/dev/null || exit 1
        run_flock_nb 7 || { exec 7<&- 7>&- 2>/dev/null || true; exit 1; }
        printf '%s\n' "$$" > "$pc_pid_f" 2>/dev/null
        # 模拟同步子进程：关闭 7/8/9 与父级输出管道，仅验证父锁存活且不会误解父锁
        "$SH_BIN" -c '
            pf="$1"; pidf="$2"; pp="$3"; cbin="$4"; csub="$5"
            [ -r "$pidf" ] && [ "$(cat "$pidf" 2>/dev/null)" = "$pp" ] || exit 1
            exec 6<>"$pf" 2>/dev/null || exit 1
            if [ -n "$csub" ]; then
                if "$cbin" "$csub" -n 0 0<&6 >/dev/null 2>&1; then
                    "$cbin" "$csub" -u 0 0<&6 >/dev/null 2>&1 || true
                    exec 6<&- 6>&- 2>/dev/null || true
                    exit 1
                fi
            else
                if "$cbin" -n 0 0<&6 >/dev/null 2>&1; then
                    "$cbin" -u 0 0<&6 >/dev/null 2>&1 || true
                    exec 6<&- 6>&- 2>/dev/null || true
                    exit 1
                fi
            fi
            exec 6<&- 6>&- 2>/dev/null || true
            exit 0
        ' _ "$pc_file" "$pc_pid_f" "$$" "$FLOCK_RESOLVED_BIN" "$FLOCK_RESOLVED_SUBCMD" </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- || {
            run_flock_unlock 7 || true
            exec 7<&- 7>&- 2>/dev/null || true
            exit 2
        }
        # 验证子进程退出后，父锁依然处于被锁定状态（未被子进程误解锁）
        if ( exec 6<>"$pc_file" 2>/dev/null && run_flock_nb 6 ); then
            run_flock_unlock 6 || true
            exec 6<&- 6>&- 2>/dev/null || true
            run_flock_unlock 7 || true
            exec 7<&- 7>&- 2>/dev/null || true
            exit 3
        fi
        run_flock_unlock 7 || true
        exec 7<&- 7>&- 2>/dev/null || true
        # 父进程释放后应可重新加锁
        if ! ( exec 6<>"$pc_file" 2>/dev/null && run_flock_nb 6 && { run_flock_unlock 6 || true; exec 6<&- 6>&- 2>/dev/null || true; exit 0; } ); then
            exit 4
        fi
        exit 0
    ) </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- || pc_status="FAIL"
    rm -f "$pc_file" "$pc_pid_f" 2>/dev/null
    printf 'PARENT_CHILD_LOCK_TEST status=%s\n' "$pc_status"

    # 3. 只读检查当前正式锁文件与后台进程 FD 继承状况
    op_exists="no"; op_locked="no"
    if [ -e "$OP_LOCK_FILE" ]; then
        op_exists="yes"
        is_file_kernel_locked "$OP_LOCK_FILE" && op_locked="yes"
    fi
    op_pid_val="none"
    if [ -e "$OP_LOCK_DIAG_PID_FILE" ]; then
        if [ -r "$OP_LOCK_DIAG_PID_FILE" ]; then
            op_pid_val=$(cat "$OP_LOCK_DIAG_PID_FILE" 2>/dev/null | tr -d '\r[:space:]')
            [ -n "$op_pid_val" ] || op_pid_val="empty"
        else
            op_pid_val="unreadable"
        fi
    fi

    wd_exists="no"; wd_locked="no"
    if [ -e "$WATCHDOG_LOCK_FILE" ]; then
        wd_exists="yes"
        is_file_kernel_locked "$WATCHDOG_LOCK_FILE" && wd_locked="yes"
    fi
    wd_pid_val=$(cat "$WATCHDOG_PID_FILE" 2>/dev/null | tr -d '\r[:space:]' || true)
    [ -n "$wd_pid_val" ] || wd_pid_val="none"

    printf 'LIVE_LOCKS op_exists=%s op_kernel_locked=%s op_diag_pid=%s watchdog_exists=%s watchdog_kernel_locked=%s watchdog_pid=%s\n' \
        "$op_exists" "$op_locked" "$op_pid_val" "$wd_exists" "$wd_locked" "$wd_pid_val"

    op_fd_leaks=0
    wd_fd_leaks=0
    active_op_holders=0
    core_bin="$BIN_DIR/AdGuardHome"
    core_bin_real=$(resolve_symlink_target "$core_bin")
    cr_char=$(printf '\r')

    for pdir in "$PROC_DIR"/[0-9]*; do
        [ -d "$pdir" ] || continue
        pid_num="${pdir##*/}"
        [ "$pid_num" = "$$" ] && continue

        # 纯 Shell 零派生快速过滤无关 /proc/<pid> 条目，消除数百进程下的数千次 fork 阻塞风险
        p_comm=""
        [ -r "$pdir/comm" ] && { IFS= read -r p_comm < "$pdir/comm" 2>/dev/null || true; }
        p_comm="${p_comm%$cr_char}"
        c_peek=""
        [ -r "$pdir/cmdline" ] && { IFS= read -r c_peek < "$pdir/cmdline" 2>/dev/null || true; }

        if [ "$pid_num" != "$op_pid_val" ] && [ "$pid_num" != "$wd_pid_val" ]; then
            [ -z "$p_comm" ] && [ -z "$c_peek" ] && continue
            cand_hit=0
            for _probe_txt in "$p_comm" "$c_peek"; do
                [ -n "$_probe_txt" ] || continue
                case "$_probe_txt" in
                    *AdGuardHome*|*agh_*|*service.sh*|*switch_mode.sh*|*iptables.sh*|*action.sh*|*ProxyConfig.sh*|*NoAdsService.sh*|sh|*/sh|sh\ *|*/sh\ *|*mksh*|*ash*|*dash*|*bash*|*ksh*|*zsh*|*busybox*|*toybox*|su|*/su|su\ *|*/su\ *|*magisk*|*ksud*|*nsenter*|*nohup*|*env*|*timeout*|*flock*|*sleep*|*python*|*perl*)
                        cand_hit=1
                        break
                        ;;
                esac
            done
            [ "$cand_hit" -eq 1 ] || continue
        fi

        # 仅对候选模块/Shell/核心进程读取 exe 与完整 NUL 分隔 cmdline
        p_exe=""
        if [ -L "$pdir/exe" ] || [ -e "$pdir/exe" ]; then
            p_exe=$(readlink -f "$pdir/exe" 2>/dev/null || readlink "$pdir/exe" 2>/dev/null || true)
        fi
        p_exe_clean="${p_exe% (deleted)}"
        cmdline_lines=""
        [ -r "$pdir/cmdline" ] && cmdline_lines=$( { tr '\000' '\n' < "$pdir/cmdline"; } 2>/dev/null || true )
        [ -d "$pdir" ] || continue

        if [ -z "$p_exe_clean" ] && [ -z "$p_comm" ] && [ -z "$cmdline_lines" ]; then
            continue
        fi

        # 精确角色识别：不再仅凭 cmdline 任意子串包含 AdGuardHome 判定核心
        role=""
        # 1) 核心识别：优先通过 /proc/<pid>/exe 实际路径核对，结合 comm 辅助判断
        if [ -n "$p_exe_clean" ]; then
            if [ "$p_exe_clean" = "$core_bin" ] || [ "$p_exe_clean" = "$core_bin_real" ]; then
                role="core"
            else
                case "$p_exe_clean" in
                    */bin/AdGuardHome|*/AdGuardHome)
                        if [ -z "$p_comm" ] || [ "$p_comm" = "AdGuardHome" ]; then
                            role="core"
                        fi
                        ;;
                esac
            fi
        elif [ ! -e "$pdir/exe" ] && [ ! -L "$pdir/exe" ]; then
            # 仅在测试模拟环境或受限内核无 /proc/<pid>/exe 时，严格要求 comm 与 argv[0] 均指向核心本身
            argv0="${cmdline_lines%%
*}"
            if [ "$p_comm" = "AdGuardHome" ]; then
                case "$argv0" in
                    AdGuardHome|*/AdGuardHome) role="core" ;;
                esac
            fi
        fi

        # 2) 守护、辅助脚本与合法短期操作脚本识别（纯 Shell 参数逐行匹配，零 grep 派生）
        wd_pid_match="n/a"
        if [ -z "$role" ] && [ -n "$cmdline_lines" ]; then
            is_wd_script=0
            has_wd_flag=0
            is_proxy_cfg=0
            is_noads=0
            is_op_script=0
            is_diag_flag=0
            _old_ifs="$IFS"
            IFS='
'
            for _arg in $cmdline_lines; do
                case "$_arg" in
                    service.sh|*/service.sh) is_wd_script=1; is_op_script=1 ;;
                    switch_mode.sh|*/switch_mode.sh|iptables.sh|*/iptables.sh|action.sh|*/action.sh) is_op_script=1 ;;
                    ProxyConfig.sh|*/ProxyConfig.sh) is_proxy_cfg=1 ;;
                    NoAdsService.sh|*/NoAdsService.sh) is_noads=1 ;;
                    --watchdog) has_wd_flag=1 ;;
                    --diag-flock|diag-flock|--diag-sni|diag-sni) is_diag_flag=1 ;;
                esac
            done
            IFS="$_old_ifs"

            if [ "$is_wd_script" -eq 1 ] && [ "$has_wd_flag" -eq 1 ]; then
                role="watchdog"
                case "$wd_pid_val" in
                    ''|none|*[!0-9]*) wd_pid_match="unrecorded" ;;
                    *)
                        if [ "$pid_num" = "$wd_pid_val" ]; then
                            wd_pid_match="yes"
                        elif kill -0 "$wd_pid_val" 2>/dev/null || [ -d "$PROC_DIR/$wd_pid_val" ]; then
                            wd_pid_match="mismatch"
                        else
                            wd_pid_match="stale_diag_pid"
                        fi
                        ;;
                esac
            elif [ "$is_proxy_cfg" -eq 1 ]; then
                role="proxy_cfg"
            elif [ "$is_noads" -eq 1 ]; then
                role="noads"
            elif [ "$is_op_script" -eq 1 ] && [ "$is_diag_flag" -eq 0 ]; then
                role="op_script"
            fi
        fi

        # 仅对已识别角色，或路径/诊断 PID 与本模块相关的 unknown 进程执行 FD 检查，无法确认核心时保持 unknown
        if [ -z "$role" ]; then
            relevant_proc=0
            [ "$pid_num" = "$op_pid_val" ] && relevant_proc=1
            [ "$pid_num" = "$wd_pid_val" ] && relevant_proc=1
            case "$cmdline_lines" in
                *AdGuardHome*|*agh_op*|*agh_watchdog*|*service.sh*|*switch_mode.sh*|*iptables.sh*|*ProxyConfig.sh*|*NoAdsService.sh*)
                    relevant_proc=1
                    ;;
            esac
            [ "$relevant_proc" -eq 1 ] || continue
            role="unknown"
        fi

        [ -d "$pdir/fd" ] || continue
        for fd_link in "$pdir/fd"/*; do
            [ -d "$pdir" ] || break
            [ -e "$fd_link" ] || [ -L "$fd_link" ] || continue
            fd_num="${fd_link##*/}"
            fd_target=""
            if command -v readlink >/dev/null 2>&1; then
                fd_target=$(readlink -f "$fd_link" 2>/dev/null || readlink "$fd_link" 2>/dev/null || true)
            fi
            [ -d "$pdir" ] || break
            [ -n "$fd_target" ] || continue
            case "$fd_target" in
                *"agh_op.flock"*)
                    if [ "$role" = "op_script" ] && { [ "$pid_num" = "$op_pid_val" ] || [ "$op_locked" = "yes" ]; }; then
                        active_op_holders=$((active_op_holders + 1))
                        printf 'ACTIVE_OP_LOCK_HOLDER role=%s pid=%s fd=%s diag_pid=%s target=%s\n' \
                            "$role" "$pid_num" "$fd_num" "$op_pid_val" "$fd_target"
                    elif [ "$role" = "watchdog" ] && [ "$pid_num" = "$op_pid_val" ] && [ "$op_locked" = "yes" ]; then
                        active_op_holders=$((active_op_holders + 1))
                        printf 'ACTIVE_OP_LOCK_HOLDER role=%s pid=%s fd=%s diag_pid=%s target=%s\n' \
                            "$role" "$pid_num" "$fd_num" "$op_pid_val" "$fd_target"
                    else
                        op_fd_leaks=$((op_fd_leaks + 1))
                        printf 'FD_LEAK_DETECTED lock=op role=%s pid=%s fd=%s target=%s\n' \
                            "$role" "$pid_num" "$fd_num" "$fd_target"
                    fi
                    ;;
                *"agh_watchdog.flock"*)
                    if [ "$role" = "watchdog" ] && [ "$fd_num" = "8" ] && [ "$wd_pid_match" != "mismatch" ]; then
                        printf 'WATCHDOG_LOCK_OK role=watchdog pid=%s fd=%s wd_pid_match=%s target=%s\n' \
                            "$pid_num" "$fd_num" "$wd_pid_match" "$fd_target"
                    else
                        wd_fd_leaks=$((wd_fd_leaks + 1))
                        printf 'FD_LEAK_DETECTED lock=watchdog role=%s pid=%s fd=%s wd_pid_match=%s target=%s\n' \
                            "$role" "$pid_num" "$fd_num" "$wd_pid_match" "$fd_target"
                    fi
                    ;;
            esac
        done
    done
    printf 'FD_LEAK_CHECK op_fd_leaks=%s non_watchdog_wd_leaks=%s active_op_holders=%s\n' \
        "$op_fd_leaks" "$wd_fd_leaks" "$active_op_holders"

    overall="PASS"
    [ "$consistency_status" != "PASS" ] && overall="FAIL"
    [ "$pc_status" != "PASS" ] && overall="FAIL"
    [ "$op_fd_leaks" -ne 0 ] && overall="FAIL"
    [ "$wd_fd_leaks" -ne 0 ] && overall="FAIL"

    printf 'AGH_FLOCK_DIAG script=%s status=%s impl=%s bin=%s consistency=%s parent_child=%s op_fd_leaks=%s non_watchdog_wd_leaks=%s\n' \
        "$SCRIPT_LABEL" "$overall" "$FLOCK_RESOLVED_IMPL" "$FLOCK_RESOLVED_BIN" \
        "$consistency_status" "$pc_status" "$op_fd_leaks" "$wd_fd_leaks"
    [ "$overall" = "PASS" ]
}

# ==============================================================================
# 子命令 0：按需单次诊断接口 (--diag-sni / --diag-flock)
# ==============================================================================
if [ "$1" = "--diag-flock" ] || [ "$1" = "diag-flock" ]; then
    diagnose_flock_state "${2:-}"
    exit $?
fi

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
    [ -n "${AGH_SWITCH_OP_ID:-}" ] && [ -z "${AGH_MONO_CLOCK_SOURCE:-}" ] && { init_monotonic_clock || true; }
    t_core_start=$(mono_now_ms || true)
    if ensure_agh_started; then
        t_core_end=$(mono_now_ms || true)
        log_stage_timing "start_core_ready" "ok" "$t_core_start" "$t_core_end" "mode=${active_mode:-unknown}"
        if remount_nat_rules "$reason_arg"; then
            exit 0
        fi
    else
        t_core_end=$(mono_now_ms || true)
        log_stage_timing "start_core_ready" "error" "$t_core_start" "$t_core_end" "mode=${active_mode:-unknown}"
    fi
    disarm_nat_safety_valve >/dev/null 2>&1 || true
    exit 1
fi

# 软重启系统就绪门控：兼容 sys.boot_completed=1 不归零的 killall system_server / ctl.restart zygote 场景
is_system_ready_after_soft_reboot() {
    _sr_reason="${1:-}"
    _sr_boot=$(getprop sys.boot_completed 2>/dev/null)
    if [ -n "$_sr_boot" ] && [ "$_sr_boot" != "1" ]; then
        return 1
    fi
    _sr_zyg=$(getprop init.svc.zygote 2>/dev/null)
    if [ -n "$_sr_zyg" ] && [ "$_sr_zyg" != "running" ]; then
        return 1
    fi
    if [ "$_sr_reason" = "soft-reboot" ] && [ "${SYS_SERVER_EVER_SEEN:-0}" -eq 1 ]; then
        resolve_sys_server_pid || return 1
    fi
    return 0
}

# ==============================================================================
# 子命令 1：独立后台单例「两级零功耗哨兵」守护模式 (--watchdog)
# - 高频快速层（默认 60 秒/轮，零外部进程开销）：纯 Shell 检测 AGH_PID / NETD_PID / SYS_SERVER_PID 及 VPN 接口变化
# - 软重启适配：sys.boot_completed=1 就绪门控防抢跑、同步关闭私人 DNS、一次性防余震复检
# - 低频兜底层（默认 10 轮=10 分钟/轮轻量化规则与端口核验，20 轮=20 分钟/轮执行系统重维护）
# - 统一失败退避与最低优先级 (nice 19)
# ==============================================================================
if [ "$1" = "--watchdog" ]; then
    unset AGH_OP_LOCK_HELD AGH_OP_LOCK_HOLDER_PID
    OP_LOCK_OWNED=0
    OP_LOCK_INHERITED=0
    escape_app_cgroup "$$"
    if [ "${AGH_SKIP_RENICE:-0}" != "1" ]; then
        renice -n 19 -p "$$" >/dev/null 2>&1 || \
            renice 19 "$$" >/dev/null 2>&1 || \
            { [ -n "$BB_BIN" ] && "$BB_BIN" renice 19 "$$" >/dev/null 2>&1; } || true
    fi
    if ! acquire_watchdog_lock; then
        exit 0
    fi

    detect_vpn_iface_fast
    vpn_last="$VPN_IFACE_STATE"
    refresh_watchdog_cached_pids
    boot_completed_cached=""
    cleaned_when_disabled=0
    watchdog_tick=0
    fail_streak=0
    backoff_remaining=0
    last_failed_reason=""
    soft_reboot_pending=0
    soft_reboot_reason=""
    soft_reboot_wait_loops=0
    post_reboot_recheck=0
    WATCHDOG_INTERVAL="${AGH_WATCHDOG_INTERVAL:-60}"
    WATCHDOG_LOW_FREQ_TICKS="${AGH_WATCHDOG_LOW_FREQ_TICKS:-10}"
    case "$WATCHDOG_LOW_FREQ_TICKS" in
        ''|*[!0-9]*|0) WATCHDOG_LOW_FREQ_TICKS=10 ;;
    esac
    WATCHDOG_SOFT_REBOOT_POLL="${AGH_WATCHDOG_SOFT_REBOOT_POLL:-5}"
    case "$WATCHDOG_SOFT_REBOOT_POLL" in
        ''|*[!0-9]*|0) WATCHDOG_SOFT_REBOOT_POLL=5 ;;
    esac

    while [ "$ABORTED_BY_SIGNAL" = "0" ]; do
        _wd_sleep="$WATCHDOG_INTERVAL"
        if [ "$soft_reboot_pending" -eq 1 ]; then
            case "$WATCHDOG_INTERVAL" in
                ''|*[!0-9]*) ;;
                *)
                    if [ "$WATCHDOG_INTERVAL" -gt "$WATCHDOG_SOFT_REBOOT_POLL" ]; then
                        _wd_sleep="$WATCHDOG_SOFT_REBOOT_POLL"
                    fi
                    ;;
            esac
        fi
        safe_sleep "$_wd_sleep" || exit 0
        [ "$ABORTED_BY_SIGNAL" = "1" ] && break
        watchdog_tick=$((watchdog_tick + 1))

        # 软重启/开机过渡期间等待 Android 系统服务就绪（已就绪后缓存在内存，稳态不再调用 getprop）
        if [ "$boot_completed_cached" != "1" ] || [ "$soft_reboot_pending" -eq 1 ]; then
            if is_system_ready_after_soft_reboot "$soft_reboot_reason"; then
                boot_completed_cached="1"
                if [ "$NETD_TRACKING_ACTIVE" -eq 0 ]; then
                    resolve_netd_pid || true
                fi
                if [ "$SYS_SERVER_TRACKING_ACTIVE" -eq 0 ]; then
                    resolve_sys_server_pid || true
                fi
            elif [ "$soft_reboot_pending" -eq 1 ]; then
                soft_reboot_wait_loops=$((soft_reboot_wait_loops + 1))
                if [ "$soft_reboot_wait_loops" -ge 12 ]; then
                    boot_completed_cached="1"
                else
                    continue
                fi
            else
                continue
            fi
        fi

        load_runtime_config

        # 1. 严格尊重手动停止或模块禁用状态：纯 Shell 判定，绝不擅自重启核心或挂载规则
        if is_manually_stopped; then
            fail_streak=0
            backoff_remaining=0
            last_failed_reason=""
            soft_reboot_pending=0
            soft_reboot_reason=""
            soft_reboot_wait_loops=0
            post_reboot_recheck=0
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

        # 2. 统一失败退避门控：处于退避冷却期时直接跳过（零外部进程开销）
        if [ "$backoff_remaining" -gt 0 ]; then
            backoff_remaining=$((backoff_remaining - 1))
            continue
        fi

        need_repair=""

        # 3. 高频快速层（每 60 秒一次，纯 Shell 内置判断，稳态禁止调用 ps/pgrep/pidof/iptables/getprop）
        if ! is_agh_pid_alive_fast "$AGH_PID"; then
            _wd_pf_pid=""
            if [ -r "$PID_FILE" ]; then
                IFS= read -r _wd_pf_pid < "$PID_FILE" 2>/dev/null || _wd_pf_pid=""
            fi
            if [ -n "$_wd_pf_pid" ] && [ "$_wd_pf_pid" != "$AGH_PID" ] && is_agh_pid_alive_fast "$_wd_pf_pid"; then
                # 合法模式切换/手动重启更新了核心 PID，直接无感刷新缓存（若刚替换失败则由低频层兜底）
                AGH_PID="$_wd_pf_pid"
            else
                need_repair="core-exited"
            fi
        fi

        if [ -z "$need_repair" ] && [ "$NETD_TRACKING_ACTIVE" -eq 1 ]; then
            if ! is_pid_alive_fast "$NETD_PID" "$NETD_COMM"; then
                need_repair="netd-restarted"
            fi
        fi

        if [ -z "$need_repair" ] && [ "$SYS_SERVER_TRACKING_ACTIVE" -eq 1 ]; then
            if ! is_pid_alive_fast "$SYS_SERVER_PID" "$SYS_SERVER_COMM"; then
                need_repair="soft-reboot"
            fi
        fi

        detect_vpn_iface_fast
        if [ -z "$need_repair" ] && [ "$VPN_IFACE_STATE" != "$vpn_last" ]; then
            need_repair="vpn-$VPN_IFACE_STATE"
        fi

        if [ -z "$need_repair" ] && [ "$soft_reboot_pending" -eq 1 ]; then
            need_repair="${soft_reboot_reason:-soft-reboot}"
        fi

        # 软重启就绪门控：捕获到 netd/system_server 重启时若系统或新 system_server 尚在重启途中，切轻轮询等就绪后再修
        if [ "$need_repair" = "netd-restarted" ] || [ "$need_repair" = "soft-reboot" ]; then
            if [ "$soft_reboot_pending" -eq 0 ]; then
                if ! is_system_ready_after_soft_reboot "$need_repair"; then
                    boot_completed_cached=""
                    soft_reboot_pending=1
                    soft_reboot_reason="$need_repair"
                    soft_reboot_wait_loops=0
                    continue
                fi
            fi
            soft_reboot_pending=0
            soft_reboot_reason=""
            soft_reboot_wait_loops=0
        fi

        # 软重启恢复后连续两轮执行防余震复检（覆盖 +60s 与 +120s 的 ConnectivityService 延迟洗表并补刷 PID 追踪）
        if [ -z "$need_repair" ] && [ "$post_reboot_recheck" -gt 0 ]; then
            post_reboot_recheck=$((post_reboot_recheck - 1))
            if [ "$NETD_TRACKING_ACTIVE" -eq 0 ]; then
                resolve_netd_pid || true
            fi
            if [ "$SYS_SERVER_TRACKING_ACTIVE" -eq 0 ]; then
                resolve_sys_server_pid || true
            fi
            if ! agh_core_healthy "$redir_port"; then
                need_repair="post-reboot-core-unhealthy"
            elif ! nat_rules_healthy; then
                need_repair="post-reboot-nat-missing"
            fi
        fi

        # 若此前处于退避后的重试轮次且规则问题尚未确认恢复，主动触发一次轻量复检/修复
        if [ -z "$need_repair" ] && [ "$fail_streak" -gt 0 ]; then
            need_repair="${last_failed_reason:-backoff-retry}"
        fi

        # 4. 低频兜底层（默认 10 分钟执行一次轻量化规则与端口核验；系统重维护默认 20 分钟一次）
        if [ -z "$need_repair" ] && [ $((watchdog_tick % WATCHDOG_LOW_FREQ_TICKS)) -eq 0 ]; then
            WATCHDOG_MAINT_TICKS=$((WATCHDOG_LOW_FREQ_TICKS * 2))
            if [ $((watchdog_tick % WATCHDOG_MAINT_TICKS)) -eq 0 ]; then
                ensure_private_dns_off
                clean_deleted_app_dirs
                if [ -n "$PROXY_URL_CLEAN" ] && [ -f "$SCRIPT_DIR/ProxyConfig.sh" ]; then
                    AGH_OP_LOCK_HELD="" AGH_OP_LOCK_HOLDER_PID="" "$SH_BIN" "$SCRIPT_DIR/ProxyConfig.sh" --once </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&-
                fi
            fi
            if [ "$NETD_TRACKING_ACTIVE" -eq 0 ]; then
                resolve_netd_pid || true
            fi
            if [ "$SYS_SERVER_TRACKING_ACTIVE" -eq 0 ]; then
                resolve_sys_server_pid || true
            fi
            if ! agh_core_healthy "$redir_port"; then
                need_repair="lowfreq-core-unhealthy"
            elif ! nat_rules_healthy; then
                need_repair="nat-missing"
            else
                fail_streak=0
                backoff_remaining=0
                last_failed_reason=""
            fi
        fi

        # 5. 按需持锁修复与统一退避保护
        if [ -n "$need_repair" ]; then
            if acquire_op_lock 5; then
                load_runtime_config
                if is_manually_stopped; then
                    fail_streak=0
                    backoff_remaining=0
                    last_failed_reason=""
                    soft_reboot_pending=0
                    soft_reboot_reason=""
                    soft_reboot_wait_loops=0
                    post_reboot_recheck=0
                    release_op_lock
                    continue
                fi

                ensure_private_dns_off
                repair_ok=0
                if agh_core_healthy "$redir_port"; then
                    if { [ "$need_repair" = "core-exited" ] || [ "$need_repair" = "soft-reboot" ]; } && nat_rules_healthy; then
                        repair_ok=1
                    elif remount_nat_rules "$need_repair" && agh_core_healthy "$redir_port" && nat_rules_healthy; then
                        repair_ok=1
                    fi
                else
                    disarm_nat_safety_valve >/dev/null 2>&1 || true
                    log_msg "[WATCHDOG] 检测到 AdGuardHome 未运行或端口未完整监听，正在按当前模式恢复核心 (reason=$need_repair, streak=$((fail_streak + 1)))..."
                    if ensure_agh_started && remount_nat_rules "$need_repair" && agh_core_healthy "$redir_port" && nat_rules_healthy; then
                        repair_ok=1
                    fi
                fi

                refresh_watchdog_cached_pids
                detect_vpn_iface_fast

                if [ "$repair_ok" -eq 1 ]; then
                    vpn_last="$VPN_IFACE_STATE"
                    fail_streak=0
                    backoff_remaining=0
                    last_failed_reason=""
                    if [ "$need_repair" = "soft-reboot" ] || [ "$need_repair" = "netd-restarted" ]; then
                        post_reboot_recheck=2
                    fi
                else
                    fail_streak=$((fail_streak + 1))
                    last_failed_reason="$need_repair"
                    case "$fail_streak" in
                        1) backoff_remaining=1 ;;
                        2) backoff_remaining=5 ;;
                        3) backoff_remaining=10 ;;
                        *) backoff_remaining=15 ;;
                    esac
                    _wd_backoff_ticks=$((backoff_remaining + 1))
                    case "$WATCHDOG_INTERVAL" in
                        ''|*[!0-9]*) _wd_backoff_str="${_wd_backoff_ticks} 轮(${WATCHDOG_INTERVAL}s/轮)" ;;
                        *) _wd_backoff_str="$((_wd_backoff_ticks * WATCHDOG_INTERVAL)) 秒" ;;
                    esac
                    log_msg "[WATCHDOG] 核心或防火墙恢复失败 (reason=$need_repair, 连续第 ${fail_streak} 次)，退避 ${_wd_backoff_str}后重试"
                fi
                release_op_lock
            fi
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
    if [ "${AGH_TX_PRECLEANED:-0}" != "1" ] && has_residual_firewall_jumps; then
        disarm_nat_safety_valve >/dev/null 2>&1 || true
    fi
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

# 检查冲突的 hosts 模块并中止启动（绝不擅自修改或删除用户的其他模块）
found_hosts=false
for module in "$MODULES_DIR"/*; do
    [ -d "$module" ] && [ -f "$module/system/etc/hosts" ] && {
        found_hosts=true
        break
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

# 开机自动触发入口先等待 sys.boot_completed=1 就绪，防止框架未初始化完毕前重复挂载
if [ -z "${1:-}" ]; then
    _boot_wait_loops=0
    _boot_wait_max="${AGH_BOOT_WAIT_MAX_LOOPS:-25}"
    while [ "$_boot_wait_loops" -lt "$_boot_wait_max" ]; do
        _boot_done=$(getprop sys.boot_completed 2>/dev/null)
        [ -z "$_boot_done" ] || [ "$_boot_done" = "1" ] && break
        safe_sleep 1 || break
        _boot_wait_loops=$((_boot_wait_loops + 1))
    done
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

[ -f "$SCRIPT_DIR/NoAdsService.sh" ] && AGH_OP_LOCK_HELD="" AGH_OP_LOCK_HOLDER_PID="" "$SH_BIN" "$SCRIPT_DIR/NoAdsService.sh" </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
if [ -n "$PROXY_URL_CLEAN" ] && [ -f "$SCRIPT_DIR/ProxyConfig.sh" ]; then
    AGH_OP_LOCK_HELD="" AGH_OP_LOCK_HOLDER_PID="" "$SH_BIN" "$SCRIPT_DIR/ProxyConfig.sh" --once </dev/null >/dev/null 2>&1 7>&- 8>&- 9>&- &
fi

start_singleton_watchdog
exit 0
