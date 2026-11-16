#!/system/bin/sh
# ==============================================================================
# AdGuard Home GoGoGo - 海外 / 国内双模无损热切换脚本 (switch_mode.sh)
# 特性：
# 1. 在内核级 flock 生命周期操作锁 (OP_LOCK_FILE, FD 9) 内串行执行完整切换事务
# 2. 遵循严格提交与回退顺序：记录状态 → 停止核心并卸载规则 → 等待核心退出落盘 → 重新读取配置
#    → 仅按显式白名单更新模式字段 → 校验候选配置 → 保存真实切换前备份 → 原子替换
#    → 启动并校验核心与防火墙 → 确认成功后提交 RUN_MODE；任一步骤失败自动回退原配置与原状态
# 3. 显式字段白名单：仅更新 dns.upstream_dns / bootstrap_dns / fallback_dns，以及内置订阅
#    ID (1721861846, 1740000001, 1721861844) 的已知官方/镜像 URL 映射；其余所有 DNS 参数、
#    缓存、访问控制、DNSSEC、自定义订阅、自定义规则、注释、空列表及合法缩进 100% 保持
# ==============================================================================

trap '' HUP

SCRIPT_LABEL="switch_mode.sh"
SH_BIN="${SH_BIN:-/system/bin/sh}"
[ -x "$SH_BIN" ] || SH_BIN="/bin/sh"

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
MODDIR="${MODDIR:-/data/adb/modules/AdGuardHome}"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
YAML_FILE="$BIN_DIR/AdGuardHome.yaml"
BAK_YAML="$BIN_DIR/AdGuardHome.yaml.bak"
PROP_FILE="$SCRIPT_DIR/config.prop"
MAIN_LOG="$AGH_DIR/agh.log"
PID_FILE="$BIN_DIR/AdGuardHome.pid"
SERVICE_SH="$MODDIR/service.sh"
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
fi

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
# 内核 flock 能力统一探测与三步独立进程竞争自检（与 service.sh / iptables.sh 完全一致）
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
            exec 6>&- 2>/dev/null || true
            exit 1
        fi
        exec 6>&- 2>/dev/null || true
        exit 0
    ) 7>&- 8>&- 9>&-
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
            "$cbin" "$csub" -n 0 0<&7 >/dev/null 2>&1 || exit 12
        else
            "$cbin" -n 0 0<&7 >/dev/null 2>&1 || exit 12
        fi
        printf "%s\n" "$$" > "$ready" 2>/dev/null || exit 13
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
        exec 7>&- 2>/dev/null || true
        exit 0
    ' _ "$probe_f" "$probe_ready" "$probe_release" "$c_bin" "$c_sub" "${BB_BIN:-}" 7>&- 8>&- 9>&- &
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
                exec 7>&- 2>/dev/null || true
                exit 0
            fi
        else
            if "$cbin" -n 0 0<&7 >/dev/null 2>&1; then
                "$cbin" -u 0 0<&7 >/dev/null 2>&1 || true
                exec 7>&- 2>/dev/null || true
                exit 0
            fi
        fi
        exec 7>&- 2>/dev/null || true
        exit 1
    ' _ "$probe_f" "$c_bin" "$c_sub" 7>&- 8>&- 9>&-
    step2_rc=$?

    : > "$probe_release" 2>/dev/null
    wait "$p1_pid" 2>/dev/null
    step1_rc=$?

    "$SH_BIN" -c '
        pf="$1"; cbin="$2"; csub="$3"
        exec 7<>"$pf" 2>/dev/null || exit 31
        if [ -n "$csub" ]; then
            "$cbin" "$csub" -n 0 0<&7 >/dev/null 2>&1 || { exec 7>&- 2>/dev/null || true; exit 1; }
            "$cbin" "$csub" -u 0 0<&7 >/dev/null 2>&1 || true
        else
            "$cbin" -n 0 0<&7 >/dev/null 2>&1 || { exec 7>&- 2>/dev/null || true; exit 1; }
            "$cbin" -u 0 0<&7 >/dev/null 2>&1 || true
        fi
        exec 7>&- 2>/dev/null || true
        exit 0
    ' _ "$probe_f" "$c_bin" "$c_sub" 7>&- 8>&- 9>&-
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
TMP_YAML=""
PRE_SWITCH_BAK=""

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

diagnose_op_lock_timeout() {
    wait_secs="${1:-20}"
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
    max_wait="${1:-20}"
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
            export AGH_TX_FLOCK_BIN="$FLOCK_RESOLVED_BIN"
            export AGH_TX_FLOCK_SUBCMD="$FLOCK_RESOLVED_SUBCMD"
            export AGH_TX_FLOCK_KIND="$FLOCK_RESOLVED_KIND"
            export AGH_TX_FLOCK_IMPL="$FLOCK_RESOLVED_IMPL"
            export AGH_TX_FLOCK_TARGET="$FLOCK_RESOLVED_TARGET"
            export AGH_TX_FLOCK_CMD_STR="$FLOCK_RESOLVED_CMD_STR"
            export AGH_TX_FLOCK_VERIFY_STEPS="$FLOCK_VERIFY_STEPS"
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

terminate_active_child() {
    if [ -n "$ACTIVE_CHILD_PID" ]; then
        cpid="$ACTIVE_CHILD_PID"
        ACTIVE_CHILD_PID=""
        if kill -0 "$cpid" 2>/dev/null; then
            kill -TERM "$cpid" 2>/dev/null || true
            for _w in 1 2 3 4 5 6 7 8 9 10; do
                kill -0 "$cpid" 2>/dev/null || break
                safe_sleep 0.1 || sleep 1
            done
            kill -0 "$cpid" 2>/dev/null && kill -KILL "$cpid" 2>/dev/null || true
            wait "$cpid" 2>/dev/null || true
        fi
    fi
}

run_sync_child() {
    [ "$ABORTED_BY_SIGNAL" = "1" ] && return 143
    "$@" 7>&- 8>&- 9>&- &
    ACTIVE_CHILD_PID=$!
    wait "$ACTIVE_CHILD_PID" 2>/dev/null
    rc=$?
    ACTIVE_CHILD_PID=""
    if [ "$ABORTED_BY_SIGNAL" = "1" ]; then
        exit 143
    fi
    return "$rc"
}

cleanup_temp_files() {
    [ -n "$TMP_YAML" ] && rm -f "$TMP_YAML" 2>/dev/null
    [ -n "$PRE_SWITCH_BAK" ] && rm -f "$PRE_SWITCH_BAK" 2>/dev/null
}

on_script_exit() {
    terminate_active_child
    cleanup_temp_files
    release_op_lock
}

on_signal_abort() {
    sig_name="${1:-TERM}"
    ABORTED_BY_SIGNAL=1
    trap - EXIT INT TERM
    log_msg "[WARN] ${SCRIPT_LABEL} (PID $$) received $sig_name, terminating active child and aborting."
    terminate_active_child
    cleanup_temp_files
    release_op_lock
    exit 143
}

trap 'on_script_exit' EXIT
trap 'on_signal_abort INT' INT
trap 'on_signal_abort TERM' TERM

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

if [ "${1:-}" = "--diag-flock" ] || [ "${1:-}" = "diag-flock" ]; then
    diagnose_flock_state "${2:-}"
    exit $?
fi

TARGET_MODE="${1:-overseas}"
NO_RESTART="${2:-}"

case "$TARGET_MODE" in
    cn|CN) TARGET_MODE="cn" ;;
    overseas|OVERSEAS|global|GLOBAL) TARGET_MODE="overseas" ;;
    *)
        echo "$(date '+%F %T') [ERROR] Invalid target mode: $TARGET_MODE" >> "$MAIN_LOG" 2>/dev/null
        echo "AGH_SWITCH_RESULT status=error stage=invalid_mode mode=$TARGET_MODE"
        exit 1
        ;;
esac

TEMPLATE_FILE="$BIN_DIR/AdGuardHome_${TARGET_MODE}.yaml"
if [ ! -s "$TEMPLATE_FILE" ]; then
    echo "$(date '+%F %T') [ERROR] Mode template not found: $TEMPLATE_FILE" >> "$MAIN_LOG" 2>/dev/null
    echo "AGH_SWITCH_RESULT status=error stage=template_missing mode=$TARGET_MODE"
    exit 1
fi

validate_yaml_file() {
    vf="$1"
    [ -s "$vf" ] || return 1
    grep -q '^schema_version:' "$vf" 2>/dev/null || return 1
    grep -q '^dns:' "$vf" 2>/dev/null || return 1
    grep -q '^user_rules:' "$vf" 2>/dev/null || return 1
    if [ -x "$BIN_DIR/AdGuardHome" ]; then
        "$BIN_DIR/AdGuardHome" --version >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            "$BIN_DIR/AdGuardHome" --check-config -c "$vf" -w "$BIN_DIR" >/dev/null 2>&1 || return 1
        fi
    fi
    return 0
}

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
    for p in $(pidof AdGuardHome 2>/dev/null); do
        if [ "$(cat "$PROC_DIR/$p/comm" 2>/dev/null)" = "AdGuardHome" ]; then
            if [ -r "$PROC_DIR/$p/status" ]; then
                grep -qE "^Gid:[[:space:]]*[0-9]+[[:space:]]+${AGH_GID}([[:space:]]|$)" "$PROC_DIR/$p/status" 2>/dev/null || continue
            fi
            return 0
        fi
    done
    return 1
}

write_run_mode_prop() {
    mode_val="$1"
    port_val="${2:-}"
    [ -f "$PROP_FILE" ] || return 0
    prop_tmp="$PROP_FILE.tmp.$$"
    if ! awk -v m="$mode_val" -v p="$port_val" '
        BEGIN { seen_mode = 0 }
        /^STOPPED=/ || /^MANUAL_STOP=/ { next }
        /^RUN_MODE=/ {
            print "RUN_MODE=" m
            seen_mode = 1
            next
        }
        /^redir_port=/ {
            if (p != "") {
                print "redir_port=" p
            } else {
                print $0
            }
            next
        }
        { print $0 }
        END {
            if (!seen_mode) {
                print "RUN_MODE=" m
            }
        }
    ' "$PROP_FILE" > "$prop_tmp" 2>/dev/null; then
        rm -f "$prop_tmp" 2>/dev/null
        return 1
    fi
    if ! mv -f "$prop_tmp" "$PROP_FILE" 2>/dev/null; then
        rm -f "$prop_tmp" 2>/dev/null
        return 1
    fi
    return 0
}

# 基于显式字段白名单生成候选 YAML：
# 1. dns 段仅更新 upstream_dns、bootstrap_dns、fallback_dns 三个列表字段，其余所有字段、注释、缩进、空列表原样保留
# 2. filters / whitelist_filters 段仅针对内置订阅 ID (1721861846, 1740000001, 1721861844) 且 URL 精确匹配已知官方/镜像地址时映射 URL
generate_candidate_yaml() {
    src_yaml="$1"
    out_yaml="$2"
    awk -v target_mode="$TARGET_MODE" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        function emit_tpl_dns_key(k, key_indent, item_indent,    i, n) {
            n = tpl_count[k] + 0
            if (n == 0) {
                print key_indent k ": []"
            } else {
                print key_indent k ":"
                for (i = 1; i <= n; i++) {
                    print item_indent "- " tpl_items[k, i]
                }
            }
            seen_dns_key[k] = 1
        }
        function flush_filter_item(    i, line, id_val, target_url, old_url) {
            if (f_buf_n == 0) return
            id_val = ""
            for (i = 1; i <= f_buf_n; i++) {
                line = f_buf[i]
                if (line ~ /^[[:space:]]*id:[[:space:]]*[0-9]+([[:space:]]*(#.*)?)?$/) {
                    sub(/^[[:space:]]*id:[[:space:]]*/, "", line)
                    sub(/[[:space:]]*(#.*)?$/, "", line)
                    id_val = line
                    break
                }
            }
            for (i = 1; i <= f_buf_n; i++) {
                line = f_buf[i]
                if (line ~ /^[[:space:]]*url:[[:space:]]*/) {
                    if (cur_section == "filters" && id_val == "1721861846") {
                        if (target_mode == "cn") {
                            sub(/https:\/\/raw\.githubusercontent\.com\/8680\/GOODBYEADS\/master\/data\/rules\/dns\.txt/, "https://ghfast.top/raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt", line)
                        } else {
                            sub(/https:\/\/ghfast\.top\/raw\.githubusercontent\.com\/8680\/GOODBYEADS\/master\/data\/rules\/dns\.txt/, "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/dns.txt", line)
                        }
                    } else if (cur_section == "filters" && id_val == "1740000001") {
                        if (target_mode == "cn") {
                            sub(/https:\/\/raw\.githubusercontent\.com\/TG-Twilight\/AWAvenue-Ads-Rule\/main\/AWAvenue-Ads-Rule\.txt/, "https://ghfast.top/raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt", line)
                        } else {
                            sub(/https:\/\/ghfast\.top\/raw\.githubusercontent\.com\/TG-Twilight\/AWAvenue-Ads-Rule\/main\/AWAvenue-Ads-Rule\.txt/, "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt", line)
                        }
                    } else if (cur_section == "whitelist_filters" && id_val == "1721861844") {
                        if (target_mode == "cn") {
                            sub(/https:\/\/raw\.githubusercontent\.com\/8680\/GOODBYEADS\/master\/data\/rules\/allow\.txt/, "https://ghfast.top/raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt", line)
                        } else {
                            sub(/https:\/\/ghfast\.top\/raw\.githubusercontent\.com\/8680\/GOODBYEADS\/master\/data\/rules\/allow\.txt/, "https://raw.githubusercontent.com/8680/GOODBYEADS/master/data/rules/allow.txt", line)
                        }
                    }
                }
                print line
            }
            f_buf_n = 0
        }
        FILENAME == ARGV[1] {
            if (/^dns:[[:space:]]*(#.*)?$/) {
                in_tpl_dns = 1
                tpl_key = ""
                next
            }
            if (in_tpl_dns && /^[^[:space:]#]/) {
                in_tpl_dns = 0
                tpl_key = ""
            }
            if (in_tpl_dns) {
                if ($0 ~ /^[[:space:]]+(upstream_dns|bootstrap_dns|fallback_dns):[[:space:]]*(\[\])?[[:space:]]*(#.*)?$/) {
                    k = $0
                    sub(/^[[:space:]]+/, "", k)
                    sub(/:.*/, "", k)
                    tpl_key = k
                    tpl_count[tpl_key] = 0
                    next
                }
                if ($0 ~ /^[[:space:]]+[A-Za-z0-9_]+:/) {
                    tpl_key = ""
                    next
                }
                if (tpl_key != "" && $0 ~ /^[[:space:]]*-[[:space:]]+/) {
                    val = $0
                    sub(/^[[:space:]]*-[[:space:]]+/, "", val)
                    tpl_items[tpl_key, ++tpl_count[tpl_key]] = val
                }
            }
            next
        }
        FILENAME == ARGV[2] {
            # 处理顶层段落切换
            if (/^[^[:space:]#]/) {
                if (cur_section == "filters" || cur_section == "whitelist_filters") {
                    flush_filter_item()
                }
                if (cur_section == "dns") {
                    if (dns_child_indent == "") dns_child_indent = "  "
                    if (!seen_dns_key["upstream_dns"]) emit_tpl_dns_key("upstream_dns", dns_child_indent, dns_child_indent "  ")
                    if (!seen_dns_key["bootstrap_dns"]) emit_tpl_dns_key("bootstrap_dns", dns_child_indent, dns_child_indent "  ")
                    if (!seen_dns_key["fallback_dns"]) emit_tpl_dns_key("fallback_dns", dns_child_indent, dns_child_indent "  ")
                }
                skip_dns_list = 0
                if (/^dns:[[:space:]]*(#.*)?$/) {
                    cur_section = "dns"
                    dns_child_indent = ""
                    print $0
                    next
                } else if (/^filters:[[:space:]]*(#.*)?$/) {
                    cur_section = "filters"
                    print $0
                    next
                } else if (/^whitelist_filters:[[:space:]]*(#.*)?$/) {
                    cur_section = "whitelist_filters"
                    print $0
                    next
                } else {
                    cur_section = ""
                    print $0
                    next
                }
            }

            if (cur_section == "dns") {
                # 记录首个子键缩进
                if (dns_child_indent == "" && $0 ~ /^[[:space:]]+[A-Za-z0-9_]+:/) {
                    dns_child_indent = $0
                    sub(/[A-Za-z0-9_]+:.*/, "", dns_child_indent)
                }
                # 检查是否为白名单中的 3 个 DNS 列表键
                if ($0 ~ /^[[:space:]]+(upstream_dns|bootstrap_dns|fallback_dns):[[:space:]]*(\[\])?[[:space:]]*(#.*)?$/) {
                    k_indent = $0
                    sub(/[A-Za-z0-9_]+:.*/, "", k_indent)
                    k_name = $0
                    sub(/^[[:space:]]+/, "", k_name)
                    sub(/:.*/, "", k_name)
                    emit_tpl_dns_key(k_name, k_indent, k_indent "  ")
                    skip_dns_list = 1
                    next
                }
                if (skip_dns_list) {
                    if ($0 ~ /^[[:space:]]*-[[:space:]]*/ && $0 !~ /^[[:space:]]*#/) {
                        next
                    }
                    if ($0 ~ /^[[:space:]]*#/) {
                        print $0
                        next
                    }
                    if ($0 ~ /^[[:space:]]*$/) {
                        print $0
                        next
                    }
                    skip_dns_list = 0
                }
                print $0
                next
            }

            if (cur_section == "filters" || cur_section == "whitelist_filters") {
                if ($0 ~ /^[[:space:]]*-[[:space:]]+/) {
                    flush_filter_item()
                    f_buf[++f_buf_n] = $0
                    next
                }
                if (f_buf_n > 0) {
                    f_buf[++f_buf_n] = $0
                    next
                }
                print $0
                next
            }

            print $0
        }
        END {
            if (cur_section == "filters" || cur_section == "whitelist_filters") {
                flush_filter_item()
            }
            if (cur_section == "dns") {
                if (dns_child_indent == "") dns_child_indent = "  "
                if (!seen_dns_key["upstream_dns"]) emit_tpl_dns_key("upstream_dns", dns_child_indent, dns_child_indent "  ")
                if (!seen_dns_key["bootstrap_dns"]) emit_tpl_dns_key("bootstrap_dns", dns_child_indent, dns_child_indent "  ")
                if (!seen_dns_key["fallback_dns"]) emit_tpl_dns_key("fallback_dns", dns_child_indent, dns_child_indent "  ")
            }
        }
    ' "$TEMPLATE_FILE" "$src_yaml" > "$out_yaml" 2>/dev/null
}

# ==============================================================================
# 在生命周期操作锁内执行严格提交与回退流程
# ==============================================================================
init_monotonic_clock || true
t_sw_start=$(mono_now_ms || true)
if [ -z "${AGH_SWITCH_OP_ID:-}" ]; then
    case "${t_sw_start:-}" in
        ''|*[!0-9]*) AGH_SWITCH_OP_ID="sw_na_$$" ;;
        *) AGH_SWITCH_OP_ID="sw_${t_sw_start}_$$" ;;
    esac
fi
export AGH_SWITCH_OP_ID AGH_MONO_CLOCK_SOURCE AGH_MONO_BASE_SEC

if [ "${AGH_MONO_CLOCK_SOURCE:-unavailable}" = "unavailable" ]; then
    log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=clock_init status=unavailable source=unavailable reason=clock_source_unreadable"
fi

case "${AGH_QUEUE_WAIT_MS:-}" in
    ''|*[!0-9]*) ;;
    *)
        if ! command -v agh_diag_debug_active >/dev/null 2>&1 || agh_diag_debug_active; then
            log_msg "[TIMING] op_id=${AGH_SWITCH_OP_ID} stage=manager_queue_wait status=ok elapsed_ms=${AGH_QUEUE_WAIT_MS}"
        fi
        ;;
esac
command -v agh_log_debug >/dev/null 2>&1 && agh_log_debug "op_id=${AGH_SWITCH_OP_ID} script=switch_mode enter target=${TARGET_MODE} no_restart=${NO_RESTART:-none}"

extract_yaml_http_port() {
    awk '
        /^http:[[:space:]]*($|#)/ { in_http=1; next }
        in_http && /^[^[:space:]#]/ { exit }
        in_http && /^[[:space:]]*address:[[:space:]]*/ {
            val=$0
            sub(/^[[:space:]]*address:[[:space:]]*/, "", val)
            sub(/[[:space:]]*(#.*)?$/, "", val)
            gsub(/^["\047]|["\047]$/, "", val)
            sub(/.*:/, "", val)
            if (val ~ /^[0-9]+$/) { print val; exit }
        }
    ' "$1" 2>/dev/null
}

emit_switch_exit() {
    em_status="$1"
    em_stage="$2"
    em_code="${3:-1}"
    em_dns="${4:-}"
    em_http="${5:-}"
    t_ret=$(mono_now_ms || true)
    total_ms="unavailable"
    if is_signed_int "${t_sw_start:-}" && is_signed_int "${t_ret:-}"; then
        _em_diff=$((t_ret - t_sw_start))
        if [ "$_em_diff" -lt 0 ]; then
            total_ms="invalid"
        else
            total_ms="$_em_diff"
        fi
    fi
    log_stage_timing "script_return" "$em_status" "$t_sw_start" "$t_ret" "stage=${em_stage} target=${TARGET_MODE} source=${AGH_MONO_CLOCK_SOURCE:-unavailable}"
    extra_kv=""
    [ -n "$em_dns" ] && extra_kv="${extra_kv} dns_port=${em_dns}"
    [ -n "$em_http" ] && extra_kv="${extra_kv} http_port=${em_http}"
    echo "AGH_SWITCH_RESULT status=${em_status} stage=${em_stage} mode=${TARGET_MODE} op_id=${AGH_SWITCH_OP_ID}${extra_kv} total_ms=${total_ms}"
    unset AGH_TX_TARGET_MODE AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA AGH_TX_PRECLEANED
    exit "$em_code"
}

t_lock_start=$(mono_now_ms || true)
if ! acquire_op_lock 20; then
    t_lock_end=$(mono_now_ms || true)
    log_stage_timing "acquire_lock" "error" "$t_lock_start" "$t_lock_end" "target=${TARGET_MODE}"
    emit_switch_exit "error" "lock_timeout" 1
fi
t_lock_end=$(mono_now_ms || true)
log_stage_timing "acquire_lock" "ok" "$t_lock_start" "$t_lock_end" "target=${TARGET_MODE}"

# 1. 记录切换前状态，并检查现有配置是否损坏（已有配置损坏时不得静默当成首次安装）
t_precheck_start=$(mono_now_ms || true)
prev_mode="overseas"
if [ -f "$PROP_FILE" ]; then
    p_mode=$(sed -n 's/^RUN_MODE=//p' "$PROP_FILE" 2>/dev/null | head -n 1 | tr -d '\r[:space:]')
    [ -n "$p_mode" ] && prev_mode="$p_mode"
fi

had_yaml=0
pre_yaml_hash=""
if [ -e "$YAML_FILE" ]; then
    had_yaml=1
    if ! validate_yaml_file "$YAML_FILE"; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Existing $YAML_FILE is corrupted or invalid; refusing to treat as fresh install." >> "$MAIN_LOG" 2>/dev/null
        emit_switch_exit "error" "corrupt_existing_config" 1
    fi
    pre_yaml_hash=$(file_hash "$YAML_FILE" 2>/dev/null || true)
fi

was_running=0
agh_running && was_running=1
was_stopped=0
if [ -f "$SESSION_STOP_FILE" ] || [ -f "$AGH_DIR/manual_stop" ] || [ -f "$AGH_DIR/stopped" ] || [ -f "$AGH_DIR/app_pause_active" ]; then
    was_stopped=1
fi

# 2. 暂停接管并停止核心（如当前流程需要），等待核心完全退出并完成最后一次配置落盘
if [ "$NO_RESTART" != "--no-restart" ]; then
    if [ ! -f "$SERVICE_SH" ]; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: service.sh not found at $SERVICE_SH" >> "$MAIN_LOG" 2>/dev/null
        emit_switch_exit "error" "service_missing" 1
    fi
    t_stop_start=$(mono_now_ms || true)
    if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-stop-under-lock; then
        t_stop_end=$(mono_now_ms || true)
        log_stage_timing "stop_and_disarm" "error" "$t_stop_start" "$t_stop_end" "was_running=$was_running"
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Failed to stop core / disarm firewall before mode switch." >> "$MAIN_LOG" 2>/dev/null
        emit_switch_exit "error" "pre_stop_failed" 1
    fi
    t_stop_end=$(mono_now_ms || true)
    export AGH_TX_PRECLEANED=1
    log_stage_timing "stop_and_disarm" "ok" "$t_stop_start" "$t_stop_end" "was_running=$was_running"
else
    log_stage_timing "stop_and_disarm" "skipped" "$t_precheck_start" "$t_precheck_start" "reason=no_restart"
fi

# 3. 重新读取最终落盘的当前配置（核心退出未改动 YAML 时直接复用 Step 1 已验证哈希）
t_reread_start=$(mono_now_ms || true)
reread_cache_hit=0
if [ "$had_yaml" -eq 1 ] || [ -e "$YAML_FILE" ]; then
    had_yaml=1
    post_stop_hash=$(file_hash "$YAML_FILE" 2>/dev/null || true)
    if [ -n "$pre_yaml_hash" ] && [ "$post_stop_hash" = "$pre_yaml_hash" ]; then
        reread_cache_hit=1
    elif ! validate_yaml_file "$YAML_FILE"; then
        t_reread_end=$(mono_now_ms || true)
        log_stage_timing "reread_config" "error" "$t_reread_start" "$t_reread_end" "cache_hit=0"
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: On-disk $YAML_FILE invalid after core exit; aborting switch." >> "$MAIN_LOG" 2>/dev/null
        if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
            export AGH_TX_TARGET_MODE="$prev_mode"
            run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback >/dev/null 2>&1
        fi
        emit_switch_exit "error" "post_stop_config_corrupt" 1
    fi
fi
t_reread_end=$(mono_now_ms || true)
log_stage_timing "reread_config" "ok" "$t_reread_start" "$t_reread_end" "cache_hit=${reread_cache_hit}"

# 4 & 5. 生成并校验候选配置（失败时不覆盖原配置，若原本运行则恢复运行状态）
t_gen_start=$(mono_now_ms || true)
TMP_YAML="$YAML_FILE.switch.tmp.$$"
rm -f "$TMP_YAML" 2>/dev/null

if [ "$had_yaml" -eq 1 ]; then
    generate_candidate_yaml "$YAML_FILE" "$TMP_YAML"
else
    # 仅在首次安装尚无 AdGuardHome.yaml 时允许从已验证备份或模板初始化
    if [ -s "$BAK_YAML" ] && validate_yaml_file "$BAK_YAML"; then
        generate_candidate_yaml "$BAK_YAML" "$TMP_YAML"
    else
        cp -pf "$TEMPLATE_FILE" "$TMP_YAML" 2>/dev/null
    fi
fi

if ! validate_yaml_file "$TMP_YAML"; then
    t_gen_end=$(mono_now_ms || true)
    log_stage_timing "generate_and_validate" "error" "$t_gen_start" "$t_gen_end" "target=${TARGET_MODE}"
    echo "$(date '+%F %T') [ERROR] switch_mode.sh: Candidate YAML failed validation (--check-config), preserving original config." >> "$MAIN_LOG" 2>/dev/null
    rm -f "$TMP_YAML" 2>/dev/null
    TMP_YAML=""
    if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
        export AGH_TX_TARGET_MODE="$prev_mode"
        if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback; then
            echo "$(date '+%F %T') [CRITICAL] switch_mode.sh: Candidate validation failed AND restoring previous runtime failed!" >> "$MAIN_LOG" 2>/dev/null
            emit_switch_exit "error" "validation_failed_restore_failed" 1
        fi
    fi
    emit_switch_exit "error" "candidate_validation_failed" 1
fi

cand_yaml_sha=$(file_hash "$TMP_YAML" 2>/dev/null || true)
t_gen_end=$(mono_now_ms || true)
log_stage_timing "generate_and_validate" "ok" "$t_gen_start" "$t_gen_end" "target=${TARGET_MODE}"

# 提取候选配置中的 DNS 端口与 HTTP 端口
cur_dns_port=$(awk '/^dns:/{f=1;next} f&&/^[^[:space:]#]/{f=0} f&&/^[[:space:]]*port:[[:space:]]*[0-9]+/{sub(/.*port:[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, ""); print; exit}' "$TMP_YAML" 2>/dev/null)
cur_http_port=$(extract_yaml_http_port "$TMP_YAML")

# 6. 保存真正的切换前备份（绝不在替换后用新配置覆盖切换前备份）与 7. 原子替换配置
t_commit_cfg_start=$(mono_now_ms || true)
PRE_SWITCH_BAK="$YAML_FILE.pre_switch.$$"
rm -f "$PRE_SWITCH_BAK" 2>/dev/null
if [ "$had_yaml" -eq 1 ]; then
    if ! cp -pf "$YAML_FILE" "$PRE_SWITCH_BAK" 2>/dev/null || ! cmp -s "$YAML_FILE" "$PRE_SWITCH_BAK"; then
        t_commit_cfg_end=$(mono_now_ms || true)
        log_stage_timing "commit_config" "error" "$t_commit_cfg_start" "$t_commit_cfg_end" "reason=pre_backup_failed"
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Failed to save pre-switch backup before replacing config!" >> "$MAIN_LOG" 2>/dev/null
        rm -f "$TMP_YAML" "$PRE_SWITCH_BAK" 2>/dev/null
        TMP_YAML=""
        PRE_SWITCH_BAK=""
        if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
            export AGH_TX_TARGET_MODE="$prev_mode"
            run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback >/dev/null 2>&1
        fi
        emit_switch_exit "error" "pre_backup_failed" 1
    fi
    cp -pf "$PRE_SWITCH_BAK" "$BAK_YAML" 2>/dev/null
fi

if ! mv -f "$TMP_YAML" "$YAML_FILE" 2>/dev/null; then
    t_commit_cfg_end=$(mono_now_ms || true)
    log_stage_timing "commit_config" "error" "$t_commit_cfg_start" "$t_commit_cfg_end" "reason=atomic_replace_failed"
    echo "$(date '+%F %T') [ERROR] switch_mode.sh: Atomic mv to $YAML_FILE failed!" >> "$MAIN_LOG" 2>/dev/null
    rm -f "$TMP_YAML" 2>/dev/null
    TMP_YAML=""
    if [ "$had_yaml" -eq 1 ] && [ -f "$PRE_SWITCH_BAK" ]; then
        cp -pf "$PRE_SWITCH_BAK" "$YAML_FILE" 2>/dev/null
    fi
    if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
        export AGH_TX_TARGET_MODE="$prev_mode"
        run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback >/dev/null 2>&1
    fi
    emit_switch_exit "error" "atomic_replace_failed" 1
fi
TMP_YAML=""
if [ -n "$cand_yaml_sha" ]; then
    export AGH_TX_VALIDATED_YAML_FILE="$YAML_FILE"
    export AGH_TX_VALIDATED_YAML_SHA="$cand_yaml_sha"
fi
t_commit_cfg_end=$(mono_now_ms || true)
log_stage_timing "commit_config" "ok" "$t_commit_cfg_start" "$t_commit_cfg_end" "target=${TARGET_MODE}"

# 8. 启动并检查核心 + 应用并检查必要接管（非 --no-restart 模式）
if [ "$NO_RESTART" != "--no-restart" ]; then
    rm -f /dev/shm/agh_manual_stop "$AGH_DIR/run/agh_manual_stop" \
          "$SESSION_STOP_FILE" "$AGH_DIR/manual_stop" "$AGH_DIR/stopped" "$AGH_DIR/app_pause_active" 2>/dev/null
    if [ -f "$PROP_FILE" ] && grep -qE '^(STOPPED|MANUAL_STOP)=' "$PROP_FILE" 2>/dev/null; then
        prop_clean_tmp="$PROP_FILE.clean.$$"
        if grep -vE '^(STOPPED|MANUAL_STOP)=' "$PROP_FILE" > "$prop_clean_tmp" 2>/dev/null; then
            mv -f "$prop_clean_tmp" "$PROP_FILE" 2>/dev/null
        else
            rm -f "$prop_clean_tmp" 2>/dev/null
        fi
    fi

    export AGH_TX_TARGET_MODE="$TARGET_MODE"
    if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock mode-switch; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Post-switch core start or firewall mount failed! Rolling back to pre-switch config and mode ($prev_mode)." >> "$MAIN_LOG" 2>/dev/null
        unset AGH_TX_VALIDATED_YAML_FILE AGH_TX_VALIDATED_YAML_SHA
        export AGH_TX_TARGET_MODE="$prev_mode"
        run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-stop-under-lock >/dev/null 2>&1
        rollback_ok=1
        if [ "$had_yaml" -eq 1 ]; then
            if [ -f "$PRE_SWITCH_BAK" ] && cp -pf "$PRE_SWITCH_BAK" "$YAML_FILE" 2>/dev/null && cmp -s "$PRE_SWITCH_BAK" "$YAML_FILE"; then
                cp -pf "$PRE_SWITCH_BAK" "$BAK_YAML" 2>/dev/null
            else
                rollback_ok=0
            fi
        else
            rm -f "$YAML_FILE" 2>/dev/null
        fi
        write_run_mode_prop "$prev_mode" >/dev/null 2>&1 || rollback_ok=0

        if [ "$was_stopped" -eq 1 ]; then
            : > "$SESSION_STOP_FILE" 2>/dev/null
        elif [ "$was_running" -eq 1 ]; then
            export AGH_TX_PRECLEANED=1
            if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback; then
                rollback_ok=0
            fi
        fi

        rm -f "$PRE_SWITCH_BAK" 2>/dev/null
        PRE_SWITCH_BAK=""
        if [ "$rollback_ok" -ne 1 ]; then
            echo "$(date '+%F %T') [CRITICAL] switch_mode.sh: Mode switch failed AND rollback to previous state ($prev_mode) failed!" >> "$MAIN_LOG" 2>/dev/null
            emit_switch_exit "error" "rollback_failed" 1
        fi
        echo "$(date '+%F %T') [WARN] switch_mode.sh: Rolled back configuration and runtime state to $prev_mode." >> "$MAIN_LOG" 2>/dev/null
        emit_switch_exit "error" "start_or_mount_failed_rolled_back" 1
    fi
fi

# 9. 确认成功后提交模式记录
t_commit_mode_start=$(mono_now_ms || true)
if ! write_run_mode_prop "$TARGET_MODE" "$cur_dns_port"; then
    t_commit_mode_end=$(mono_now_ms || true)
    log_stage_timing "commit_run_mode" "error" "$t_commit_mode_start" "$t_commit_mode_end" "target=${TARGET_MODE}"
    echo "$(date '+%F %T') [ERROR] switch_mode.sh: Failed to persist RUN_MODE=$TARGET_MODE to $PROP_FILE" >> "$MAIN_LOG" 2>/dev/null
    emit_switch_exit "error" "commit_prop_failed" 1
fi
t_commit_mode_end=$(mono_now_ms || true)
log_stage_timing "commit_run_mode" "ok" "$t_commit_mode_start" "$t_commit_mode_end" "mode=${TARGET_MODE}"

rm -f "$PRE_SWITCH_BAK" 2>/dev/null
PRE_SWITCH_BAK=""
echo "$(date '+%F %T') [INFO] switch_mode.sh: Mode switch to $TARGET_MODE committed successfully." >> "$MAIN_LOG" 2>/dev/null
emit_switch_exit "ok" "completed" 0 "$cur_dns_port" "$cur_http_port"
