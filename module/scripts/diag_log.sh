#!/system/bin/sh
# ==============================================================================
# diag_log.sh - 模块共用诊断开关解析与有界日志轮转辅助
# 特性：
# 1. 不使用 source / eval 解析 diag.conf，严格白名单键值解析，异常按关闭处理
# 2. 详细调试日志默认关闭，到期时间由写日志前惰性校验（零新增常驻进程/定时器/Wakelock）
# 3. 256 KiB 单文件上限 + 最多 1 份历史滚动日志 (agh.log + agh.log.1 ≈ 512 KiB 总上限)
# 4. 每次追加走“准备文本 -> 取 FD 6 短有界 flock -> 阈值原子 mv 轮转 -> 打开并追加 -> 关闭日志 -> 释放锁”短事务
# 5. 绝不复用生命周期操作锁；绝不无锁写回同一文件绕过协调；取锁失败/写入错误按尽力记录静默降级返回 0
# ==============================================================================

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
RUN_DIR="${RUN_DIR:-$AGH_DIR/run}"
DIAG_CONF_FILE="${DIAG_CONF_FILE:-$AGH_DIR/diag.conf}"
MAIN_LOG="${MAIN_LOG:-$AGH_DIR/agh.log}"
AGH_LOG_MAX_BYTES="${AGH_LOG_MAX_BYTES:-262144}"
AGH_LOG_FLOCK_FILE="${AGH_LOG_FLOCK_FILE:-$RUN_DIR/agh_log.flock}"

_AGH_LOG_FLOCK_INIT="${_AGH_LOG_FLOCK_INIT:-0}"
_AGH_LOG_FLOCK_BIN="${_AGH_LOG_FLOCK_BIN:-}"
_AGH_LOG_FLOCK_SUB="${_AGH_LOG_FLOCK_SUB:-}"

_agh_strip_leading_zeros() {
    _slz_v="${1:-0}"
    while :; do
        case "$_slz_v" in
            0[0-9]*) _slz_v="${_slz_v#0}" ;;
            *) break ;;
        esac
    done
    printf '%s\n' "$_slz_v"
}

agh_diag_write_conf() {
    _dwc_en="${1:-0}"
    _dwc_exp="${2:-0}"
    [ "$_dwc_en" = "1" ] || _dwc_en="0"
    case "$_dwc_exp" in
        ''|*[!0-9]*) _dwc_exp="0" ;;
        *) _dwc_exp=$(_agh_strip_leading_zeros "$_dwc_exp") ;;
    esac
    [ -d "$AGH_DIR" ] || mkdir -p "$AGH_DIR" 2>/dev/null || return 1
    _dwc_tmp="${DIAG_CONF_FILE}.tmp.$$"
    {
        printf 'debug_enabled=%s\n' "$_dwc_en"
        printf 'debug_expire_epoch=%s\n' "$_dwc_exp"
    } > "$_dwc_tmp" 2>/dev/null || {
        rm -f "$_dwc_tmp" 2>/dev/null || true
        return 1
    }
    chmod 0600 "$_dwc_tmp" 2>/dev/null || true
    if ! mv -f "$_dwc_tmp" "$DIAG_CONF_FILE" 2>/dev/null; then
        rm -f "$_dwc_tmp" 2>/dev/null || true
        return 1
    fi
    chmod 0600 "$DIAG_CONF_FILE" 2>/dev/null || true
    return 0
}

# 严格解析独立诊断配置文件；超时自动失效且失败闭合（默认返回 1=关闭）
agh_diag_debug_active() {
    [ -f "$DIAG_CONF_FILE" ] && [ -r "$DIAG_CONF_FILE" ] || return 1
    _dda_en="0"
    _dda_exp=""
    _dda_invalid=0
    while IFS= read -r _dda_line || [ -n "$_dda_line" ]; do
        _dda_line=$(printf '%s' "$_dda_line" | tr -d '\r')
        case "$_dda_line" in
            ''|'#'*) continue ;;
            debug_enabled=*)
                _dda_v="${_dda_line#debug_enabled=}"
                case "$_dda_v" in
                    0|1) _dda_en="$_dda_v" ;;
                    *) _dda_invalid=1 ;;
                esac
                ;;
            debug_expire_epoch=*)
                _dda_v="${_dda_line#debug_expire_epoch=}"
                case "$_dda_v" in
                    ''|*[!0-9]*) _dda_invalid=1 ;;
                    *) _dda_exp=$(_agh_strip_leading_zeros "$_dda_v") ;;
                esac
                ;;
            *)
                _dda_invalid=1
                ;;
        esac
    done < "$DIAG_CONF_FILE" 2>/dev/null || return 1

    [ "$_dda_invalid" -eq 0 ] || return 1
    [ "$_dda_en" = "1" ] || return 1
    case "${_dda_exp:-}" in
        ''|*[!0-9]*|0) return 1 ;;
    esac

    _dda_now="${AGH_DIAG_NOW_EPOCH:-}"
    if [ -z "$_dda_now" ]; then
        _dda_now=$(date +%s 2>/dev/null || true)
    fi
    case "${_dda_now:-}" in
        ''|*[!0-9]*) return 1 ;;
    esac
    _dda_now=$(_agh_strip_leading_zeros "$_dda_now")
    [ "$_dda_now" -gt 0 ] || return 1

    if [ "$_dda_now" -ge "$_dda_exp" ]; then
        # 已到期：尝试惰性写回关闭状态，并立即按关闭返回
        agh_diag_write_conf 0 "$_dda_exp" >/dev/null 2>&1 || true
        return 1
    fi
    return 0
}

_agh_find_log_flock() {
    if [ "${_AGH_LOG_FLOCK_INIT:-0}" -eq 1 ]; then
        [ -n "${_AGH_LOG_FLOCK_BIN:-}" ]
        return $?
    fi
    _AGH_LOG_FLOCK_INIT=1
    _AGH_LOG_FLOCK_BIN=""
    _AGH_LOG_FLOCK_SUB=""

    if [ -n "${FLOCK_RESOLVED_BIN:-}" ] && [ -x "$FLOCK_RESOLVED_BIN" ]; then
        _AGH_LOG_FLOCK_BIN="$FLOCK_RESOLVED_BIN"
        _AGH_LOG_FLOCK_SUB="${FLOCK_RESOLVED_SUBCMD:-}"
        return 0
    fi

    if [ -n "${FLOCK_BIN:-}" ] && [ -x "$FLOCK_BIN" ]; then
        _AGH_LOG_FLOCK_BIN="$FLOCK_BIN"
        return 0
    fi

    for _fl_bb in /data/adb/magisk/busybox /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /system/xbin/busybox /system/bin/busybox; do
        [ -x "$_fl_bb" ] || continue
        case "$("$_fl_bb" --list 2>/dev/null || true)" in
            *flock*)
                _AGH_LOG_FLOCK_BIN="$_fl_bb"
                _AGH_LOG_FLOCK_SUB="flock"
                return 0
                ;;
        esac
    done
    _fl_bb_path=$(command -v busybox 2>/dev/null || true)
    if [ -n "$_fl_bb_path" ] && [ -x "$_fl_bb_path" ]; then
        case "$("$_fl_bb_path" --list 2>/dev/null || true)" in
            *flock*)
                _AGH_LOG_FLOCK_BIN="$_fl_bb_path"
                _AGH_LOG_FLOCK_SUB="flock"
                return 0
                ;;
        esac
    fi

    _fl_sys=$(command -v flock 2>/dev/null || true)
    if [ -n "$_fl_sys" ] && [ -x "$_fl_sys" ]; then
        _AGH_LOG_FLOCK_BIN="$_fl_sys"
        return 0
    fi

    for _fl_tb in /system/bin/toybox /vendor/bin/toybox "$(command -v toybox 2>/dev/null || true)"; do
        [ -n "$_fl_tb" ] && [ -x "$_fl_tb" ] || continue
        case "$("$_fl_tb" 2>/dev/null || true)" in
            *flock*)
                _AGH_LOG_FLOCK_BIN="$_fl_tb"
                _AGH_LOG_FLOCK_SUB="flock"
                return 0
                ;;
        esac
    done

    return 1
}

_agh_short_sleep_tick() {
    case "${_AGH_LOG_SLEEP_KIND:-}" in
        sleep)   sleep 0.015 >/dev/null 2>&1 && return 0 ;;
        usleep)  usleep 15000 >/dev/null 2>&1 && return 0 ;;
        toybox)  /system/bin/toybox sleep 0.015 >/dev/null 2>&1 && return 0 ;;
        busybox) [ -n "${_AGH_LOG_FLOCK_BIN:-}" ] && "$_AGH_LOG_FLOCK_BIN" sleep 0.015 >/dev/null 2>&1 && return 0 ;;
        none)    return 1 ;;
    esac

    if sleep 0.01 >/dev/null 2>&1; then
        _AGH_LOG_SLEEP_KIND="sleep"
        sleep 0.015 >/dev/null 2>&1 || true
        return 0
    elif command -v usleep >/dev/null 2>&1 && usleep 1000 >/dev/null 2>&1; then
        _AGH_LOG_SLEEP_KIND="usleep"
        usleep 15000 >/dev/null 2>&1 || true
        return 0
    elif [ -x /system/bin/toybox ] && /system/bin/toybox sleep 0.01 >/dev/null 2>&1; then
        _AGH_LOG_SLEEP_KIND="toybox"
        /system/bin/toybox sleep 0.015 >/dev/null 2>&1 || true
        return 0
    elif [ -n "${_AGH_LOG_FLOCK_BIN:-}" ] && [ "${_AGH_LOG_FLOCK_SUB:-}" = "flock" ] && "$_AGH_LOG_FLOCK_BIN" sleep 0.01 >/dev/null 2>&1; then
        _AGH_LOG_SLEEP_KIND="busybox"
        "$_AGH_LOG_FLOCK_BIN" sleep 0.015 >/dev/null 2>&1 || true
        return 0
    fi
    _AGH_LOG_SLEEP_KIND="none"
    return 1
}

_agh_log_rotate_locked() {
    _arl_log="${1:-$MAIN_LOG}"
    _arl_max="${2:-262144}"
    [ -f "$_arl_log" ] || return 0
    case "${_arl_max:-}" in
        ''|*[!0-9]*) _arl_max=262144 ;;
    esac
    _arl_sz=$({ wc -c < "$_arl_log"; } 2>/dev/null || true)
    set -- $_arl_sz
    _arl_sz="${1:-0}"
    case "${_arl_sz:-}" in
        ''|*[!0-9]*) _arl_sz=0 ;;
    esac
    if [ "$_arl_sz" -ge "$_arl_max" ]; then
        if mv -f "$_arl_log" "${_arl_log}.1" 2>/dev/null; then
            chmod 0600 "${_arl_log}.1" 2>/dev/null || true
        fi
    fi
    return 0
}

_agh_acquire_log_lock_fd6() {
    _all_retries="${1:-16}"
    _all_try=0
    while [ "$_all_try" -lt "$_all_retries" ]; do
        if [ -n "${_AGH_LOG_FLOCK_SUB:-}" ]; then
            "$_AGH_LOG_FLOCK_BIN" "$_AGH_LOG_FLOCK_SUB" -n 0 0<&6 >/dev/null 2>&1 && return 0
        else
            "$_AGH_LOG_FLOCK_BIN" -n 0 0<&6 >/dev/null 2>&1 && return 0
        fi
        _all_try=$((_all_try + 1))
        [ "$_all_try" -lt "$_all_retries" ] || break
        _agh_short_sleep_tick || break
    done
    return 1
}

_agh_log_rotate_if_needed() {
    _alr_log="${1:-$MAIN_LOG}"
    [ -f "$_alr_log" ] || return 0
    _alr_max="${AGH_LOG_MAX_BYTES:-262144}"
    case "${_alr_max:-}" in
        ''|*[!0-9]*) _alr_max=262144 ;;
    esac
    _agh_find_log_flock || return 0
    _alr_flock_file="${AGH_LOG_FLOCK_FILE:-$RUN_DIR/agh_log.flock}"
    _alr_lock_parent="${_alr_flock_file%/*}"
    if [ -n "$_alr_lock_parent" ] && [ "$_alr_lock_parent" != "$_alr_flock_file" ] && [ ! -d "$_alr_lock_parent" ]; then
        mkdir -p "$_alr_lock_parent" 2>/dev/null || return 0
    fi
    (
        { exec 6<>"$_alr_flock_file"; } 2>/dev/null || exit 0
        _agh_acquire_log_lock_fd6 3 || exit 0
        _agh_log_rotate_locked "$_alr_log" "$_alr_max" || true
        exit 0
    ) 7>&- 8>&- 9>&- || true
    return 0
}

agh_log_always() {
    _ala_msg="$1"
    _ala_log="${MAIN_LOG:-/data/adb/agh/agh.log}"
    [ -n "$_ala_log" ] || return 0

    # 1. 在取锁前先准备本条完整日志文本，缩短持锁耗时
    _ala_ts=$(date '+%F %T' 2>/dev/null || echo '0000-00-00 00:00:00')
    _ala_line="${_ala_ts} ${_ala_msg}"

    # 2. 解析独立日志 flock；不可用时直接降级放弃，绝不无锁写回同一文件绕过协调
    _agh_find_log_flock || return 0

    _ala_flock_file="${AGH_LOG_FLOCK_FILE:-$RUN_DIR/agh_log.flock}"
    _ala_lock_parent="${_ala_flock_file%/*}"
    if [ -n "$_ala_lock_parent" ] && [ "$_ala_lock_parent" != "$_ala_flock_file" ] && [ ! -d "$_ala_lock_parent" ]; then
        mkdir -p "$_ala_lock_parent" 2>/dev/null || return 0
    fi

    _ala_dir="${_ala_log%/*}"
    _ala_max="${AGH_LOG_MAX_BYTES:-262144}"
    case "${_ala_max:-}" in
        ''|*[!0-9]*) _ala_max=262144 ;;
    esac
    _ala_retries="${AGH_LOG_LOCK_MAX_RETRIES:-16}"
    case "${_ala_retries:-}" in
        ''|*[!0-9]*) _ala_retries=16 ;;
    esac
    [ "$_ala_retries" -le 20 ] || _ala_retries=20

    # 3-6. 短事务（持独立 FD 6 日志锁后才打开当前日志文件）：
    # 取得日志锁 -> 检查大小并按策略原子 mv 轮转 -> 打开当前日志并追加 -> 关闭日志 FD -> 子 shell 退出自动释放锁
    (
        { exec 6<>"$_ala_flock_file"; } 2>/dev/null || exit 0
        _agh_acquire_log_lock_fd6 "$_ala_retries" || exit 0
        if [ -n "$_ala_dir" ] && [ "$_ala_dir" != "$_ala_log" ] && [ ! -d "$_ala_dir" ]; then
            mkdir -p "$_ala_dir" 2>/dev/null || exit 0
        fi
        _agh_log_rotate_locked "$_ala_log" "$_ala_max" || true
        { printf '%s\n' "$_ala_line" >> "$_ala_log"; } 2>/dev/null || exit 0
        exit 0
    ) 7>&- 8>&- 9>&- || true
    return 0
}

agh_log_debug() {
    agh_diag_debug_active || return 0
    agh_log_always "[DEBUG] $1"
}
