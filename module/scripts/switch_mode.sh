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

SH_BIN="/system/bin/sh"
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

BUSYBOX_BIN=""
for bb in /data/adb/ksu/bin/busybox /data/adb/ap/bin/busybox /data/adb/magisk/busybox /debug_ramdisk/.magisk/busybox/busybox /sbin/.magisk/busybox/busybox; do
    if [ -x "$bb" ]; then
        BUSYBOX_BIN="$bb"
        command -v awk >/dev/null 2>&1 || awk() { "$bb" awk "$@"; }
        command -v pidof >/dev/null 2>&1 || pidof() { "$bb" pidof "$@"; }
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

# ==============================================================================
# 内核级 flock 锁与信号安全处理
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
TMP_YAML=""
PRE_SWITCH_BAK=""

acquire_op_lock() {
    max_wait="${1:-20}"
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
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: kernel flock utility not available, refusing unlocked execution." >> "$MAIN_LOG" 2>/dev/null
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
    echo "$(date '+%F %T') [WARN] switch_mode.sh: timed out waiting for operation lock after ${max_wait}s (last recorded holder PID ${holder:-unknown})" >> "$MAIN_LOG" 2>/dev/null
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

run_sync_child() {
    "$@" &
    ACTIVE_CHILD_PID=$!
    wait "$ACTIVE_CHILD_PID"
    rc=$?
    ACTIVE_CHILD_PID=""
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
    trap - EXIT INT TERM
    echo "$(date '+%F %T') [WARN] switch_mode.sh (PID $$) received $sig_name, terminating active child and aborting." >> "$MAIN_LOG" 2>/dev/null
    terminate_active_child
    cleanup_temp_files
    release_op_lock
    exit 130
}

trap 'on_script_exit' EXIT
trap 'on_signal_abort INT' INT
trap 'on_signal_abort TERM' TERM

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
if ! acquire_op_lock 20; then
    echo "AGH_SWITCH_RESULT status=error stage=lock_timeout mode=$TARGET_MODE"
    exit 1
fi

# 1. 记录切换前状态，并检查现有配置是否损坏（已有配置损坏时不得静默当成首次安装）
prev_mode="overseas"
if [ -f "$PROP_FILE" ]; then
    p_mode=$(sed -n 's/^RUN_MODE=//p' "$PROP_FILE" 2>/dev/null | head -n 1 | tr -d '\r[:space:]')
    [ -n "$p_mode" ] && prev_mode="$p_mode"
fi

had_yaml=0
if [ -e "$YAML_FILE" ]; then
    had_yaml=1
    if ! validate_yaml_file "$YAML_FILE"; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Existing $YAML_FILE is corrupted or invalid; refusing to treat as fresh install." >> "$MAIN_LOG" 2>/dev/null
        echo "AGH_SWITCH_RESULT status=error stage=corrupt_existing_config mode=$TARGET_MODE"
        exit 1
    fi
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
        echo "AGH_SWITCH_RESULT status=error stage=service_missing mode=$TARGET_MODE"
        exit 1
    fi
    if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-stop-under-lock; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Failed to stop core / disarm firewall before mode switch." >> "$MAIN_LOG" 2>/dev/null
        echo "AGH_SWITCH_RESULT status=error stage=pre_stop_failed mode=$TARGET_MODE"
        exit 1
    fi
fi

# 3. 重新读取最终落盘的当前配置
if [ "$had_yaml" -eq 1 ] || [ -e "$YAML_FILE" ]; then
    had_yaml=1
    if ! validate_yaml_file "$YAML_FILE"; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: On-disk $YAML_FILE invalid after core exit; aborting switch." >> "$MAIN_LOG" 2>/dev/null
        if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
            run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback >/dev/null 2>&1
        fi
        echo "AGH_SWITCH_RESULT status=error stage=post_stop_config_corrupt mode=$TARGET_MODE"
        exit 1
    fi
fi

# 4. 生成候选配置
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

# 5. 校验候选配置（失败时不覆盖原配置，若原本运行则恢复运行状态）
if ! validate_yaml_file "$TMP_YAML"; then
    echo "$(date '+%F %T') [ERROR] switch_mode.sh: Candidate YAML failed validation (--check-config), preserving original config." >> "$MAIN_LOG" 2>/dev/null
    rm -f "$TMP_YAML" 2>/dev/null
    TMP_YAML=""
    if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
        if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback; then
            echo "$(date '+%F %T') [CRITICAL] switch_mode.sh: Candidate validation failed AND restoring previous runtime failed!" >> "$MAIN_LOG" 2>/dev/null
            echo "AGH_SWITCH_RESULT status=error stage=validation_failed_restore_failed mode=$TARGET_MODE"
            exit 1
        fi
    fi
    echo "AGH_SWITCH_RESULT status=error stage=candidate_validation_failed mode=$TARGET_MODE"
    exit 1
fi

# 提取候选配置中的 DNS 端口
cur_dns_port=$(awk '/^dns:/{f=1;next} f&&/^[^[:space:]#]/{f=0} f&&/^[[:space:]]*port:[[:space:]]*[0-9]+/{sub(/.*port:[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, ""); print; exit}' "$TMP_YAML" 2>/dev/null)

# 6. 保存真正的切换前备份（绝不在替换后用新配置覆盖切换前备份）
PRE_SWITCH_BAK="$YAML_FILE.pre_switch.$$"
rm -f "$PRE_SWITCH_BAK" 2>/dev/null
if [ "$had_yaml" -eq 1 ]; then
    if ! cp -pf "$YAML_FILE" "$PRE_SWITCH_BAK" 2>/dev/null || ! cmp -s "$YAML_FILE" "$PRE_SWITCH_BAK"; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Failed to save pre-switch backup before replacing config!" >> "$MAIN_LOG" 2>/dev/null
        rm -f "$TMP_YAML" "$PRE_SWITCH_BAK" 2>/dev/null
        TMP_YAML=""
        PRE_SWITCH_BAK=""
        if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
            run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback >/dev/null 2>&1
        fi
        echo "AGH_SWITCH_RESULT status=error stage=pre_backup_failed mode=$TARGET_MODE"
        exit 1
    fi
    cp -pf "$PRE_SWITCH_BAK" "$BAK_YAML" 2>/dev/null
fi

# 7. 原子替换配置
if ! mv -f "$TMP_YAML" "$YAML_FILE" 2>/dev/null; then
    echo "$(date '+%F %T') [ERROR] switch_mode.sh: Atomic mv to $YAML_FILE failed!" >> "$MAIN_LOG" 2>/dev/null
    rm -f "$TMP_YAML" 2>/dev/null
    TMP_YAML=""
    if [ "$had_yaml" -eq 1 ] && [ -f "$PRE_SWITCH_BAK" ]; then
        cp -pf "$PRE_SWITCH_BAK" "$YAML_FILE" 2>/dev/null
    fi
    if [ "$NO_RESTART" != "--no-restart" ] && [ "$was_running" -eq 1 ] && [ "$was_stopped" -eq 0 ]; then
        run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback >/dev/null 2>&1
    fi
    echo "AGH_SWITCH_RESULT status=error stage=atomic_replace_failed mode=$TARGET_MODE"
    exit 1
fi
TMP_YAML=""

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

    if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock mode-switch; then
        echo "$(date '+%F %T') [ERROR] switch_mode.sh: Post-switch core start or firewall mount failed! Rolling back to pre-switch config and mode ($prev_mode)." >> "$MAIN_LOG" 2>/dev/null
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
            if ! run_sync_child "$SH_BIN" "$SERVICE_SH" --internal-start-and-mount-under-lock rollback; then
                rollback_ok=0
            fi
        fi

        rm -f "$PRE_SWITCH_BAK" 2>/dev/null
        PRE_SWITCH_BAK=""
        if [ "$rollback_ok" -ne 1 ]; then
            echo "$(date '+%F %T') [CRITICAL] switch_mode.sh: Mode switch failed AND rollback to previous state ($prev_mode) failed!" >> "$MAIN_LOG" 2>/dev/null
            echo "AGH_SWITCH_RESULT status=error stage=rollback_failed mode=$TARGET_MODE"
            exit 1
        fi
        echo "$(date '+%F %T') [WARN] switch_mode.sh: Rolled back configuration and runtime state to $prev_mode." >> "$MAIN_LOG" 2>/dev/null
        echo "AGH_SWITCH_RESULT status=error stage=start_or_mount_failed_rolled_back mode=$TARGET_MODE"
        exit 1
    fi
fi

# 9. 确认成功后提交模式记录
if ! write_run_mode_prop "$TARGET_MODE" "$cur_dns_port"; then
    echo "$(date '+%F %T') [ERROR] switch_mode.sh: Failed to persist RUN_MODE=$TARGET_MODE to $PROP_FILE" >> "$MAIN_LOG" 2>/dev/null
    echo "AGH_SWITCH_RESULT status=error stage=commit_prop_failed mode=$TARGET_MODE"
    exit 1
fi

rm -f "$PRE_SWITCH_BAK" 2>/dev/null
PRE_SWITCH_BAK=""
echo "$(date '+%F %T') [INFO] switch_mode.sh: Mode switch to $TARGET_MODE committed successfully." >> "$MAIN_LOG" 2>/dev/null
echo "AGH_SWITCH_RESULT status=ok stage=completed mode=$TARGET_MODE"
exit 0
