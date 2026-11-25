#!/system/bin/sh
# ==============================================================================
# ProxyConfig.sh - 双模自适应代理联动脚本（带归属记录与防误改保护）
# 特性：
# 1. 当用户在管理 App 中未填写 PROXY_URL（默认留空）：
#    不对无归属记录的第三方代理配置做任何猜测性修改或还原，完全静默不干预外部代理。
# 2. 当用户在管理 App 中填写了 PROXY_URL：
#    修改前在 $AGH_DIR/proxy_ownership/ 记录目标路径、原始备份与哈希、修改后哈希、
#    注入的 127.0.0.1:<redir_port>、URL 及原 enhanced-mode。
# 3. 清理或还原 (--clean) 时：
#    - 无归属记录的文件：保持原状并报告，绝不把任意 127.0.0.1:<port> 当成本模块写入，
#      也绝不全局将 redir-host 改回 fake-ip。
#    - 有归属记录且未被外部改动：从原始备份精确还原并移除归属记录。
#    - 有归属记录但已被用户/代理软件二次修改：不粗暴覆盖，仅精确移除本模块记录的
#      注入项 (127.0.0.1:<injected_port>) 并输出提示交由用户处理。
# ==============================================================================

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
[ -z "$SCRIPT_DIR" ] && SCRIPT_DIR="$AGH_DIR/scripts"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/config.prop}"
MAIN_LOG="${MAIN_LOG:-$AGH_DIR/agh.log}"
OWNERSHIP_DIR="${OWNERSHIP_DIR:-$AGH_DIR/proxy_ownership}"
if [ -z "${RUN_DIR:-}" ]; then
    mkdir -p /dev/shm 2>/dev/null
    if ( : >> /dev/shm/.agh_probe ) 2>/dev/null; then
        rm -f /dev/shm/.agh_probe 2>/dev/null
        RUN_DIR="/dev/shm"
    else
        mkdir -p "$AGH_DIR/run" 2>/dev/null
        RUN_DIR="$AGH_DIR/run"
    fi
fi

if [ -f "$SCRIPT_DIR/diag_log.sh" ]; then
    . "$SCRIPT_DIR/diag_log.sh"
elif [ -f "${MODDIR:-/data/adb/modules/AdGuardHome}/scripts/diag_log.sh" ]; then
    . "${MODDIR:-/data/adb/modules/AdGuardHome}/scripts/diag_log.sh"
fi

[ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"
redir_port="${redir_port:-55453}"
LOCAL_DNS="127.0.0.1:${redir_port}"

# 防止重复启动后台守护实例（允许 --clean 和 --once 单次立即执行）
if [ "$1" != "--clean" ] && [ "$1" != "--once" ]; then
    for pid in $(pidof -x "$0" 2>/dev/null); do
        [ "$pid" != "$$" ] && exit 0
    done
fi

# 支持的 Root 代理模块配置文件路径与重启命令（支持通过 AGH_PROXY_CONFIGS 覆盖以便沙箱测试）
DEFAULT_PROXY_CONFIGS="
/data/adb/box_bll/clash/*.yaml|/data/adb/box_bll/scripts/box.service restart
/data/adb/box/mihomo/*.yaml|/data/adb/box/scripts/box.service restart
/data/clash/*.yaml|/data/clash/scripts/clash.service -k && /data/clash/scripts/clash.service -s
/data/media/0/Android/Clash/*.yaml|/data/adb/modules/Clash/Scripts/Clash.Service stop; /data/adb/modules/Clash/Scripts/Clash.Service start
"
PROXY_CONFIGS="${AGH_PROXY_CONFIGS:-$DEFAULT_PROXY_CONFIGS}"

ALL_SECTIONS="direct-nameserver: proxy-server-nameserver: nameserver: default-nameserver:"

log_msg() {
    msg="$1"
    if command -v agh_log_always >/dev/null 2>&1; then
        agh_log_always "[ProxyConfig] $msg"
    else
        echo "$(date '+%F %T') [ProxyConfig] $msg" >> "$MAIN_LOG" 2>/dev/null || true
    fi
    echo "[ProxyConfig] $msg"
}

file_hash() {
    f="$1"
    [ -f "$f" ] || return 1
    if command -v sha256sum >/dev/null 2>&1; then
        set -- $(sha256sum "$f" 2>/dev/null)
        [ -n "${1:-}" ] && { printf '%s\n' "$1"; return 0; }
    elif command -v shasum >/dev/null 2>&1; then
        set -- $(shasum -a 256 "$f" 2>/dev/null)
        [ -n "${1:-}" ] && { printf '%s\n' "$1"; return 0; }
    elif command -v md5sum >/dev/null 2>&1; then
        set -- $(md5sum "$f" 2>/dev/null)
        [ -n "${1:-}" ] && { printf '%s\n' "$1"; return 0; }
    else
        set -- $(cksum "$f" 2>/dev/null)
        [ -n "${1:-}" ] && [ -n "${2:-}" ] && { printf '%s_%s\n' "$1" "$2"; return 0; }
    fi
    return 1
}

ownership_key() {
    set -- $(printf '%s' "$1" | cksum 2>/dev/null)
    [ -n "${1:-}" ] && [ -n "${2:-}" ] && printf '%s_%s\n' "$1" "$2"
}

escape_ere() {
    printf '%s' "$1" | sed 's/[][\\.^$*+?(){}|/]/\\&/g'
}

# 校验外部修改后的增量清理结果：
# 1. 候选文件非空
# 2. 已移除归属记录确认的本模块注入项 (- $INJECTED_DNS) 且已恢复 # [AGH_ORIG] 注释项
# 3. 除上述本模块注入痕迹外，其余所有行（含用户后续修改、原生其他端口如 127.0.0.1:5353、enhanced-mode）与清理前 100% 一致
verify_partial_clean_candidate() {
    pre_file="$1"
    cand_file="$2"
    inj_dns="$3"
    [ -s "$pre_file" ] && [ -s "$cand_file" ] || return 1

    esc_dns=$(escape_ere "$inj_dns")
    [ -n "$esc_dns" ] || return 1

    # 候选文件中不得残留本模块注入的 DNS 项或 # [AGH_ORIG] 标记
    if grep -qE "^[[:space:]]*-[[:space:]]*${esc_dns}([[:space:]]*(#.*)?)?$" "$cand_file" 2>/dev/null; then
        return 1
    fi
    if grep -qE "^[[:space:]]*#[[:space:]]*\[AGH_ORIG\][[:space:]]*-[[:space:]]*" "$cand_file" 2>/dev/null; then
        return 1
    fi

    # 若清理前文件包含本模块注入项或 # [AGH_ORIG]，清理后文件不能与清理前完全相同
    if grep -qE "^[[:space:]]*-[[:space:]]*${esc_dns}([[:space:]]*(#.*)?)?$" "$pre_file" 2>/dev/null || \
       grep -qE "^[[:space:]]*#[[:space:]]*\[AGH_ORIG\][[:space:]]*-[[:space:]]*" "$pre_file" 2>/dev/null; then
        if cmp -s "$pre_file" "$cand_file"; then
            return 1
        fi
    fi

    # 逐行精确核对：仅允许移除本模块注入的 - $inj_dns 行并解开 # [AGH_ORIG] 注释，不得改动任何其他内容
    exp_file="${cand_file}.expected.$$"
    if ! sed -E \
        -e "/^[[:space:]]*-[[:space:]]*${esc_dns}([[:space:]]*(#.*)?)?$/d" \
        -e "s/^([[:space:]]*)#[[:space:]]*\[AGH_ORIG\][[:space:]]*(-[[:space:]]*)/\1\2/" \
        "$pre_file" > "$exp_file" 2>/dev/null; then
        rm -f "$exp_file" 2>/dev/null
        return 1
    fi
    if ! cmp -s "$exp_file" "$cand_file"; then
        rm -f "$exp_file" 2>/dev/null
        return 1
    fi
    rm -f "$exp_file" 2>/dev/null
    return 0
}

get_dns_enhanced_mode() {
    awk '
        /^[[:space:]]*dns:[[:space:]]*(#.*)?$/ { in_dns = 1; next }
        in_dns && /^[^[:space:]#]/ { in_dns = 0 }
        in_dns && /^[[:space:]]*enhanced-mode:[[:space:]]*/ {
            line = $0
            sub(/^[[:space:]]*enhanced-mode:[[:space:]]*/, "", line)
            sub(/[[:space:]]*(#.*)?$/, "", line)
            print line
            exit
        }
    ' "$1" 2>/dev/null
}

restart_service() {
    [ -n "$1" ] && eval "$1" >/dev/null 2>&1
    ndc resolver flushenv >/dev/null 2>&1 || true
}

# 清理配置文件中的本模块注入（严格校验归属记录）
# 返回码约定：0=已清理/还原归属配置；1=无归属记录或无需动作（非错误）；2=清理归属配置过程中发生错误（保留恢复记录）
clean_config() {
    cfg="$1"
    mode_arg="${2:---clean}"
    [ -f "$cfg" ] || return 1

    key=$(ownership_key "$cfg")
    meta_file="$OWNERSHIP_DIR/${key}.meta"
    orig_file="$OWNERSHIP_DIR/${key}.orig"

    if [ ! -f "$meta_file" ]; then
        # 检查是否存在上次提交中断且回滚失败所保留的恢复用 .meta.tmp.* 材料
        recovered_tmp=""
        for cand_tmp in "$OWNERSHIP_DIR/${key}.meta.tmp."*; do
            if [ -f "$cand_tmp" ]; then
                recovered_tmp="$cand_tmp"
                break
            fi
        done
        if [ -n "$recovered_tmp" ]; then
            meta_file="$recovered_tmp"
        else
            if [ "$mode_arg" = "--clean" ]; then
                log_msg "SKIP $cfg: 未找到本模块归属记录，保持原状不猜测还原。"
            fi
            return 1
        fi
    fi

    TARGET_PATH=""
    ORIG_SHA256=""
    MOD_SHA256=""
    INJECTED_DNS=""
    INJECTED_URL=""
    ORIG_ENHANCED_MODE=""
    CHANGED_ENHANCED_MODE="0"
    . "$meta_file" 2>/dev/null

    if [ "$TARGET_PATH" != "$cfg" ] || [ -z "$MOD_SHA256" ] || [ -z "$INJECTED_DNS" ]; then
        log_msg "ERROR $cfg: 归属记录不完整或路径不匹配，已保留恢复记录并拒绝猜测还原。"
        return 2
    fi

    cur_sha=$(file_hash "$cfg")
    if [ -z "$cur_sha" ]; then
        log_msg "ERROR $cfg: 无法读取当前文件哈希，已保留归属恢复记录。"
        return 2
    fi

    # 情况 1：文件自本模块上次写入后未被外部改动，且原始备份完好 -> 100% 精确还原
    if [ "$cur_sha" = "$MOD_SHA256" ]; then
        if [ ! -f "$orig_file" ] || [ "$(file_hash "$orig_file")" != "$ORIG_SHA256" ]; then
            log_msg "ERROR $cfg: 原始备份缺失或哈希不匹配，已保留归属恢复记录。"
            return 2
        fi
        tmp_restore="${cfg}.agh_restore.$$"
        if ! cp -pf "$orig_file" "$tmp_restore" 2>/dev/null || [ ! -s "$tmp_restore" ] || [ "$(file_hash "$tmp_restore")" != "$ORIG_SHA256" ]; then
            rm -f "$tmp_restore" 2>/dev/null
            log_msg "ERROR $cfg: 生成还原临时文件失败，已保留原配置与归属恢复记录。"
            return 2
        fi
        if ! mv -f "$tmp_restore" "$cfg" 2>/dev/null; then
            rm -f "$tmp_restore" 2>/dev/null
            log_msg "ERROR $cfg: mv 替换还原配置失败，已保留原配置与归属恢复记录。"
            return 2
        fi
        if [ ! -s "$cfg" ] || [ "$(file_hash "$cfg")" != "$ORIG_SHA256" ]; then
            log_msg "ERROR $cfg: 目标文件写入后校验失败，已保留归属恢复记录。"
            return 2
        fi
        rm -f "$meta_file" "$orig_file" "$OWNERSHIP_DIR/${key}.meta.tmp."* 2>/dev/null
        log_msg "RESTORED $cfg: 已根据归属备份完整还原修改前配置。"
        return 0
    fi

    # 情况 2：文件已是原始状态 -> 直接清理归属记录
    if [ "$cur_sha" = "$ORIG_SHA256" ]; then
        rm -f "$meta_file" "$orig_file" "$OWNERSHIP_DIR/${key}.meta.tmp."* 2>/dev/null
        log_msg "CLEAN $cfg: 文件已处于修改前原始状态，清理归属记录。"
        return 1
    fi

    # 情况 3：文件在本模块写入后又被用户或代理软件修改 -> 绝不整文件覆盖，也绝不改动 enhanced-mode 或其他端口，
    # 仅精确移除确属本模块记录的 - $INJECTED_DNS 注入项，并恢复带有 # [AGH_ORIG] 标记的注释项
    pre_clean_snap="$OWNERSHIP_DIR/${key}.pre_clean.$$"
    if ! cp -pf "$cfg" "$pre_clean_snap" 2>/dev/null || [ "$(file_hash "$pre_clean_snap")" != "$cur_sha" ]; then
        rm -f "$pre_clean_snap" 2>/dev/null
        log_msg "ERROR $cfg: 无法建立清理前校验快照，已保留原配置与归属恢复记录。"
        return 2
    fi

    tmp_clean="${cfg}.agh_clean.$$"
    rm -f "$tmp_clean" 2>/dev/null
    if ! awk -v inj_dns="$INJECTED_DNS" '
        {
            line = $0
            trimmed = line
            sub(/^[[:space:]]+/, "", trimmed)
            sub(/[[:space:]]*(#.*)?$/, "", trimmed)
            if (trimmed == "- " inj_dns || trimmed == "-" inj_dns) {
                removed_count++
                next
            }
            if (line ~ /^[[:space:]]*#[[:space:]]*\[AGH_ORIG\][[:space:]]*-[[:space:]]*/) {
                sub(/#[[:space:]]*\[AGH_ORIG\][[:space:]]*/, "", line)
                restored_count++
            }
            print line
        }
    ' "$cfg" > "$tmp_clean" 2>/dev/null || [ ! -s "$tmp_clean" ]; then
        rm -f "$tmp_clean" "$pre_clean_snap" 2>/dev/null
        log_msg "ERROR $cfg: 临时清理文件生成失败或为空，已保留原配置与归属恢复记录。"
        return 2
    fi

    if ! verify_partial_clean_candidate "$pre_clean_snap" "$tmp_clean" "$INJECTED_DNS"; then
        rm -f "$tmp_clean" "$pre_clean_snap" 2>/dev/null
        log_msg "ERROR $cfg: 临时清理文件校验未通过（未包含预期清理结果），已保留原配置与归属恢复记录。"
        return 2
    fi

    expected_clean_sha=$(file_hash "$tmp_clean")
    if [ -z "$expected_clean_sha" ]; then
        rm -f "$tmp_clean" "$pre_clean_snap" 2>/dev/null
        log_msg "ERROR $cfg: 无法计算临时清理文件哈希，已保留原配置与归属恢复记录。"
        return 2
    fi

    if ! mv -f "$tmp_clean" "$cfg" 2>/dev/null; then
        rm -f "$tmp_clean" "$pre_clean_snap" 2>/dev/null
        log_msg "ERROR $cfg: mv 替换配置文件失败，已保留原配置与归属恢复记录。"
        return 2
    fi

    # 替换成功后重新读取目标文件，确认内容与哈希符合预期，通过后才允许删除归属恢复记录
    if [ ! -s "$cfg" ] || [ "$(file_hash "$cfg")" != "$expected_clean_sha" ] || \
       ! verify_partial_clean_candidate "$pre_clean_snap" "$cfg" "$INJECTED_DNS"; then
        cp -pf "$pre_clean_snap" "$cfg" 2>/dev/null || true
        rm -f "$pre_clean_snap" 2>/dev/null
        log_msg "ERROR $cfg: 目标文件写入后校验失败，已保留归属恢复记录。"
        return 2
    fi

    rm -f "$pre_clean_snap" "$meta_file" "$orig_file" "$OWNERSHIP_DIR/${key}.meta.tmp."* 2>/dev/null
    log_msg "PARTIAL_CLEAN $cfg: 检测到文件在模块写入后被外部修改，已仅移除本模块注入项 ($INJECTED_DNS) 并保留用户后续改动，请按需检查代理配置。"
    return 0
}

# 将 CLEAN_URL 与 LOCAL_DNS 注入候选配置文件：
# - 支持 nameserver: [] 空数组展开为合法 YAML 列表并写入 - $inj_dns
# - 支持 nameserver: 空映射（后接其他子键、顶层键或文件末尾）在不覆盖相邻字段的前提下写入 - $inj_dns
# - 保留非空列表原有注释与注入语义，绝不改动 fallback 等非目标 DNS 段
apply_injection_to_file() {
    src_in="$1"
    dst_out="$2"
    inj_dns="$3"
    inj_url="$4"

    awk -v inj_dns="$inj_dns" -v inj_url="$inj_url" '
        function is_target_key_name(k) {
            return (k == "direct-nameserver" || k == "proxy-server-nameserver" || k == "nameserver" || k == "default-nameserver")
        }
        function flush_buf(    i) {
            for (i = 1; i <= buf_n; i++) {
                print buf[i]
            }
            buf_n = 0
        }
        function leave_section() {
            if (!in_sec) return
            if (!sec_injected) {
                print sec_indent "  - " inj_dns
                sec_injected = 1
            }
            flush_buf()
            in_sec = 0
            sec_indent = ""
        }
        {
            line = $0

            # 1. proxy-providers 段内的首个 url: 更新
            if (inj_url != "") {
                if (line ~ /^[[:space:]]*proxy-providers:[[:space:]]*(#.*)?$/) {
                    in_pp = 1
                } else if (in_pp && line ~ /^[^[:space:]#]/) {
                    in_pp = 0
                }
                if (in_pp && line ~ /^[[:space:]]*url:[[:space:]]*/) {
                    indent = line
                    sub(/url:.*/, "", indent)
                    print indent "url: \"" inj_url "\""
                    next
                }
            }

            # 2. dns 段内的 enhanced-mode 与目标 DNS 列表段处理
            if (line ~ /^[[:space:]]*dns:[[:space:]]*(#.*)?$/) {
                leave_section()
                in_dns = 1
                print line
                next
            }
            if (in_dns && line ~ /^[^[:space:]#]/) {
                leave_section()
                in_dns = 0
            }

            if (in_dns) {
                if (line ~ /^[[:space:]]*enhanced-mode:[[:space:]]*/) {
                    leave_section()
                    indent = line
                    sub(/enhanced-mode:.*/, "", indent)
                    print indent "enhanced-mode: redir-host"
                    next
                }

                # 解析是否为 dns 下的子键行
                if (line ~ /^[[:space:]]+[\x27"]?[A-Za-z0-9_-]+[\x27"]?:/) {
                    k_line = line
                    sub(/^[[:space:]]+/, "", k_line)
                    k_name = k_line
                    sub(/:.*/, "", k_name)
                    gsub(/[\x27"]/, "", k_name)

                    k_rest = k_line
                    sub(/^[^:]+:[[:space:]]*/, "", k_rest)
                    k_rest_nocomment = k_rest
                    sub(/[[:space:]]*(#.*)?$/, "", k_rest_nocomment)

                    if (is_target_key_name(k_name)) {
                        leave_section()
                        cur_indent = line
                        sub(/[\x27"]?[A-Za-z0-9_-]+[\x27"]?:.*/, "", cur_indent)

                        # 情况 A：内联空列表 nameserver: []
                        if (k_rest_nocomment ~ /^\[[[:space:]]*\]$/) {
                            header_out = line
                            sub(/:[[:space:]]*\[[[:space:]]*\]/, ":", header_out)
                            print header_out
                            print cur_indent "  - " inj_dns
                            in_sec = 0
                            sec_injected = 0
                            next
                        }

                        # 情况 B：块级列表或空映射 nameserver:
                        if (k_rest_nocomment == "") {
                            in_sec = 1
                            sec_injected = 0
                            sec_indent = cur_indent
                            print line
                            next
                        }

                        # 其他内联非空形式（无法安全按行注释原项）：原样输出，交由后续候选校验拦截
                        print line
                        next
                    } else {
                        # 遇到非目标子键（如 fallback:、listen: 等），先闭合上一个未完成的目标 DNS 段
                        leave_section()
                        print line
                        next
                    }
                }

                if (in_sec) {
                    if (line ~ /^[[:space:]]*-[[:space:]]*/ && line !~ /^[[:space:]]*#/) {
                        flush_buf()
                        item_indent = line
                        sub(/-[[:space:]]*.*/, "", item_indent)
                        val = line
                        sub(/^[[:space:]]*-[[:space:]]*/, "", val)
                        val_clean = val
                        sub(/[[:space:]]*(#.*)?$/, "", val_clean)
                        if (!sec_injected) {
                            print item_indent "- " inj_dns
                            sec_injected = 1
                        }
                        if (val_clean != inj_dns) {
                            print item_indent "# [AGH_ORIG] - " val
                        }
                        next
                    } else if (line ~ /^[[:space:]]*#/ || line ~ /^[[:space:]]*$/) {
                        if (!sec_injected) {
                            buf[++buf_n] = line
                        } else {
                            print line
                        }
                        next
                    } else {
                        leave_section()
                    }
                }
            }

            print line
        }
        END {
            leave_section()
        }
    ' "$src_in" > "$dst_out" 2>/dev/null
}

# 严格校验生成的候选配置文件：
# 1. 候选文件非空且无非法控制字符
# 2. 原配置与候选配置在 dns: 下至少存在 1 个本模块接管的目标 DNS 段，且目标段数量与顺序完全一致
# 3. 每个目标 DNS 段在候选配置中均已消除 [] 并包含唯一个生效的 - 127.0.0.1:<当前端口> 项（且缩进合法）
# 4. 顶层段落顺序以及非目标 DNS 段（如 fallback: 及其列表项）未被覆盖或污染
verify_injected_candidate() {
    src_in="$1"
    cand_in="$2"
    inj_dns="$3"
    [ -s "$src_in" ] && [ -s "$cand_in" ] || return 1

    awk -v inj_dns="$inj_dns" '
        function is_target_key_name(k) {
            return (k == "direct-nameserver" || k == "proxy-server-nameserver" || k == "nameserver" || k == "default-nameserver")
        }
        FILENAME == ARGV[1] {
            if (/^[^[:space:]#]/) {
                in_dns_1 = ($0 ~ /^dns:[[:space:]]*(#.*)?$/)
                top_1[++top_1_n] = $0
                in_tsec_1 = 0
                next
            }
            if (!in_dns_1 && /^[[:space:]]+dns:[[:space:]]*(#.*)?$/) {
                in_dns_1 = 1
                in_tsec_1 = 0
                next
            }
            if (in_dns_1) {
                if ($0 ~ /^[[:space:]]+[\x27"]?[A-Za-z0-9_-]+[\x27"]?:/) {
                    k = $0
                    sub(/^[[:space:]]+/, "", k)
                    sub(/:.*/, "", k)
                    gsub(/[\x27"]/, "", k)
                    if (is_target_key_name(k)) {
                        tsec_1[++tsec_1_n] = k
                        in_tsec_1 = 1
                    } else {
                        in_tsec_1 = 0
                        if (k != "enhanced-mode") {
                            other_key_1[++other_key_1_n] = k
                        }
                    }
                    next
                }
                if (!in_tsec_1 && $0 ~ /^[[:space:]]*-[[:space:]]*/ && $0 !~ /^[[:space:]]*#/) {
                    nt_item_1[++nt_item_1_n] = $0
                }
            }
            next
        }
        FILENAME == ARGV[2] {
            if (/^[^[:space:]#]/) {
                in_dns_2 = ($0 ~ /^dns:[[:space:]]*(#.*)?$/)
                top_2[++top_2_n] = $0
                cur_tsec_2 = 0
                next
            }
            if (!in_dns_2 && /^[[:space:]]+dns:[[:space:]]*(#.*)?$/) {
                in_dns_2 = 1
                cur_tsec_2 = 0
                next
            }
            if (in_dns_2) {
                if ($0 ~ /^[[:space:]]+[\x27"]?[A-Za-z0-9_-]+[\x27"]?:/) {
                    k_line = $0
                    ind = k_line
                    sub(/[\x27"]?[A-Za-z0-9_-]+[\x27"]?:.*/, "", ind)
                    k = k_line
                    sub(/^[[:space:]]+/, "", k)
                    sub(/:.*/, "", k)
                    gsub(/[\x27"]/, "", k)
                    rest = k_line
                    sub(/^[^:]+:[[:space:]]*/, "", rest)
                    sub(/[[:space:]]*(#.*)?$/, "", rest)

                    if (is_target_key_name(k)) {
                        if (rest != "") {
                            # 候选配置中目标 DNS 键同行不得残留 [] 或内联值
                            invalid = 1
                        }
                        tsec_2[++tsec_2_n] = k
                        tsec_2_indent[tsec_2_n] = length(ind)
                        cur_tsec_2 = tsec_2_n
                    } else {
                        cur_tsec_2 = 0
                        if (k != "enhanced-mode") {
                            other_key_2[++other_key_2_n] = k
                        }
                    }
                    next
                }
                if ($0 ~ /^[[:space:]]*-[[:space:]]*/ && $0 !~ /^[[:space:]]*#/) {
                    if (cur_tsec_2 > 0) {
                        item_ind = $0
                        sub(/-[[:space:]]*.*/, "", item_ind)
                        if (length(item_ind) <= tsec_2_indent[cur_tsec_2]) {
                            invalid = 1
                        }
                        v = $0
                        sub(/^[[:space:]]*-[[:space:]]*/, "", v)
                        sub(/[[:space:]]*(#.*)?$/, "", v)
                        if (v == inj_dns) {
                            tsec_2_inj_cnt[cur_tsec_2]++
                        } else {
                            invalid = 1
                        }
                    } else {
                        nt_item_2[++nt_item_2_n] = $0
                    }
                }
            }
            next
        }
        END {
            if (invalid) exit 1
            if (tsec_1_n < 1 || tsec_2_n != tsec_1_n) exit 1
            for (i = 1; i <= tsec_2_n; i++) {
                if (tsec_1[i] != tsec_2[i]) exit 1
                if (tsec_2_inj_cnt[i] != 1) exit 1
            }
            if (top_1_n != top_2_n) exit 1
            for (i = 1; i <= top_1_n; i++) {
                if (top_1[i] != top_2[i]) exit 1
            }
            if (other_key_1_n != other_key_2_n) exit 1
            for (i = 1; i <= other_key_1_n; i++) {
                if (other_key_1[i] != other_key_2[i]) exit 1
            }
            if (nt_item_1_n != nt_item_2_n) exit 1
            for (i = 1; i <= nt_item_1_n; i++) {
                if (nt_item_1[i] != nt_item_2[i]) exit 1
            }
            exit 0
        }
    ' "$src_in" "$cand_in" 2>/dev/null || return 1

    # 若运行环境提供额外的外部 YAML 校验器（可通过 AGH_YAML_VALIDATOR 指定），一并执行校验
    if [ -n "${AGH_YAML_VALIDATOR:-}" ]; then
        "$AGH_YAML_VALIDATOR" "$cand_in" >/dev/null 2>&1 || return 1
    fi
    return 0
}

write_meta_tmp() {
    mtmp="$1"
    t_path="$2"
    o_sha="$3"
    m_sha="$4"
    i_dns="$5"
    i_url="$6"
    o_em="$7"
    c_em="$8"

    rm -f "$mtmp" 2>/dev/null
    touch "$mtmp" 2>/dev/null || return 1
    [ -f "$mtmp" ] || return 1
    cat > "$mtmp" 2>/dev/null <<EOF
TARGET_PATH='$t_path'
ORIG_SHA256='$o_sha'
MOD_SHA256='$m_sha'
INJECTED_DNS='$i_dns'
INJECTED_URL='$i_url'
ORIG_ENHANCED_MODE='$o_em'
CHANGED_ENHANCED_MODE='$c_em'
EOF
}

verify_meta_file() {
    mf="$1"
    exp_path="$2"
    exp_orig_sha="$3"
    exp_mod_sha="$4"
    exp_dns="$5"
    exp_url="$6"
    exp_orig_em="$7"
    exp_changed_em="$8"

    [ -s "$mf" ] || return 1
    for req_key in TARGET_PATH ORIG_SHA256 MOD_SHA256 INJECTED_DNS INJECTED_URL ORIG_ENHANCED_MODE CHANGED_ENHANCED_MODE; do
        grep -q "^${req_key}=" "$mf" 2>/dev/null || return 1
    done

    (
        TARGET_PATH=""
        ORIG_SHA256=""
        MOD_SHA256=""
        INJECTED_DNS=""
        INJECTED_URL=""
        ORIG_ENHANCED_MODE="__UNSET__"
        CHANGED_ENHANCED_MODE=""
        . "$mf" 2>/dev/null || exit 1
        [ "$TARGET_PATH" = "$exp_path" ] || exit 1
        [ -n "$ORIG_SHA256" ] && [ "$ORIG_SHA256" = "$exp_orig_sha" ] || exit 1
        [ -n "$MOD_SHA256" ] && [ "$MOD_SHA256" = "$exp_mod_sha" ] || exit 1
        [ -n "$INJECTED_DNS" ] && [ "$INJECTED_DNS" = "$exp_dns" ] || exit 1
        [ -n "$INJECTED_URL" ] && [ "$INJECTED_URL" = "$exp_url" ] || exit 1
        [ "$ORIG_ENHANCED_MODE" = "$exp_orig_em" ] || exit 1
        [ "$CHANGED_ENHANCED_MODE" = "$exp_changed_em" ] || exit 1
        exit 0
    )
}

# 处理单个代理配置文件的注入与原子归属提交
# 返回码约定：0=成功提交注入与归属记录；1=无需修改或按策略跳过（非错误）；2=注入或提交失败
process_config() {
    cfg="$1"
    [ -f "$cfg" ] || return 1
    [ -n "$CLEAN_URL" ] || return 1

    mkdir -p "$OWNERSHIP_DIR" 2>/dev/null || {
        log_msg "ERROR $cfg: 无法创建归属记录目录 $OWNERSHIP_DIR，中止修改。"
        return 2
    }
    key=$(ownership_key "$cfg")
    [ -n "$key" ] || {
        log_msg "ERROR $cfg: 无法生成归属记录键，中止修改。"
        return 2
    }
    meta_file="$OWNERSHIP_DIR/${key}.meta"
    orig_file="$OWNERSHIP_DIR/${key}.orig"
    meta_tmp="$OWNERSHIP_DIR/${key}.meta.tmp.$$"
    tmp_mod="${cfg}.agh_mod.$$"

    cur_sha=$(file_hash "$cfg")
    if [ -z "$cur_sha" ]; then
        log_msg "ERROR $cfg: 无法计算目标文件哈希，中止修改。"
        return 2
    fi

    base_input="$cfg"
    orig_sha="$cur_sha"
    orig_em=$(get_dns_enhanced_mode "$cfg")
    had_prev_meta=0

    if [ -f "$meta_file" ]; then
        TARGET_PATH=""
        ORIG_SHA256=""
        MOD_SHA256=""
        INJECTED_DNS=""
        INJECTED_URL=""
        ORIG_ENHANCED_MODE=""
        CHANGED_ENHANCED_MODE="0"
        . "$meta_file" 2>/dev/null

        if [ "$cur_sha" = "$MOD_SHA256" ] && [ "$INJECTED_DNS" = "$LOCAL_DNS" ] && [ "$INJECTED_URL" = "$CLEAN_URL" ]; then
            # 已经是最新注入状态，无需重复修改
            return 1
        fi

        if [ "$cur_sha" != "$MOD_SHA256" ] && [ "$cur_sha" != "$ORIG_SHA256" ]; then
            log_msg "SKIP $cfg: 检测到文件在本模块修改后又被用户或代理软件改动，拒绝覆盖用户修改。"
            return 1
        fi

        if [ ! -f "$orig_file" ] || [ "$(file_hash "$orig_file")" != "$ORIG_SHA256" ]; then
            log_msg "ERROR $cfg: 现有原始配置备份缺失或哈希不匹配，拒绝修改并保留现有恢复材料。"
            return 2
        fi
        base_input="$orig_file"
        orig_sha="$ORIG_SHA256"
        orig_em="$ORIG_ENHANCED_MODE"
        had_prev_meta=1
    fi

    # 1. 生成候选配置并在写任何归属文件或修改目标文件前完成严格结构与本地 DNS 注入校验
    rm -f "$tmp_mod" 2>/dev/null
    if ! apply_injection_to_file "$base_input" "$tmp_mod" "$LOCAL_DNS" "$CLEAN_URL" || [ ! -s "$tmp_mod" ]; then
        rm -f "$tmp_mod" 2>/dev/null
        log_msg "ERROR $cfg: 生成候选配置文件失败，保持原配置不变。"
        return 2
    fi

    if ! verify_injected_candidate "$base_input" "$tmp_mod" "$LOCAL_DNS"; then
        rm -f "$tmp_mod" 2>/dev/null
        log_msg "ERROR $cfg: 候选配置未包含有效本地 DNS ($LOCAL_DNS) 或未通过结构校验，保持原配置不变。"
        return 2
    fi

    mod_sha=$(file_hash "$tmp_mod")
    if [ -z "$mod_sha" ]; then
        rm -f "$tmp_mod" 2>/dev/null
        log_msg "ERROR $cfg: 无法计算候选配置哈希，保持原配置不变。"
        return 2
    fi

    if [ "$mod_sha" = "$cur_sha" ] && [ "$had_prev_meta" -eq 1 ]; then
        rm -f "$tmp_mod" 2>/dev/null
        return 1
    fi

    # 2. 确保原始配置备份 $orig_file 存在且哈希与 $orig_sha 完全一致
    if [ "$had_prev_meta" -eq 0 ]; then
        if ! cp -pf "$cfg" "$orig_file" 2>/dev/null; then
            rm -f "$tmp_mod" 2>/dev/null
            log_msg "ERROR $cfg: 无法创建原始配置备份 $orig_file，中止修改。"
            return 2
        fi
    fi
    if [ ! -f "$orig_file" ] || [ "$(file_hash "$orig_file")" != "$orig_sha" ]; then
        rm -f "$tmp_mod" 2>/dev/null
        log_msg "ERROR $cfg: 原始配置备份 $orig_file 校验失败，中止修改。"
        return 2
    fi

    changed_em=0
    [ -n "$orig_em" ] && [ "$orig_em" != "redir-host" ] && changed_em=1

    # 3. 在触碰目标配置前，先写入同目录唯一临时元数据 <key>.meta.tmp.<pid> 并重新读取校验全部字段
    if ! write_meta_tmp "$meta_tmp" "$cfg" "$orig_sha" "$mod_sha" "$LOCAL_DNS" "$CLEAN_URL" "$orig_em" "$changed_em"; then
        rm -f "$tmp_mod" "$meta_tmp" 2>/dev/null
        log_msg "ERROR $cfg: 归属元数据临时文件创建或写入失败，目标配置未修改。"
        return 2
    fi

    if ! verify_meta_file "$meta_tmp" "$cfg" "$orig_sha" "$mod_sha" "$LOCAL_DNS" "$CLEAN_URL" "$orig_em" "$changed_em"; then
        rm -f "$tmp_mod" "$meta_tmp" 2>/dev/null
        log_msg "ERROR $cfg: 归属元数据临时文件字段校验失败，目标配置未修改。"
        return 2
    fi

    # 4. 原子安装候选配置并重新读取目标文件比对哈希
    if ! mv -f "$tmp_mod" "$cfg" 2>/dev/null; then
        rm -f "$tmp_mod" "$meta_tmp" 2>/dev/null
        log_msg "ERROR $cfg: 候选配置原子替换失败，目标配置未生效。"
        return 2
    fi

    if [ ! -s "$cfg" ] || [ "$(file_hash "$cfg")" != "$mod_sha" ]; then
        # 候选配置安装后校验不通过，立即尝试从已验证的原始备份回滚
        if [ -f "$orig_file" ] && [ "$(file_hash "$orig_file")" = "$orig_sha" ] && \
           cp -pf "$orig_file" "$cfg" 2>/dev/null && [ "$(file_hash "$cfg")" = "$orig_sha" ]; then
            rm -f "$meta_tmp" 2>/dev/null
            log_msg "ERROR $cfg: 候选配置替换后哈希校验失败，已从原始备份回滚目标配置。"
            return 2
        fi
        log_msg "CRITICAL $cfg: 候选配置替换后校验失败且回滚原始配置也失败！已保留 $orig_file 与 $meta_tmp 等恢复材料。"
        return 2
    fi

    # 5. 原子安装正式归属元数据并重新读取校验全部字段；若失败则立即从已验证原始备份回滚目标配置
    meta_commit_ok=0
    if mv -f "$meta_tmp" "$meta_file" 2>/dev/null; then
        if verify_meta_file "$meta_file" "$cfg" "$orig_sha" "$mod_sha" "$LOCAL_DNS" "$CLEAN_URL" "$orig_em" "$changed_em"; then
            meta_commit_ok=1
        fi
    fi

    if [ "$meta_commit_ok" -ne 1 ]; then
        rollback_ok=0
        if [ -f "$orig_file" ] && [ "$(file_hash "$orig_file")" = "$orig_sha" ]; then
            if cp -pf "$orig_file" "$cfg" 2>/dev/null && [ -s "$cfg" ] && [ "$(file_hash "$cfg")" = "$orig_sha" ]; then
                rollback_ok=1
            fi
        fi
        if [ "$rollback_ok" -eq 1 ]; then
            rm -f "$meta_tmp" 2>/dev/null
            if [ "$had_prev_meta" -eq 0 ]; then
                rm -f "$meta_file" 2>/dev/null
            fi
            log_msg "ERROR $cfg: 正式归属元数据提交或校验失败，已从原始备份成功回滚目标配置。"
            return 2
        fi
        log_msg "CRITICAL $cfg: 正式归属元数据提交失败且回滚原始配置也失败！已保留 $orig_file 与 $meta_tmp 等全部恢复材料。"
        return 2
    fi

    # 6. 最终确认目标配置与正式元数据均在盘且校验通过后，才报告注入成功
    if [ "$(file_hash "$cfg")" != "$mod_sha" ]; then
        log_msg "CRITICAL $cfg: 提交完成复核时发现目标配置哈希异常，已保留全部恢复材料。"
        return 2
    fi

    log_msg "INJECTED $cfg: 已注入 DNS ($LOCAL_DNS) 并记录归属信息 (orig=$orig_sha, mod=$mod_sha)。"
    return 0
}

run_pass() {
    pass_mode="${1:-}"
    [ -f "$CONFIG_FILE" ] && . "$CONFIG_FILE"
    redir_port="${redir_port:-55453}"
    LOCAL_DNS="127.0.0.1:${redir_port}"
    CLEAN_URL=$(printf '%s' "${PROXY_URL:-}" | tr -d '[:space:]')

    # 当非 --clean 且未配置 PROXY_URL 时，若不存在任何历史归属记录则直接静默返回，绝不触碰任何第三方代理配置
    if [ "$pass_mode" != "--clean" ] && [ -z "$CLEAN_URL" ]; then
        has_owned=0
        if [ -d "$OWNERSHIP_DIR" ]; then
            for mf in "$OWNERSHIP_DIR"/*.meta "$OWNERSHIP_DIR"/*.meta.tmp.*; do
                if [ -f "$mf" ]; then
                    has_owned=1
                    break
                fi
            done
        fi
        [ "$has_owned" -eq 0 ] && return 0
    fi

    had_error=0
    while IFS='|' read -r pattern restart_cmd; do
        [ -z "$pattern" ] && continue
        need_restart=0
        for cfg in $pattern; do
            [ -f "$cfg" ] || continue
            if [ "$pass_mode" = "--clean" ] || [ -z "$CLEAN_URL" ]; then
                clean_config "$cfg" "$pass_mode"
                rc=$?
                if [ "$rc" -eq 0 ]; then
                    need_restart=1
                elif [ "$rc" -ge 2 ]; then
                    had_error=1
                fi
            else
                process_config "$cfg"
                rc=$?
                if [ "$rc" -eq 0 ]; then
                    need_restart=1
                elif [ "$rc" -ge 2 ]; then
                    had_error=1
                fi
            fi
        done
        [ "$need_restart" -eq 1 ] && [ "$pass_mode" != "--clean" ] && restart_service "$restart_cmd"
    done <<EOF
$PROXY_CONFIGS
EOF
    [ "$had_error" -ne 0 ] && return 1
    command -v agh_log_debug >/dev/null 2>&1 && agh_log_debug "[ProxyConfig] run_pass completed mode=${pass_mode:-sync} had_error=$had_error"
    return 0
}

if [ "$1" = "--clean" ] || [ "$1" = "--once" ]; then
    run_pass "$1" || exit 1
    exit 0
fi

# 后台守护循环：开机立即执行一次同步，随后每 20 秒轻量检查一次
while :; do
    run_pass
    sleep 20
done
