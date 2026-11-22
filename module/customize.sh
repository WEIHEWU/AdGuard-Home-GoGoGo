#!/system/bin/sh
SKIPUNZIP=1

# 多语言检测
locale=$(getprop persist.sys.locale 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
[ -z "$locale" ] && locale="zh"
ui_print "- $locale"
case $locale in
  en*) language=en ;;
  *)   language=zh ;;
esac
i18n_print() {
  if [ "$language" = "zh" ]; then
    ui_print "$2"
  else
    ui_print "$1"
  fi
}

fail_install() {
  i18n_print "! Installation aborted: $1" "! 安装已中止: $2"
  if [ -n "${UPGRADE_BACKUP_DIR:-}" ] && [ -d "$UPGRADE_BACKUP_DIR" ]; then
    i18n_print "! Recoverable backup preserved at: $UPGRADE_BACKUP_DIR" "! 可恢复备份已保留在: $UPGRADE_BACKUP_DIR"
  fi
  if type abort >/dev/null 2>&1; then
    abort "$1"
  fi
  exit 1
}

AGH_DIR="${AGH_DIR:-/data/adb/agh}"
BIN_DIR="$AGH_DIR/bin"
SCRIPT_DIR="$AGH_DIR/scripts"
ADGPATH="${ADGPATH:-/data/adb/modules/AdGuardHome}"
MODULES_ROOT="${MODULES_ROOT:-/data/adb/modules}"

# 检测潜在冲突的 Hosts 模块（仅提示并记录模块名称，绝不自动创建 remove/disable 或修改其他模块，发现冲突明确中止安装）
i18n_print "- Checking for Hosts modules" "- 正在检测Hosts模块"
found_hosts=false
conflict_hosts_list=""
for module in "$MODULES_ROOT"/*; do
  [ -d "$module" ] || continue
  [ "$module" = "$MODPATH" ] || [ "$module" = "$ADGPATH" ] || [ "${module##*/}" = "AdGuardHome" ] && continue
  if [ -f "$module/system/etc/hosts" ] && [ -f "$module/module.prop" ]; then
    if [ "$found_hosts" = false ]; then
      i18n_print "! Conflicting Hosts module(s) detected (will NOT modify or remove other modules automatically):" "! 检测到潜在冲突的 Hosts 模块（不会自动移除或修改其他模块）:"
      found_hosts=true
    fi
    mod_name=""
    if type grep_prop >/dev/null 2>&1; then
      mod_name=$(grep_prop name "$module/module.prop" 2>/dev/null || true)
    fi
    if [ -z "$mod_name" ]; then
      mod_name=$(sed -n 's/^name=//p' "$module/module.prop" 2>/dev/null | head -n 1 || true)
    fi
    [ -z "$mod_name" ] && mod_name="${module##*/}"
    ui_print "  - $mod_name (${module##*/})"
    if [ -z "$conflict_hosts_list" ]; then
      conflict_hosts_list="$mod_name"
    else
      conflict_hosts_list="$conflict_hosts_list, $mod_name"
    fi
  fi
done
if [ "$found_hosts" = true ]; then
  fail_install "Conflicting Hosts module detected ($conflict_hosts_list). Please disable or remove it manually in your Root manager and retry." "检测到冲突的 Hosts 模块 ($conflict_hosts_list)，请先在 Root 管理器中自行禁用或移除该模块后再重试安装。"
fi

i18n_print "- Extracting basic module files" "- 正在解压模块基本文件"
mkdir -p "$MODPATH" || fail_install "Failed to create MODPATH" "创建模块目录失败"
unzip -q -o "$ZIPFILE" uninstall.sh module.prop service.sh action.sh AdGuardHomeManager.apk -d "$MODPATH" || \
  fail_install "Failed to extract basic module files" "解压模块基本文件失败"

# 检查并停止运行中的进程（按 PID 校验 / pidof / pgrep 精准定位，禁止全 /proc 遍历调用 tr 触发上千次 fork 阻塞）
if [ -d "$AGH_DIR" ]; then
  i18n_print "- Stopping AdGuardHome and its additional processes" "- 正在终止AdGuardHome及附加进程"
  collect_agh_target_pids() {
    _cap_pids=""
    if [ -r "$BIN_DIR/AdGuardHome.pid" ]; then
      IFS= read -r _cap_p < "$BIN_DIR/AdGuardHome.pid" 2>/dev/null || _cap_p=""
      case "$_cap_p" in
        ''|*[!0-9]*) ;;
        *)
          if [ ! -d /proc ] || { [ -r "/proc/$_cap_p/comm" ] && IFS= read -r _cap_c < "/proc/$_cap_p/comm" 2>/dev/null && [ "$_cap_c" = "AdGuardHome" ]; }; then
            _cap_pids="$_cap_pids $_cap_p"
          fi
          ;;
      esac
    fi
    for pid_f in /dev/shm/agh_watchdog.pid "$AGH_DIR/run/agh_watchdog.pid" \
                 /dev/shm/agh_watchdog.lock/pid "$AGH_DIR/run/agh_watchdog.lock/pid"; do
      [ -r "$pid_f" ] || continue
      IFS= read -r _cap_p < "$pid_f" 2>/dev/null || _cap_p=""
      case "$_cap_p" in
        ''|*[!0-9]*) ;;
        *)
          if [ ! -d /proc ]; then
            _cap_pids="$_cap_pids $_cap_p"
          elif [ -r "/proc/$_cap_p/comm" ]; then
            IFS= read -r _cap_c < "/proc/$_cap_p/comm" 2>/dev/null || _cap_c=""
            case "$_cap_c" in
              sh|mksh|ash|ksh|dash|bash|busybox|service.sh) _cap_pids="$_cap_pids $_cap_p" ;;
            esac
          fi
          ;;
      esac
    done
    if command -v pidof >/dev/null 2>&1; then
      for _cap_p in $(pidof AdGuardHome 2>/dev/null); do
        case "$_cap_p" in
          ''|*[!0-9]*) ;;
          *) _cap_pids="$_cap_pids $_cap_p" ;;
        esac
      done
    fi
    if command -v pgrep >/dev/null 2>&1; then
      for _cap_pat in "$BIN_DIR/AdGuardHome" "$AGH_DIR/scripts/" "/AdGuardHome/service.sh.*--watchdog"; do
        for _cap_p in $(pgrep -f "$_cap_pat" 2>/dev/null); do
          case "$_cap_p" in
            ''|*[!0-9]*) ;;
            *) _cap_pids="$_cap_pids $_cap_p" ;;
          esac
        done
      done
    fi
  }

  _parent_pid="${PPID:-0}"
  stop_loops=0
  while [ "$stop_loops" -lt 8 ]; do
    collect_agh_target_pids
    _killed_any=0
    for target_p in $_cap_pids; do
      [ "$target_p" != "$$" ] && [ "$target_p" != "$_parent_pid" ] || continue
      if kill -0 "$target_p" 2>/dev/null; then
        kill -9 "$target_p" 2>/dev/null || true
        _killed_any=1
      fi
    done
    [ "$_killed_any" -eq 0 ] && break
    sleep 0.1 2>/dev/null || sleep 1
    stop_loops=$((stop_loops + 1))
  done

  rm -rf /dev/shm/agh_watchdog.pid /dev/shm/agh_watchdog.lock /dev/shm/agh_op.lock /dev/shm/agh_manual_stop \
         "$AGH_DIR/run/agh_watchdog.pid" "$AGH_DIR/run/agh_watchdog.lock" "$AGH_DIR/run/agh_op.lock" "$AGH_DIR/run/agh_manual_stop" \
         "$BIN_DIR/AdGuardHome.pid" 2>/dev/null || true
fi

# 轻量结构校验（零子进程开销，先快速拦截明显损坏或空 YAML，核心二进制校验延后至新核心就位后仅执行一次）
validate_yaml_structure() {
  vf="$1"
  [ -s "$vf" ] || return 1
  grep -q '^schema_version:' "$vf" 2>/dev/null || return 1
  grep -q '^dns:' "$vf" 2>/dev/null || return 1
  grep -q '^user_rules:' "$vf" 2>/dev/null || return 1
  return 0
}

# 使用目标核心校验 YAML 兼容性（若当前执行环境可执行该架构二进制）
validate_yaml_with_bin() {
  vf="$1"
  check_bin="${2:-$BIN_DIR/AdGuardHome}"
  validate_yaml_structure "$vf" || return 1
  if [ -x "$check_bin" ]; then
    if "$check_bin" --version >/dev/null 2>&1; then
      "$check_bin" --check-config -c "$vf" -w "${vf%/*}" >/dev/null 2>&1 || return 1
    fi
  fi
  return 0
}

copy_and_verify_file() {
  src_f="$1"
  dst_f="$2"
  cp -pf "$src_f" "$dst_f" 2>/dev/null || cp -f "$src_f" "$dst_f" 2>/dev/null || return 1
  [ -f "$dst_f" ] || return 1
  cmp -s "$src_f" "$dst_f" || return 1
  return 0
}

# 用于大体积订阅规则单向备份的轻量校验（避免逐字节全量二次读取回比）
copy_backup_fast() {
  src_f="$1"
  dst_f="$2"
  cp -pf "$src_f" "$dst_f" 2>/dev/null || cp -f "$src_f" "$dst_f" 2>/dev/null || return 1
  [ -f "$dst_f" ] || return 1
  if [ -s "$src_f" ] && [ ! -s "$dst_f" ]; then
    return 1
  fi
  return 0
}

# 同分区优先 O(1) 原子重命名移动，跨设备时回退至安全拷贝校验
move_or_copy_file() {
  src_f="$1"
  dst_f="$2"
  mv -f "$src_f" "$dst_f" 2>/dev/null && return 0
  copy_and_verify_file "$src_f" "$dst_f"
}

# 判定首次安装 vs 已有安装升级
IS_UPGRADE=0
if [ -d "$AGH_DIR" ] && { [ -e "$BIN_DIR/AdGuardHome.yaml" ] || [ -e "$BIN_DIR/AdGuardHome.yaml.bak" ] || [ -d "$BIN_DIR/data/filters" ] || [ -f "$SCRIPT_DIR/config.prop" ]; }; then
  IS_UPGRADE=1
fi

# 解锁旧脚本防篡改保护（仅在确认备份完成后才会修改任何运行文件）
if [ -d "$SCRIPT_DIR" ]; then
  i18n_print "- Unlocking old script files" "- 正在解锁旧脚本文件"
  find "$AGH_DIR/scripts" "$ADGPATH" -type f -name "*.sh" -exec chattr -i {} + 2>/dev/null || true
fi

if [ "$IS_UPGRADE" -eq 1 ]; then
  i18n_print "- Existing installation detected: creating dedicated upgrade backup" "- 检测到已有安装：正在创建本次升级专属备份"
  UPGRADE_TS="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo 0)_$$"
  UPGRADE_BACKUP_DIR="$AGH_DIR/backup_upgrade_${UPGRADE_TS}"
  if [ -e "$UPGRADE_BACKUP_DIR" ]; then
    fail_install "Dedicated backup path already exists: $UPGRADE_BACKUP_DIR" "专属备份目录已存在: $UPGRADE_BACKUP_DIR"
  fi
  mkdir -p "$UPGRADE_BACKUP_DIR/bin" "$UPGRADE_BACKUP_DIR/scripts" "$UPGRADE_BACKUP_DIR/filters" "$UPGRADE_BACKUP_DIR/state" || \
    fail_install "Failed to create dedicated backup directory" "创建本次升级专属备份目录失败"

  # 1. 备份配置文件并校验存在性与完整性
  if [ -f "$BIN_DIR/AdGuardHome.yaml" ]; then
    copy_and_verify_file "$BIN_DIR/AdGuardHome.yaml" "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml" || \
      fail_install "Failed to back up AdGuardHome.yaml" "备份 AdGuardHome.yaml 失败"
  fi
  if [ -f "$BIN_DIR/AdGuardHome.yaml.bak" ]; then
    copy_and_verify_file "$BIN_DIR/AdGuardHome.yaml.bak" "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml.bak" || \
      fail_install "Failed to back up AdGuardHome.yaml.bak" "备份 AdGuardHome.yaml.bak 失败"
  fi
  if [ -f "$SCRIPT_DIR/config.prop" ]; then
    copy_and_verify_file "$SCRIPT_DIR/config.prop" "$UPGRADE_BACKUP_DIR/scripts/config.prop" || \
      fail_install "Failed to back up config.prop" "备份 config.prop 失败"
  fi
  if [ -f "$SCRIPT_DIR/NoAdsService.sh" ]; then
    copy_and_verify_file "$SCRIPT_DIR/NoAdsService.sh" "$UPGRADE_BACKUP_DIR/scripts/NoAdsService.sh" || \
      fail_install "Failed to back up NoAdsService.sh" "备份 NoAdsService.sh 失败"
  fi

  # 2. 备份模块拥有的自定义状态资源（只处理模块自有路径，不触碰外部引用文件）
  for state_f in app-allow.txt private_dns.bak; do
    if [ -f "$AGH_DIR/$state_f" ]; then
      copy_and_verify_file "$AGH_DIR/$state_f" "$UPGRADE_BACKUP_DIR/state/$state_f" || \
        fail_install "Failed to back up $state_f" "备份 $state_f 失败"
    fi
  done
  if [ -d "$AGH_DIR/proxy_ownership" ]; then
    mkdir -p "$UPGRADE_BACKUP_DIR/state/proxy_ownership" || \
      fail_install "Failed to create proxy_ownership backup dir" "创建代理归属记录备份目录失败"
    for pof in "$AGH_DIR/proxy_ownership/"*; do
      [ -f "$pof" ] || continue
      copy_and_verify_file "$pof" "$UPGRADE_BACKUP_DIR/state/proxy_ownership/${pof##*/}" || \
        fail_install "Failed to back up proxy ownership state" "备份代理归属记录失败"
    done
  fi

  # 3. 单向备份当前设备侧订阅规则文件集合并记录清单（升级阶段绝不覆盖原 filters 目录，无需二次回写比对）
  : > "$UPGRADE_BACKUP_DIR/filters.manifest" || \
    fail_install "Failed to create filters manifest" "创建订阅备份清单失败"
  if [ -d "$BIN_DIR/data/filters" ]; then
    for ff in "$BIN_DIR/data/filters/"*; do
      [ -f "$ff" ] || continue
      fname="${ff##*/}"
      copy_backup_fast "$ff" "$UPGRADE_BACKUP_DIR/filters/$fname" || \
        fail_install "Failed to back up filter file $fname" "备份订阅文件 $fname 失败"
      printf '%s\n' "$fname" >> "$UPGRADE_BACKUP_DIR/filters.manifest" || \
        fail_install "Failed to record filter manifest for $fname" "写入订阅清单 $fname 失败"
    done
  fi

  # 4. 快速结构预检：提前拦截完全缺失/空配置，避免无效解压
  HAS_STRUCT_YAML=0
  if [ -f "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml" ] && validate_yaml_structure "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml"; then
    HAS_STRUCT_YAML=1
  elif [ -f "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml.bak" ] && validate_yaml_structure "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml.bak"; then
    HAS_STRUCT_YAML=1
  fi
  if [ "$HAS_STRUCT_YAML" -ne 1 ]; then
    fail_install "Existing AdGuardHome.yaml is missing or corrupted in upgrade path (refusing to overwrite with factory template)" "升级路径下现有 AdGuardHome.yaml 损坏且无有效 .bak（拒绝静默重置为出厂模板）"
  fi

  # 5. 仅解压升级所需的脚本、核心与模式模板至同分区暂存目录（跳过包内自带 bin/data/filters/*，零多余 I/O）
  i18n_print "- Extracting updated binary and scripts" "- 正在解压新版程序与运行脚本"
  STAGE_DIR="$AGH_DIR/.stage_upgrade_${UPGRADE_TS}"
  rm -rf "$STAGE_DIR" 2>/dev/null
  mkdir -p "$STAGE_DIR" || fail_install "Failed to create staging directory" "创建升级暂存目录失败"
  if ! unzip -q -o "$ZIPFILE" "scripts/*" \
         "bin/AdGuardHome" "bin/AdGuardHome_overseas.yaml" "bin/AdGuardHome_cn.yaml" "bin/default_user_rules.txt" \
         -d "$STAGE_DIR"; then
    rm -rf "$STAGE_DIR" 2>/dev/null
    fail_install "Failed to extract package files to staging directory" "解压升级包到暂存目录失败"
  fi

  for req_f in \
    "$STAGE_DIR/bin/AdGuardHome" \
    "$STAGE_DIR/bin/AdGuardHome_overseas.yaml" \
    "$STAGE_DIR/bin/AdGuardHome_cn.yaml" \
    "$STAGE_DIR/bin/default_user_rules.txt" \
    "$STAGE_DIR/scripts/config.prop" \
    "$STAGE_DIR/scripts/iptables.sh" \
    "$STAGE_DIR/scripts/switch_mode.sh" \
    "$STAGE_DIR/scripts/ProxyConfig.sh" \
    "$STAGE_DIR/scripts/NoAdsService.sh"; do
    if [ ! -s "$req_f" ]; then
      rm -rf "$STAGE_DIR" 2>/dev/null
      fail_install "Staged file missing or empty: $req_f" "暂存文件缺失或为空: $req_f"
    fi
  done

  # 使用新核心一次性校验现有主配置（或 .bak 备选）的兼容性
  i18n_print "- Validating existing configuration against updated core" "- 正在校验现有配置与新核心兼容性"
  RESTORE_YAML=""
  if [ -f "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml" ] && validate_yaml_with_bin "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml" "$STAGE_DIR/bin/AdGuardHome"; then
    RESTORE_YAML="$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml"
  elif [ -f "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml.bak" ] && validate_yaml_with_bin "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml.bak" "$STAGE_DIR/bin/AdGuardHome"; then
    RESTORE_YAML="$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml.bak"
    i18n_print "- Primary YAML invalid; using verified .bak from current install" "- 主配置无效，使用当前安装已验证的 .bak 备份"
  else
    rm -rf "$STAGE_DIR" 2>/dev/null
    fail_install "Existing configuration failed validation against new AdGuardHome binary" "现有配置未通过新核心兼容性校验"
  fi

  # 6. 同分区直接原子移动替换程序文件、脚本与模式参考模板，跳过用户配置与规则目录
  i18n_print "- Updating binary and scripts (preserving configs and filters)" "- 正在更新核心与脚本（保留现有配置与订阅）"
  mkdir -p "$BIN_DIR" "$SCRIPT_DIR" "$BIN_DIR/data/filters" || {
    rm -rf "$STAGE_DIR" 2>/dev/null
    fail_install "Failed to prepare runtime directories" "准备运行目录失败"
  }

  for bin_item in AdGuardHome AdGuardHome_overseas.yaml AdGuardHome_cn.yaml default_user_rules.txt cacerts.pem; do
    if [ -f "$STAGE_DIR/bin/$bin_item" ]; then
      if ! move_or_copy_file "$STAGE_DIR/bin/$bin_item" "$BIN_DIR/$bin_item"; then
        rm -rf "$STAGE_DIR" 2>/dev/null
        fail_install "Failed to update binary/template $bin_item" "更新程序文件 $bin_item 失败"
      fi
    fi
  done

  for sh_file in "$STAGE_DIR/scripts/"*.sh; do
    [ -f "$sh_file" ] || continue
    sh_name="${sh_file##*/}"
    if ! move_or_copy_file "$sh_file" "$SCRIPT_DIR/$sh_name"; then
      rm -rf "$STAGE_DIR" 2>/dev/null
      fail_install "Failed to update script $sh_name" "更新脚本 $sh_name 失败"
    fi
  done

  # 合并 config.prop：以新模板为基础，保留用户原有的个人设置（RUN_MODE / ENABLE_SNI / VPN_DNS_TAKEOVER / PROXY_URL / redir_port）
  STAGE_PROP="$STAGE_DIR/scripts/config.prop.merged"
  STAGE_PROP_TMP="$STAGE_DIR/scripts/config.prop.tmp"
  cp -f "$STAGE_DIR/scripts/config.prop" "$STAGE_PROP" || {
    rm -rf "$STAGE_DIR" 2>/dev/null
    fail_install "Failed to prepare merged config.prop" "准备合并 config.prop 失败"
  }
  if [ -f "$UPGRADE_BACKUP_DIR/scripts/config.prop" ]; then
    if [ -n "$(tail -c 1 "$STAGE_PROP" 2>/dev/null || true)" ]; then
      echo "" >> "$STAGE_PROP"
    fi
    old_url=$(sed -n 's/^PROXY_URL=//p' "$UPGRADE_BACKUP_DIR/scripts/config.prop" | head -n 1 | tr -d '"' | tr -d "'")
    if [ -n "$old_url" ] && [ "$old_url" != " " ] && ! echo "$old_url" | grep -q "smjcdh\.top"; then
      grep -v '^PROXY_URL=' "$STAGE_PROP" > "$STAGE_PROP_TMP" 2>/dev/null || true
      mv -f "$STAGE_PROP_TMP" "$STAGE_PROP"
      if [ -n "$(tail -c 1 "$STAGE_PROP" 2>/dev/null || true)" ]; then
        echo "" >> "$STAGE_PROP"
      fi
      echo "PROXY_URL=\"$old_url\"" >> "$STAGE_PROP"
      i18n_print "- Preserved PROXY_URL from existing config" "- 已保留原有 PROXY_URL"
    fi
    for key in VPN_DNS_TAKEOVER RUN_MODE ENABLE_SNI redir_port; do
      old_val=$(sed -n "s/^${key}=//p" "$UPGRADE_BACKUP_DIR/scripts/config.prop" | head -n 1)
      if [ -n "$old_val" ]; then
        if grep -q "^${key}=" "$STAGE_PROP" 2>/dev/null; then
          awk -v k="$key" -v v="$old_val" '
            index($0, k "=") == 1 { print k "=" v; next }
            { print $0 }
          ' "$STAGE_PROP" > "$STAGE_PROP_TMP" && mv -f "$STAGE_PROP_TMP" "$STAGE_PROP"
        else
          echo "${key}=${old_val}" >> "$STAGE_PROP"
        fi
      fi
    done
  fi
  if ! move_or_copy_file "$STAGE_PROP" "$SCRIPT_DIR/config.prop"; then
    rm -rf "$STAGE_DIR" 2>/dev/null
    fail_install "Failed to write merged config.prop" "写入合并后的 config.prop 失败"
  fi

  # 7. 若运行 YAML 来自 .bak 降级或不存在则补回，并确保 .yaml.bak 与当前配置一致
  if [ "$RESTORE_YAML" != "$UPGRADE_BACKUP_DIR/bin/AdGuardHome.yaml" ] || [ ! -f "$BIN_DIR/AdGuardHome.yaml" ]; then
    if ! copy_and_verify_file "$RESTORE_YAML" "$BIN_DIR/AdGuardHome.yaml"; then
      rm -rf "$STAGE_DIR" 2>/dev/null
      fail_install "Failed to preserve AdGuardHome.yaml" "恢复并校验 AdGuardHome.yaml 失败"
    fi
  fi
  if ! copy_and_verify_file "$RESTORE_YAML" "$BIN_DIR/AdGuardHome.yaml.bak"; then
    rm -rf "$STAGE_DIR" 2>/dev/null
    fail_install "Failed to preserve AdGuardHome.yaml.bak" "恢复并校验 AdGuardHome.yaml.bak 失败"
  fi

  # 8. 原地核对订阅规则清单（原 filters 目录未受触动，仅当意外缺失某项时从本次备份单文件补齐）
  while IFS= read -r manifest_fname || [ -n "$manifest_fname" ]; do
    [ -n "$manifest_fname" ] || continue
    if [ ! -f "$BIN_DIR/data/filters/$manifest_fname" ]; then
      if ! copy_and_verify_file "$UPGRADE_BACKUP_DIR/filters/$manifest_fname" "$BIN_DIR/data/filters/$manifest_fname"; then
        rm -rf "$STAGE_DIR" 2>/dev/null
        fail_install "Failed to restore filter $manifest_fname from dedicated backup" "从专属备份还原订阅 $manifest_fname 失败"
      fi
    fi
  done < "$UPGRADE_BACKUP_DIR/filters.manifest"

  # 9. 清理历史遗留的无用缓存库与暂存目录，仅保留本次升级专属备份
  rm -rf "$STAGE_DIR" "$AGH_DIR/ifw" "$BIN_DIR/agh_pid" "$AGH_DIR/datachart"* "$AGH_DIR/app_pause_active" 2>/dev/null || true
  rm -f "$BIN_DIR/data/stats.db"* "$BIN_DIR/data/sessions.db"* "$BIN_DIR/data/querylog.json"* 2>/dev/null || true
  for old_bak in "$AGH_DIR"/backup_upgrade_*; do
    [ -d "$old_bak" ] || continue
    [ "$old_bak" = "$UPGRADE_BACKUP_DIR" ] && continue
    rm -rf "$old_bak" 2>/dev/null || true
  done

else
  # ==================== 首次安装路径 ====================
  i18n_print "- Fresh installation: extracting default configuration and rules" "- 首次安装：正在解压默认配置与规则"
  mkdir -p "$AGH_DIR" "$BIN_DIR" "$SCRIPT_DIR" || fail_install "Failed to create AGH_DIR" "创建模块运行目录失败"
  unzip -q -o "$ZIPFILE" "scripts/*" "bin/*" -d "$AGH_DIR" || fail_install "Failed to extract runtime files" "解压程序与规则文件失败"
  if [ -s "$BIN_DIR/AdGuardHome.yaml" ]; then
    cp -f "$BIN_DIR/AdGuardHome.yaml" "$BIN_DIR/AdGuardHome.yaml.bak" 2>/dev/null || true
  fi
fi

i18n_print "- Setting permissions" "- 设置权限"
find "$AGH_DIR" -type d -exec chmod 0700 {} + 2>/dev/null || true
chmod +x "$BIN_DIR/AdGuardHome" || fail_install "Failed to chmod AdGuardHome" "设置核心执行权限失败"
chmod +x "$SCRIPT_DIR"/*.sh || fail_install "Failed to chmod scripts" "设置脚本执行权限失败"
chown root:net_raw "$BIN_DIR/AdGuardHome" 2>/dev/null || true

# 立即执行一次性安全解锁与广告缓存清理（主用户，零死循环）
sh "$SCRIPT_DIR/NoAdsService.sh" >/dev/null 2>&1 || true

# 清理旧版本可能残留的冲突规则与策略路由
ip rule del pref 99 2>/dev/null || true
ip rule del pref 100 2>/dev/null || true
ip rule del pref 101 2>/dev/null || true
ip route flush table 61 2>/dev/null || true
while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p tcp --dport 853 -j DROP 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 853 -j DROP 2>/dev/null; do :; done
while iptables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
while ip6tables -w 2 -D OUTPUT -p tcp --dport 853 -j REJECT 2>/dev/null; do :; done
while ip6tables -w 2 -D OUTPUT -p udp --dport 853 -j REJECT 2>/dev/null; do :; done
while ip6tables -w 2 -D OUTPUT -p udp --dport 443 -j REJECT 2>/dev/null; do :; done
while iptables -w 2 -t mangle -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
iptables -w 2 -t mangle -F AGH_SNI 2>/dev/null || true
iptables -w 2 -t mangle -X AGH_SNI 2>/dev/null || true
while ip6tables -w 2 -t mangle -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
ip6tables -w 2 -t mangle -F AGH_SNI 2>/dev/null || true
ip6tables -w 2 -t mangle -X AGH_SNI 2>/dev/null || true
while iptables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
iptables -w 2 -t filter -F AGH_SNI 2>/dev/null || true
iptables -w 2 -t filter -X AGH_SNI 2>/dev/null || true
while ip6tables -w 2 -t filter -D OUTPUT -j AGH_SNI 2>/dev/null; do :; done
ip6tables -w 2 -t filter -F AGH_SNI 2>/dev/null || true
ip6tables -w 2 -t filter -X AGH_SNI 2>/dev/null || true

proxy_url_chk=$(sed -n 's/^PROXY_URL=//p' "$SCRIPT_DIR/config.prop" 2>/dev/null | tr -d '"' | tr -d "'" | tr -d '[:space:]' || true)
if [ -n "$proxy_url_chk" ]; then
  sh "$SCRIPT_DIR/ProxyConfig.sh" --once >/dev/null 2>&1 || true
fi

# 安装 AdGuard Home 管理器 APP 到手机主用户 (User 0)
# 保持相同包名与签名覆盖升级，绝不卸载不属于本模块的应用，也不清除用户数据掩盖失败
if [ -f "$MODPATH/AdGuardHomeManager.apk" ]; then
  i18n_print "- Installing Manager APK" "- 正在安装或更新管理器 APK"
  install_res=$(pm install -r -d -g --user 0 "$MODPATH/AdGuardHomeManager.apk" 2>&1 || true)
  if ! echo "$install_res" | grep -q "Success"; then
    install_res=$(pm install -r -d -g "$MODPATH/AdGuardHomeManager.apk" 2>&1 || true)
  fi
  if echo "$install_res" | grep -q "Success"; then
    rm -f "$MODPATH/AdGuardHomeManager.apk"
  else
    i18n_print "! Warning: Manager APK install returned: $install_res (APK kept in $MODPATH/AdGuardHomeManager.apk)" "! 警告: 管理器 APK 自动安装未成功 ($install_res)，安装包已保留在 $MODPATH/AdGuardHomeManager.apk"
  fi
fi

i18n_print "- Installation complete. Reboot device." "- 安装完成，请重启设备。"
