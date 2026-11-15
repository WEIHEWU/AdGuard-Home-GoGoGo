# AdGuard-Home-GoGoGo

> **AdGuard-Home-GoGoGo - 面向 Android 的轻量级 AdGuard Home 模块，支持海外/国内双模一键切换与精准去广告**

**[📥 下载全能统一模块包 (AdGuard_Home_gogogo_20261113.1.zip)](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo/releases/download/v20261113.1/AdGuard_Home_gogogo_20261113.1.zip)** · **[📱 单独下载管理器 APK (v2.24.18)](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo/releases/download/v20261113.1/AdGuardHomeManager.apk)** · [Releases 页面 (`v20261113.1`)](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo/releases/latest)

基于 Magisk / KernelSU / APatch 的 **AdGuard-Home-GoGoGo**（模块显示名称：`AdGuard Home GoGoGo`）全设备级满血 DNS + SNI 双引擎去广告防火墙模块。内置专属深度瘦身核心 **[AdGuard-Home-GoGoGo-Core](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo-Core)**（`11.75 MiB` 纯静态 `ARMv8.2` LSE 加速、完整内置 NFQUEUE SNI 过滤、100% 零后台磁盘写 I/O），专为追求**极致省电、零断流、局域网免检直通、临时 Root 软重启 30 秒自愈、以及 VPN / 代理无缝协同**打造。

配套管理器开源仓库：[AdGuard-Home-GoGoGo Manager](https://github.com/WEIHEWU/AdGuard-Home-GoGoGo-Manager)（桌面名称：`AdGuard Home GoGoGo`，快捷磁贴：`AGH GoGoGo`，包名：`com.wu.adgogogo`，已内置于模块刷机包中，刷入时自动安装）

---

## 🌐 单包统一发布 · 内置「海外 / 国内」双模无损热切换

无需再区分下载两个不同的刷机包！本模块采用**单包统一发布**，内置 [`AdGuardHome_overseas.yaml`](module/bin/AdGuardHome_overseas.yaml) 与 [`AdGuardHome_cn.yaml`](module/bin/AdGuardHome_cn.yaml) 双预设模板及 [`switch_mode.sh`](module/scripts/switch_mode.sh) 热切换引擎：

- **默认激活模式**：初次刷入默认激活 **🌐 海外模式 (`overseas`)**；
- **App 内一键无损热切换**：打开配套管理器 `AdGuard Home GoGoGo`，在 **「首页快捷栏」** 或 **「设置 -> DNS 设置」** 顶部点击分段开关即可随时在 **「🌐 海外模式 (Overseas)」** 与 **「🇨🇳 国内模式 (CN)」** 之间毫秒级切换；
- **100% 保留个人数据（升级与切模双保险）**：
  - **刷机升级不丢规则与设置**：升级安装自动区分首次安装与覆盖升级，基于当次独立时间戳备份完整保留设备现有订阅规则文件集合（含同名订阅修改、新增订阅及已删默认订阅状态）与 `AdGuardHome.yaml`，若检测到冲突 hosts 模块或备份异常立即安全中止且零副作用；
  - **白名单级精准切模**：切换模式前先停止核心并重读其停机落盘配置，**仅按白名单更新 `RUN_MODE`、`VPN_COMPANION_MODE`、预设默认上游 DNS 与预设订阅镜像地址**，100% 保留动态端口、密码、自定义规则 (`user_rules`)、用户自建订阅及非预设 DNS 参数，切换失败自动回滚。

| 对比维度 | 🌐 海外模式 (`overseas`，**默认激活**) | 🇨🇳 国内模式 (`cn`) |
| :--- | :--- | :--- |
| **适用场景** | 身处海外（澳洲/欧美/亚太等），物理网络可直连全球 | 身处中国大陆（纯国内直连，或配合 VPN / 订阅链接翻墙） |
| **默认上游 DNS** | **Cloudflare / Google / Quad9 超低延迟 DoH** + 境内政务/高校域名 (`gov.cn`/`edu.cn`/`12306.cn`) 分流回阿里/腾讯 DoH | **阿里 (`223.5.5.5`) + 腾讯 DNSPod (`1.12.12.12`) DoH** 并行请求 |
| **规则订阅源地址** | GitHub 官方直连源 (`raw.githubusercontent.com`) | 国内免翻墙高速镜像 (`ghfast.top`) |
| **VPN 伴生策略** | 自动识别海外环境并保持 `takeover` 接管 VPN 53 端口满血去广告 | 自动识别翻墙防污染 VPN (`Clash`/`Sing-box`/Fake-IP) 并切换 `bypass` 防污染 |

---

## ✨ 核心架构与优化亮点

1. **`nsenter -G 23333` 专属进程组隔离 + 零自吞噬防回环**：
   - 统一采用 `nsenter -G 23333 -t 1` 启动 `AdGuardHome` 核心（`v2026-11-07`），将核心流量（`uid=0, gid=23333`）与安卓系统 `netd`（`uid=0, gid=0`）在内核层彻底物理隔离；
   - 无论当前 Wi-Fi 或 VPN 的系统 DNS 是否与上游 IP（如 `1.1.1.1` / `8.8.8.8` / `223.5.5.5`）重合，均能 100% 拦截系统 DNS 请求且绝不发生核心自吞噬回环。
2. **首包级低功耗 `mangle` 表 SNI 嗅探 (`AGH_SNI`) + 局域网免检直通 + 零 `sysctl` 侵入**：
   - 在 `iptables -t mangle` / `ip6tables -t mangle` 挂载 `AGH_SNI` 链，优先探测内核 `connbytes` 支持（`--connbytes 1:4 --connbytes-dir original --connbytes-mode packets -j NFQUEUE --queue-num 0 --queue-bypass`，不支持时自动回退标准 `443` `NFQUEUE`），仅检查 TLS 握手前 4 个数据包且强制 `--queue-bypass` 零断流，**全程严禁修改任何 `sysctl` 内核参数**；
   - 在 `AGH_SNI` 与 `ADGUARD_DOT` 顶层全协议豁免核心自身（`--gid-owner 23333`）与局域网私有网段（`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` 及 IPv6 `fc00::/7`, `fe80::/10`），完美访问局域网 NAS、投影仪、TVBox 及非标端口 HTTP 服务。
3. **分应用白名单内核级直通 (`App Allowlist`)**：
   - 在配套管理器中勾选任意应用加入白名单后，[`iptables.sh`](module/scripts/iptables.sh) 直接在内核 `ADGUARD`、`ADGUARD6_NAT`、`ADGUARD_DOT`、`AGH_SNI` 四条链顶层通过 `-m owner --uid-owner` 精准放行该应用流量，零后台轮询、零发热且不影响其他应用的去广告保护。
4. **双模代理安全自适应（归属追踪 + 事务级回滚保护）**：
   - **用法 A（使用独立 VPN App）**：保持管理 App 内的 `PROXY_URL` 留空即可，模块对无归属记录的第三方代理配置保持 100% 静默零改动，自动感知 `/sys/class/net/tun*` 状态并配合 `ndc` 无感刷新 DNS 缓存；
   - **用法 B（使用 Box / Clash / Mihomo 模块 + 填订阅链接）**：在管理器的【设置 -> 模块设置 -> `PROXY_URL 订阅链接`】中填入机场订阅并保存，[`ProxyConfig.sh`](module/scripts/ProxyConfig.sh) 先生成候选配置并严格校验目标 DNS 列表（完整支持 `nameserver: []` 空数组、`nameserver:` 空映射与非空列表），预写校验 `<key>.meta.tmp.<pid>` 与原始备份 `.orig` 后再原子提交（若提交异常立即从 `.orig` 自动回滚），清理时支持完整还原或保留外部二次改动的增量清理。
5. **临时 Root 软重启自愈、内核锁并发互斥与极致省电优化**：
   - **软重启就绪等待与单次原子刷表**：[`service.sh`](module/service.sh) 自动等待系统与数据分区就绪，启动与模式切换统一单次调用 [`iptables.sh`](module/scripts/iptables.sh) 完成 `nat`/`mangle` 规则挂载（消除重复刷表抖动与后台无效命令开销），内置内核 `flock` 互斥锁、后台子进程锁句柄关闭与信号安全回收；
   - **核心与管理器低功耗协同**：定制核心针对环形查询日志与统计切片实施底层数组按需收缩、过期会话惰性清理及 DoH 响应体 `io.LimitReader` 排空复用；配套管理器内置目标感知有序模式切换队列、Root 探测缓存、快捷磁贴超时强制回收，并在退至后台或锁屏时自动暂停状态轮询。
6. **取长补短的精炼规则体系（`230,574` 条不重复有效规则，1.2 秒极速启动）**：
   - 完整启用 5 大核心规则源：**GOODBYEADS 主规则** (`122,005` 条) + **AdGuard DNS filter 去重独有库** (`89,293` 条) + **URLHaus 恶意域名库** (`1,832` 条) + **AWAvenue 秋风规则** (`966` 条) + **GOODBYEADS 白名单** (`14,863` 条)；
   - 内置 `1,764` 条精调自定义规则（涵盖 Google 全家桶/Wallet/FCM 推送、局域网公共静态资源、国内主流 App 防误杀白名单及 12 大类隐私与防挖矿增强规则）。

---

## 🛠️ 目录结构与构建

```text
├── module/          # 全能统一模块完整源码（含 overseas / cn 双预设模板与 switch_mode.sh 热切换脚本）
├── releases/        # 打包好的统一模块 zip 与配套管理器 APK
└── build.sh         # 一键构建统一模块包脚本
```

在 macOS / Linux 下运行以下命令即可重新打包：

```bash
chmod +x build.sh
./build.sh 20261113.1
```

## 维护与开源

- 作者与维护：[wu](https://github.com/WEIHEWU)
- 管理器原版基础：[JGeek00/adguard-home-manager](https://github.com/JGeek00/adguard-home-manager)
