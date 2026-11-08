# qx-adguard-tracking

把 AdGuard 官方过滤器与两个社区广告列表转成 Quantumult X 能直接订阅的规则，自动重建。仓库提供**三个订阅文件**，按需选一个或两个。

## 三个订阅文件

| 文件 | 上游 | 内容 | 更新频率 |
|---|---|---|---|
| **`Anti-AdBlock.list`** | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 的 `adblockqx.conf`<br>[privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) 的 `anti-ad-quanx.txt` | 约 27.5 万条，广告 + 跟踪器域名 | **每 8 小时**，比 adblockqx 晚 10 分钟 |
| **`Anti-AdBlock-Extra.list`** | 上面两个列表 + 本仓库 `Tracking.list` | 约 850 条，只补 Anti-AdBlock 没有的 | 跟随 Anti-AdBlock |
| **`Tracking.list`** | AdGuard `filter_3_Spyware`（防跟踪保护过滤器） | 11.6 万条，纯跟踪器域名，不含广告 | 每天 04:23 HKT |
| `Tracking.rewrite.conf` | 同上 | 4,814 条 URL 级重写 | 每天 |

三个列表的定位：

- **Anti-AdBlock** 是"广告 + 跟踪"的全集，两个社区列表去重合并，覆盖最广。
- **Anti-AdBlock-Extra** 是个小补丁，专门捞回 AdGuard 里有、那两个大列表没有的 CNAME 伪装追踪域名。它很小（约 25 KB），必须**和 Anti-AdBlock 一起订**才有意义。
- **Tracking.list** 只从 AdGuard Spyware filter 转换，不含广告域。适合"只想防跟踪、不想拦广告"的场景。

### 该订哪个

| 你的目标 | 订阅 |
|---|---|
| 广告 + 跟踪全拦（推荐） | `Anti-AdBlock.list` + `Anti-AdBlock-Extra.list` |
| 只防跟踪、不碰广告位 | `Tracking.list` |
| 上次那个 QX 通配告警怕了 | 三个都不会触发（Extra 73 条通配，Anti-AdBlock 0 条） |

⚠️ **`Tracking.list` 和 `Anti-AdBlock` 不要同时订**——前者 99% 的域名已包含在后者里，同时订只是让 QX 多匹配 11.6 万条重复规则。

## 订阅地址

```
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Anti-AdBlock.list
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Anti-AdBlock-Extra.list
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.rewrite.conf
```

国内访问 `raw.githubusercontent.com` 有时不通。以下替代地址指向同一份文件，实测（2026-11-09，华南家宽）可用：

| 线路 | 实测 | 用法 |
|---|---|---|
| 直连 raw | 0.5s | 上面那几个地址 |
| gh-proxy | 1.9s | 在 `https://raw.githubusercontent.com/...` 前面加 `https://gh-proxy.com/` |
| gcore.jsDelivr | 3.4s | `https://gcore.jsdelivr.net/gh/karllagerfeld-cn/qx-adguard-tracking@main/rules/<文件名>` |

**`cdn.jsdelivr.net` 和 `raw.gitmirror.com` 实测连不通**（返回 000），不要用。

> 已订阅旧版本时，QX 里删掉该资源重新添加最干净。判断拉到的是新版看文件头 `# TOTAL:`。

## Quantumult X 配置

推荐组合：

```ini
[filter_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Anti-AdBlock.list, tag=Anti-AdBlock, update-interval=28800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Anti-AdBlock-Extra.list, tag=Anti-AdBlock-Extra, update-interval=28800, opt-parser=false, enabled=true
```

只防跟踪：

```ini
[filter_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list, tag=AdGuard Spyware, force-policy=reject, update-interval=86400, opt-parser=false, enabled=true
```

需要 URL 级拦截时再加（详见下方「该不该订阅重写文件」）：

```ini
[rewrite_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.rewrite.conf, tag=AdGuard Spyware Rewrite, update-interval=86400, opt-parser=false, enabled=true
```

关于"策略偏好"：三个分流文件的第三字段都是 `reject`（内置动作），**不需要开启策略偏好，也不要选策略组**。开了并选了代理，只会让广告走代理而不是被拦。只有文件里写的是策略组名（如 `Advertising`）时才需要那一步。

## 生成的文件

| 文件 | 内容 | 规模 |
|---|---|---|
| `rules/Anti-AdBlock.list` | adblockqx + anti-AD 合并去重 | 约 27.5 万条 / 10.5 MB |
| `rules/Anti-AdBlock-Extra.list` | Tracking.list − Anti-AdBlock 的差集 | 约 850 条 / 25 KB |
| `rules/Tracking.list` | `HOST-SUFFIX` + `HOST-WILDCARD`，全部 reject | 11.6 万条 / 4.85 MB |
| `rules/Tracking.rewrite.conf` | `url reject` + 内嵌 `hostname =`（3,795 主机） | 4,814 条 / 554 KB |
| `rules/report.json` | Tracking 转换的分类条数与跳过原因 | — |
| `rules/anti-adblock-report.json` | 两个源的贡献条数、去重量 | — |
| `rules/skipped.txt` | 未转换的原始规则（每类抽样 25 条） | — |

### Anti-AdBlock 怎么合并

两个源都是 QX 原生语法，所以是纯集合运算，不做语法转换：

1. 合并去重：同一域名只留一条；
2. **父域归并**：`example.com` 已在时删掉 `a.example.com`——`host-suffix` 按后缀匹配，子域规则永远轮不到命中，留着只浪费解析时间；
3. **PSL 校验**：拒绝把 `co.uk` 这类公共后缀当域名拦。

### Extra 怎么来的

`Anti-AdBlock-Extra` = `Tracking.list` − `Anti-AdBlock`。某条规则只有在「它本身和它的所有父域都不在 Anti-AdBlock 里」时才会进 Extra，所以和 Anti-AdBlock 叠加不会产生任何重复。

每天大约 850 条，主要是 CNAME 伪装的追踪子域（`cname.xxx`、`event.xxx`、`xxx.omtrdc.net` 这类）——两个大列表覆盖不到，因为这类域名要靠 CNAME uncloaking 才能发现。

## 该不该订阅重写文件

**分流直接订，重写请先看完这段。**

分流靠匹配域名，不需要 MITM。重写要拦的是"某个域名下的某个路径"，QX 只有解密 TLS 才看得见路径，所以要为规则涉及的每个主机开 MITM。当前 4,814 条规则覆盖 **3,795 个主机**，`hostname =` 那一行约 128 KB。

代价是真实的：每次 TLS 连接多一次证书协商；开了证书锁定（pinning）的 App 可能直接连不上，而且很难归因。这 3,795 个主机里包含 `163.com`、`01net.com` 这类正常网站——只是为了拦其中一条埋点路径。

所以：只想要整域拦截跟踪器 → 不订重写；确实要拦 `/log.gif`、`/api/counters/` 这类路径，并能接受代价 → 再订。订了之后某个 App 异常，第一个动作就是关掉它。

## Tracking.list 的转换原则

**只做能保义的转换，不能保义的一律跳过并记录。**

| 上游形态 | 处理 |
|---|---|
| `\|\|domain^` | `HOST-SUFFIX,domain,reject`（`\|\|` 本含所有子域，语义等价） |
| `\|\|logws*.ati-host.net^` | `HOST-WILDCARD`（精确等价，不需要 MITM） |
| `\|\|host/path^` | `(?i)^https?://(?:[a-z0-9-]+\.)*host(?::\d+)?/path(?:[^0-9A-Za-z_.%-]\|$) url reject` |
| `$third-party`（2,901 条） | 跳过。QX 的 host 规则没有"仅第三方请求"，删掉条件就把「跨站才拦」放大成「一律拦」 |
| `$domain=` / `$script` / `$image` / `$document` | 跳过，丢了条件就改变了适用范围 |
| `$removeparam`（2,552 条） | 跳过。QX 没有去参能力，`filter_17_TrackParam` 因此只出报告 |
| `##` `#%#` `#$#` `$$`（792 条） | 跳过。QX 没有元素隐藏 / 脚本注入能力 |
| `@@` 例外 | 收集后从输出剔除对应域名 |
| `!#if` 条件指令（76 对） | 按 AdGuard 语义求值，支持 `&&` `\|\|` `!` 括号 `!#else` 嵌套 |

一个细节：`^` 在 AdGuard 里是"分隔符"（`/`、`?`、`#`、串尾都算），不是路径分隔符。所以 `||host/ad^` 的转出正则是 `/ad` 后跟 `(?:[^0-9A-Za-z_.%-]|$)`，否则 `/advertisement` 也会被拦——那就是扩大拦截范围。

### 完整性守卫

任一条不通过就**不发布**，保留上一版文件：

- HTTP 200、非 HTML、`Content-Length` 与实际字节数一致（最强的截断检测）
- 载荷必须以换行结尾、末行不是残缺片段
- `!#if` / `!#endif` 必须配对
- 某类规则数相对上一版变动超过 25%，或从上千条掉到 0 → 中止
- Anti-AdBlock 总数低于 20 万 → 中止；Extra 超过 2 万条 → 中止（说明 Anti-AdBlock 抓空了）
- PSL 校验 + 共享宿拒绝名单

## 已知限制

1. **QX 没有删除 URL 查询参数的能力**。rewrite 动作只有 `reject` / `reject-200` / `reject-img` / `reject-dict` / `reject-array` / `302` / `307` / header / body / script。`filter_17_TrackParam` 的规则（其中 416 条是无域名的全站去参）**一条都没转**。近似成 `url reject` 会让带 utm 的正常链接打不开。
2. 元素隐藏、脚本注入、CSS/HTML 过滤不转换，所以网页里的跟踪元素不会被"隐藏"，只有网络请求被拦。
3. 定时轮询，不是实时同步。Anti-AdBlock 跟着 adblockqx 的 8 小时节奏，Tracking 每天；下游 QX 的 `update-interval` 再叠加一次延迟。
4. 列表较大：Anti-AdBlock 约 27.5 万条 / 10.5 MB。QX 能吃下（blackmatrix7 单个分流文件 29 万条），但首次导入和每次更新有可感知耗时。
5. `url reject` 返回 404，且 QX 对高频重复请求有 0~5 秒动态延迟；某些埋点 SDK 会把 404 当失败重试。
6. Tracking.list 的 `HOST-WILDCARD` 限制在 90 条（QX 建议 <100，通配是线性扫描）。先删父域已被整域拦截的，再按父域轮转保留，每个追踪家族至少留最窄的一条。参数 `--max-wildcard` 可调。

## 本地运行

```bash
python scripts/selftest.py            # 无网络，规则分类与守卫断言
python scripts/convert.py             # Tracking.list + Tracking.rewrite.conf
python scripts/anti_adblock.py        # Anti-AdBlock + Anti-AdBlock-Extra
python scripts/convert.py --dry-run   # 只统计不落盘
python scripts/convert.py --lean      # 丢掉 !#if 块内的规则
python scripts/anti_adblock.py --tracking rules/Tracking.list --dry-run
```

## 来源与许可

- 上游过滤规则来自 [AdguardTeam/FiltersRegistry](https://github.com/AdguardTeam/FiltersRegistry)（GPL-3.0）、[217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)、[privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD)。本仓库产物是这些规则的派生数据，保留来源与许可声明。
- 格式参考：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)、[217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)。
