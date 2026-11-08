# qx-adguard-tracking

把 AdGuard 官方过滤器转成 Quantumult X 能直接订阅的**分流**与**重写**文件，每天自动重建。

| 上游 | 官方说明 | 当前结果 |
|---|---|---|
| [`filter_3_Spyware`](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt)<br>防跟踪保护过滤器 | 各种在线计数器和网络分析工具的综合列表。用它来隐藏用户在网上的活动，避免跟踪。 | 116,450 条分流 + 4,814 条 URL 重写 |
| [`filter_17_TrackParam`](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt)<br>URL 跟踪过滤器 | 从网址中移除跟踪参数，加强隐私保护。当用户选择在隐身模式下拦截跟踪参数时，此过滤器将自动启用。 | **0 条**，只出报告（原因见下） |

两个上游的分工不一样：**防跟踪保护**在域名层拦掉计数器与分析工具；**URL 跟踪**处理的是网址里 `?utm_source=...` 这类参数，属于"改请求"而不是"拦请求"，Quantumult X 没有这个能力，所以这一个只统计不转换。

## 订阅地址

```
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.rewrite.conf
```

国内访问 `raw.githubusercontent.com` 有时不通。下面这些地址指向同一份文件，实测（2026-11-09，华南家宽）可用性如下：

| 线路 | 实测 | 地址 |
|---|---|---|
| 直连 raw | 0.5s | `https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list` |
| gh-proxy | 1.9s | `https://gh-proxy.com/https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list` |
| gcore.jsDelivr | 3.4s | `https://gcore.jsdelivr.net/gh/karllagerfeld-cn/qx-adguard-tracking@main/rules/Tracking.list` |

**`cdn.jsdelivr.net` 和 `raw.gitmirror.com` 实测连不通**（返回 000），不要用。

换镜像时只替换 `Tracking.list` 前面那一段，后缀不变；`Tracking.rewrite.conf` 同理。

> 已经订阅过旧版本时，QX 里删掉该资源重新添加最干净（走「更新」有时会沿用旧缓存）。判断拉到的是新版看文件头：`# HOST-WILDCARD:` 应该是 `90`，不是 `215`。
## 该不该订阅重写文件

**分流文件直接订，重写文件请先看完这段再决定。**

分流靠匹配域名，不需要 MITM，开了就生效。重写要拦的是"某个域名下的某个路径"，QX 只有解密 TLS 才看得见路径，所以必须为规则涉及的每个主机开启 MITM。当前规则涉及 **3,795 个主机**，`hostname =` 那一行约 128 KB。

代价是真实的：

- 每次 TLS 连接多一次证书协商，首屏会慢一些；主机越多越明显。
- 开启了证书锁定（pinning）的 App 或银行类应用，可能直接连不上，而且很难归因。
- 3,795 个主机里包含 `163.com`、`01net.com` 这类正常网站——它们被 MITM 只是为了拦其中一条埋点路径。

所以建议：

- 只想要"整域拦截跟踪器"→ **只订分流文件**，效果已经有 95% 以上。
- 确实要拦 `/log.gif`、`/api/counters/` 这类路径级埋点，并且能接受上面的代价 → 再订重写文件。
- 订了之后出现某个 App 异常，第一个排查动作就是临时关掉重写订阅。

## Quantumult X 配置

```ini
[filter_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list, tag=AdGuard Spyware, force-policy=reject, update-interval=86400, opt-parser=false, enabled=true

[rewrite_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.rewrite.conf, tag=AdGuard Spyware Rewrite, update-interval=86400, opt-parser=false, enabled=true
```

- 文件已经是 QX 原生格式，`opt-parser=false` 是为了**避免**被第三方资源解析器二次改写，不是性能选项。
- 重写文件末尾自带 `hostname = ...`，QX 加载远程重写资源时会合并 MITM 主机名。若你的 QX 版本不认，把那一行的主机名追加到 `[mitm] hostname = ` 后面（**追加，不是替换**）。
- 分流文件每行都是 `reject`，订阅参数又加了 `force-policy=reject`，双保险。

## 生成的文件

| 文件 | 内容 | 规模 |
|---|---|---|
| `rules/Tracking.list` | `HOST-SUFFIX` 116,360 / `HOST-WILDCARD` 90，全部 reject | 4.85 MB |
| `rules/Tracking.rewrite.conf` | 4,814 条 `url reject` + 内嵌 `hostname =`（3,795 主机） | 554 KB |
| `rules/Merged.list` | 三源合并去重，见下节 | 275,833 条 / 10.5 MB |
| `rules/report.json` | 分类条数、跳过原因、上游大小与 sha256 | — |
| `rules/merged-report.json` | 合并时每个源贡献了多少、去掉了多少 | — |
| `rules/skipped.txt` | 没被转换的原始规则（每类抽样 25 条） | 43 KB |

## `Merged.list`：一份顶三份

如果你只想在 QX 里订一个广告/跟踪列表，订这个：

```ini
[filter_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Merged.list, tag=AdBlock Merged, update-interval=86400, opt-parser=false, enabled=true
```

它把三份 **QX 原生格式**的列表做集合运算合并：

| 源 | 条数 | 合并后新增 |
|---|---:|---:|
| [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) `adblockqx.conf` | 251,792 | 251,792 |
| [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) `anti-ad-quanx.txt` | 103,068 | 25,640 |
| 本仓库 `Tracking.list` | 116,450 | 2,239 |
| **合计（去重 + 剔除被父域覆盖的子域）** | 279,671 | **275,833** |

两件事值得说明：

- **不是简单拼接。** 如果 `example.com` 已经在列表里，`a.example.com` 这种子域规则会被删掉——`host-suffix` 按后缀匹配，子域规则永远轮不到命中，留着只是浪费解析时间。这一步删了 3,916 条。
- **任何一源下载失败就不发布**，保留上一版。少 25 万条的列表比昨天的列表危险得多。

`HOST-WILDCARD` 合并后是 78 条（原本 90 条，12 条被父域覆盖），仍在 QX 建议的 100 条以下。

**注意：`Merged.list` 和 `Tracking.list` 二选一**，别同时订——前者已经包含后者。

产物由 GitHub Actions 每天 20:23 UTC（香港时间 04:23）重建。

## 转换原则

**只做能保义的转换，不能保义的一律跳过并记录。** 这跟"把 AdGuard 规则全 replace 成 reject"是两种东西。

| 上游形态 | 处理 |
|---|---|
| `\|\|domain^` | `HOST-SUFFIX,domain,reject`（`\|\|` 本身含所有子域，语义等价） |
| `\|\|logws*.ati-host.net^` | `HOST-WILDCARD`（精确等价，且**不需要 MITM**，215 条这样省下来的） |
| `\|\|1.2.3.4^` | `HOST,1.2.3.4,reject` |
| `\|\|host/path^` | `(?i)^https?://(?:[a-z0-9-]+\.)*host(?::\d+)?/path(?:[^0-9A-Za-z_.%-]\|$) url reject` |
| `$third-party`（2,901 条） | 跳过。QX 的 host 规则没有"仅第三方请求"，删掉条件就把「跨站才拦」放大成「一律拦」 |
| `$domain=` / `$script` / `$image` / `$document` … | 跳过。丢了条件就改变了适用范围 |
| `$removeparam`（2,136 + 416 条） | 跳过。QX 没有去参能力 |
| `##` `#%#` `#$#` `$$`（792 条） | 跳过。QX 没有元素隐藏 / 脚本注入能力 |
| `@@` 例外 | 收集后从输出剔除对应域名；被修饰符限定的（2,004 条）跳过 |
| `!#if` 条件指令（76 对） | 按 AdGuard 语义求值，支持 `&&` `\|\|` `!` 括号 `!#else` 嵌套 |
| `$badfilter` | 按归一化 pattern 从输出中剔除被禁用的规则（7 条） |

一个细节：`^` 在 AdGuard 里是"分隔符"（`/`、`?`、`#`、串尾都算），不是路径分隔符。所以 `||host/ad^` 转出来的正则是 `/ad` 后面跟 `(?:[^0-9A-Za-z_.%-]|$)`——否则 `/advertisement` 也会被拦，那就是扩大拦截范围了。

### 完整性守卫

任一条不通过就**不发布**，保留上一版文件：

- HTTP 200、非 HTML、`Content-Length` 与实际字节数一致（这是最强的截断检测）
- 载荷必须以换行结尾、末行不是残缺片段
- `!#if` / `!#endif` 必须配对，否则整份文件拒绝解析
- 某一类规则数相对上一版变动超过 25%，或从上千条掉到 0 → 中止
- PSL 校验：不许把 `co.uk` 这类公共后缀当域名拦；`github.io` 等共享宿另有手工拒绝名单

## 已知限制

1. **QX 没有删除 URL 查询参数的能力。** rewrite 动作只有 `reject` / `reject-200` / `reject-img` / `reject-dict` / `reject-array` / `302` / `307` / header / body / script。`filter_17_TrackParam` 的规则（其中 416 条是无域名的全站去参）**一条都没转**。把它们近似成 `url reject` 会让带 utm 参数的正常链接直接打不开——那不是保守，是事故。明细见 `report.json`。
2. 元素隐藏、脚本注入、CSS/HTML 过滤不转换，所以网页里的跟踪元素不会被"隐藏"，只有网络请求被拦。
3. 定时轮询，不是实时同步：上游改动 → 下一轮 cron → QX 下一次 `update-interval`，最坏接近 48 小时。
4. 分流列表 11.6 万条、4.86 MB。QX 能吃下（blackmatrix7 单个分流文件 29 万条），但首次导入和每次更新有可感知耗时。
5. `url reject` 返回 404 且 QX 对高频重复请求有 0~5 秒的动态延迟；这和参考实现一致，但某些埋点 SDK 会把 404 当失败重试。
6. **`HOST-WILDCARD` 被限制在 90 条。** QX 在通配规则过多时会弹出性能错误（它自己的建议是少于 100 条，因为通配是线性扫描，不是哈希查找）。上游有 215 条通配域名规则（`ulog*.kwaipros.com` 这种，无法用 `host-suffix` 等价表达），转换器会先删掉父域已被整域拦截的，再按父域轮转保留 90 条——每个追踪域名家族（字节、快手、B 站等）至少留最窄的一条，其余写入 `report.json` 的 `host_wildcard.dropped_samples`。用 `--max-wildcard` 可以改这个上限。

## 本地运行

```bash
python scripts/selftest.py          # 无网络，跑规则分类与守卫断言
python scripts/convert.py           # 下载 + 转换 + 校验，写入 rules/
python scripts/convert.py --dry-run # 只统计不落盘
python scripts/convert.py --lean    # 丢掉 !#if 块内的规则（更小的列表）
python scripts/convert.py --local spyware=./a.txt trackparam=./b.txt --allow-small
```

## 来源与许可

过滤规则来自 [AdguardTeam/FiltersRegistry](https://github.com/AdguardTeam/FiltersRegistry)（GPL-3.0）。本仓库产物是这些规则的派生数据，保留来源与许可声明。

格式参考：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（QX 重写文件结构）、[217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)（QX 分流文件结构）。
