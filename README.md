# qx-adguard-tracking

把 AdGuard 官方过滤器转成 Quantumult X 能直接订阅的**分流**与**重写**文件，每天自动重建。

| 上游 | 用途 |
|---|---|
| [`filter_3_Spyware`](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt) | 间谍软件 / 跟踪器域名 → 分流 + 少量 URL 重写 |
| [`filter_17_TrackParam`](https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt) | URL 去参规则 → **只出报告，不转换**（原因见下） |

## 订阅地址

```
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.rewrite.conf
```

国内访问 `raw.githubusercontent.com` 经常不通，可换成 jsDelivr 镜像（内容相同，更新有缓存延迟）：

```
https://cdn.jsdelivr.net/gh/karllagerfeld-cn/qx-adguard-tracking@main/rules/Tracking.list
https://cdn.jsdelivr.net/gh/karllagerfeld-cn/qx-adguard-tracking@main/rules/Tracking.rewrite.conf
```

## Quantumult X 配置

```ini
[filter_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.list, tag=AdGuard Spyware, force-policy=reject, update-interval=86400, opt-parser=false, enabled=true

[rewrite_remote]
https://raw.githubusercontent.com/karllagerfeld-cn/qx-adguard-tracking/main/rules/Tracking.rewrite.conf, tag=AdGuard Spyware Rewrite, update-interval=86400, opt-parser=false, enabled=true
```

几点说明：

- 文件已经是 QX 原生格式，所以 `opt-parser=false` —— 这是为了**避免**被第三方资源解析器二次改写，不是因为性能。
- 重写文件末尾自带 `hostname = ...`，QX 加载远程重写资源时会合并 MITM 主机名，通常不需要再改 `[mitm]`。若你的 QX 版本不认，把那一行里的主机名追加到 `[mitm] hostname = ` 后面即可（**追加，不是替换**）。
- 分流文件里每一行都是 `reject`，订阅参数又加了 `force-policy=reject`，双保险。

## 生成的文件

| 文件 | 内容 |
|---|---|
| `rules/Tracking.list` | `HOST-SUFFIX` / `HOST` / `HOST-WILDCARD`，全部 reject |
| `rules/Tracking.rewrite.conf` | `url reject` 的 URL 级规则 + 内嵌 `hostname =` |
| `rules/report.json` | 分类条数、跳过原因、上游大小与 sha256 |
| `rules/skipped.txt` | 没被转换的原始规则（每类抽样） |

产物由 GitHub Actions 每天 20:23 UTC（香港时间 04:23）重建，一次 commit 同时更新，避免分流与重写出现版本错位。

## 转换原则

**只做能保义的转换，不能保义的一律跳过并记录。** 这是这份列表和"把 AdGuard 规则全replace成 reject"的最大区别。

| 上游形态 | 处理 |
|---|---|
| `\|\|domain^` | `HOST-SUFFIX,domain,reject`（`\|\|` 本身含所有子域，语义等价） |
| `\|\|logws*.ati-host.net^` | `HOST-WILDCARD`（精确等价，且不需要 MITM） |
| `\|\|1.2.3.4^` | `HOST,1.2.3.4,reject` |
| `\|\|host/path^` | `(?i)^https?://(?:[a-z0-9-]+\.)*host(?::\d+)?/path(?:[^0-9A-Za-z_.%-]\|$) url reject` |
| `$third-party` | 跳过。QX 的 host 规则没有"仅第三方请求"的概念，删掉条件就等于把「跨站才拦」放大成「一律拦」 |
| `$domain=` / `$script` / `$image` / `$document` … | 跳过。丢了条件就改变了适用范围 |
| `$removeparam` | 跳过。见下方限制 |
| `##` `#%#` `#$#` `$$` | 跳过。QX 没有元素隐藏 / 脚本注入能力，硬转会变成整站误杀 |
| `@@` 例外 | 收集后从输出中剔除对应域名；无法表达时宁可少拦 |
| `!#if` 条件指令 | 按 AdGuard 语义求值（本客户端所有平台常量均为 false），支持 `&&` `\|\|` `!` 括号 `!#else` 嵌套 |

### 完整性守卫

任一条不通过就**不发布**，保留上一版文件：

- HTTP 200、非 HTML、字节数下限
- 载荷必须以换行结尾、末行必须是完整规则（截断最常见的表现就是最后一行被切断）
- `!#if` / `!#endif` 必须配对
- 某一类规则数相对上一版变动超过 25%，或从上千条掉到 0 → 中止
- PSL 校验：不许把 `co.uk` 这类公共后缀当域名拦；`github.io` 等共享宿另有手工拒绝名单

## 已知限制

1. **QX 没有删除 URL 查询参数的能力。** rewrite 的动作只有 `reject` / `reject-200` / `reject-img` / `reject-dict` / `reject-array` / `302` / `307` / header / body / script。所以 `filter_17_TrackParam` 的 2000 多条 `$removeparam`（其中 600 多条是无域名的全站规则）**一条都没转**。把它们近似成 `url reject` 会让带 utm 参数的正常链接直接打不开——那不是保守，是事故。具体条数见 `report.json`。
2. 元素隐藏、脚本注入、CSS/HTML 过滤规则不转换，因此网页里的跟踪元素不会被"隐藏"，只有网络请求被拦。
3. 定时轮询，不是实时同步：上游改动 → 下一轮 cron → QX 下一次 `update-interval`。最坏情况接近 48 小时。
4. 分流列表很大（十几万条、数 MB）。QX 能吃下这个量级，但首次导入和每次更新会有可感知耗时。
5. `url reject` 会在 HTTPS 上生效，需要 MITM 覆盖对应主机；这就是重写文件里带 `hostname =` 的原因。

## 本地运行

```bash
python scripts/selftest.py          # 无网络，跑规则分类与守卫的断言
python scripts/convert.py           # 下载 + 转换 + 校验，写入 rules/
python scripts/convert.py --dry-run # 只统计不落盘
python scripts/convert.py --lean    # 丢掉 !#if 块内的规则（更小的列表）
python scripts/convert.py --local spyware=./sample.txt trackparam=./tp.txt --allow-small
```

## 来源与许可

过滤规则来自 [AdguardTeam/FiltersRegistry](https://github.com/AdguardTeam/FiltersRegistry)（GPL-3.0）与 [AdguardTeam/AdGuardFilters](https://github.com/AdguardTeam/AdGuardFilters)。本仓库的产物是这些规则的派生数据，保留来源与许可声明；转换脚本本身见仓库内 `scripts/`。

参考格式：[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（QX 重写文件结构）、[217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)（QX 分流文件结构）。
