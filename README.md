# adblock-tracking-filters

自动把 AdGuard 官方过滤器与社区广告列表转换成 **Quantumult X** 和 **Clash Verge（Mihomo）** 可直接订阅的拦截规则，由 GitHub Actions 定时重建。

## 规则与客户端

| 规则 | 内容 | 客户端 | 更新 |
|---|---|---|---|
| `Anti-AdBlock.list` | 广告 + 跟踪域名全集，约 28 万条 | QX | 每 8 小时 |
| `Anti-AdBlock-Extra.list` | 补 Anti-AdBlock 未覆盖的 CNAME 追踪域名，1,374 条 | QX | 每 8 小时 |
| `Tracking.list` | 纯跟踪域名，11.6 万条，不含广告 | QX | 每天 |
| `Tracking.rewrite.conf` | URL 路径级拦截，4,814 条 | QX | 每天 |
| `Anti-AdBlock-All-domain.mrs` + `Anti-AdBlock-All-classical.list` | 上面两份 Anti-AdBlock 的完整并集 | Clash Verge | 每 8 小时 |

## 导入方法

### Quantumult X

「设置 → 订阅资源 → 过滤器」里添加（推荐前两条一起订）：

```
https://raw.githubusercontent.com/karllagerfeld-cn/adblock-tracking-filters/main/rules/Anti-AdBlock.list, tag=Anti-AdBlock, update-interval=28800, opt-parser=false, enabled=true
https://raw.githubusercontent.com/karllagerfeld-cn/adblock-tracking-filters/main/rules/Anti-AdBlock-Extra.list, tag=Anti-AdBlock-Extra, update-interval=28800, opt-parser=false, enabled=true
```

只想防跟踪、不拦广告时用 `Tracking.list`（`update-interval=86400`）。需要拦具体 URL 路径时，把 `Tracking.rewrite.conf` 加到 `[rewrite_remote]`（`update-interval=86400`）。

所有分流文件的第三字段都是内置 `reject`，**不需要开启策略偏好，也不要选策略组**——选了代理只会让广告走代理而不是被拦。

### Clash Verge（全局扩展覆写 Merge）

订阅页 → 右键「全局扩展覆写配置 (Merge)」→ 编辑文件，顶格追加：

```yaml
rule-providers:
  QXADB-Domain:
    type: http
    behavior: domain
    format: mrs
    url: "https://raw.githubusercontent.com/karllagerfeld-cn/adblock-tracking-filters/main/rules/mihomo/Anti-AdBlock-All-domain.mrs"
    path: ./rulesets/QXADB-All-domain.mrs
    interval: 86400
  QXADB-Classical:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/karllagerfeld-cn/adblock-tracking-filters/main/rules/mihomo/Anti-AdBlock-All-classical.list"
    path: ./rulesets/QXADB-All-classical.list
    interval: 86400
```

保存后重载配置，再到「编辑规则」页面添加两条 `RULE-SET`（`QXADB-Domain`、`QXADB-Classical`，策略选 REJECT），规则才真正生效。

顶格 `rule-providers:` 是深度合并，不会覆盖订阅自带的规则集；若原 Merge 已有同名键，把条目并进去，不要重复声明。日志里应看到两个 provider 下载成功（首次约 2.6 MB）。`.mrs` 只支持 domain 行为，73 条通配必须走 classical text，两者一起订才等于完整列表。

## 上游内容

| 产物 | 上游 |
|---|---|
| `Tracking.list`、`Tracking.rewrite.conf` | AdGuard [filter_3_Spyware](https://github.com/AdguardTeam/FiltersRegistry)（防跟踪保护过滤器） |
| `Anti-AdBlock.list` | [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters) 的 `adblockqx.conf` + [privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD) 的 `anti-ad-quanx.txt`，合并去重 + 父域归并 + PSL 校验 |
| `Anti-AdBlock-Extra.list` | 上述两份 + `Tracking.list` 的差集，捞回 CNAME 伪装的追踪子域 |
| `rules/mihomo/*` | 由 `Anti-AdBlock.list` + `Anti-AdBlock-Extra.list` 转换，用官方 mihomo 二进制编译 `.mrs` |

派生数据保留上游来源与许可声明（AdGuard FiltersRegistry 为 GPL-3.0）。

## 实现效果

- **域名级拦截无需 MITM**：在连接阶段直接拒绝，不解密 TLS，不影响证书锁定的 App。
- **Anti-AdBlock 覆盖广告与跟踪全集**；Extra 只补它没覆盖的 CNAME 追踪域，两者叠加零重复。逐条核对过：Mihomo 的 All 规则集 = 这两个 QX 列表的完整并集，281,255 条无遗漏。
- **Tracking.list 只拦跟踪器、不碰广告位**，适合只要隐私保护的场景。
- **URL 级重写能拦具体路径**（如 `/log.gif`），但要为 3,795 个主机开 MITM，可能让证书锁定的 App 连不上，按需启用；出问题第一个动作就是关掉它。
- **无法保义的规则一律跳过**（`$third-party`、`$removeparam`、元素隐藏等），不扩大拦截范围；跳过统计见 `rules/report.json`。
- **全自动更新**：Anti-AdBlock 每 8 小时（跟随 adblockqx，晚 10 分钟）、Tracking 每天、Mihomo 规则集跟随 Anti-AdBlock，均自动提交；客户端按上面的 `update-interval` / `interval` 定时拉取。
