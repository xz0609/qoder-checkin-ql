# Qoder CN 桌面端 国内多账号每日积分自动签到（青龙面板单文件脚本）

**Qoder（阿里，国内版 qoder.com.cn / 国际版 qoder.com）每日积分自动签到 · 单文件 · 零依赖（仅 Python 标准库）**

每天自动领取 Qoder 国内版每日福利（每天领 100 Credits，领取后 30 天有效）与各类限时 CLAIM\_BENEFIT 活动，并实时刷新额度与套餐。登录一次保存凭证，之后由青龙面板定时任务自动签到。

> ⚠️ **免责声明**：这是第三方逆向脚本，与官方无关，可能违反相关产品的服务条款，接口随时可能失效。仅供个人学习研究，请自行评估风险后使用。

## 亮点

- **零依赖**：仅用 Python 标准库 `urllib` / `ctypes`（AES-GCM / AES-CBC 纯手写实现，NIST 向量验证通过），无需安装任何第三方库

- **单文件**：登录、签到、凭证探测解密、设备指纹全部在 `qoder-checkin.py` 一个文件里

- **双区域**：国内版（qoder.com.cn，支持签到/福利）与国际版（qoder.com，仅额度套餐查询）独立配置，区域独占能力自动门控

- **OAuth 设备授权一键免客户端登录**：PKCE (S256) 设备流，打开浏览器授权即自动入池（双区 URL 参数按官方差异构造）

- **本机已登录凭证只读探测**：桌面 App `auth.v1.dat`（Local State 的 os\_crypt 密钥 → DPAPI 解出 → AES-256-GCM）与 CLI `~/.qoder*/.auth/user`（AES-128-CBC）两类官方存储解密导入；扫描全程只读，交互确认后才写入

- **稳定物理设备指纹隔离**：machineId / sessionId 按账号 UID 加盐哈希派生，同一账号长期固定同一台虚拟物理设备，多账号天然隔离，防跨账号关联风控

- **每日签到走官方新版 campaigns 框架**（2026-09 官方迁移，旧 daily-check-in 接口已下线）：`GET /sash/api/v1/me/campaigns` 列出活动，自动领取全部 CLAIM\_BENEFIT 可领福利（每日 +100 Credits 等）；409 AlreadyExists 归一化为已领；额度（基础 + 赠送/签到）与套餐实时刷新

- **token 生命周期**：临期（< 24h）自动按前缀路由刷新（`drt-` 设备族 / `jrt-` job 族 / PAT 兜底），会话死亡（TOKEN\_EXPIRE）自动停用并提示重登

- **文件凭证**：仅读取脚本同目录 `auths/<uid>.json` 文件（与 Qoder2API-Hub 账号文件同构），无环境变量

- **青龙面板适配**：内置 `cron` + `new Env('..')` 标头，每账号独立随机延时防同时刻打卡，可选 notify.py 通知

## 环境要求

Python 3.8+，无任何第三方依赖。

> `login` / `import` 需在本地带浏览器的环境执行（import 仅支持 Windows：DPAPI 解密）；`checkin` 任意平台（青龙容器）均可。

## 用法

#### 以下两种方式，任选其一即可。

- 方式一、 登录（OAuth 设备授权，**本地执行**，需带浏览器的环境）：

    ```bash
    python qoder-checkin.py login          # 交互选择区域，默认国内版
    python qoder-checkin.py login cn       # 直接指定：国内版
    python qoder-checkin.py login intl     # 直接指定：国际版
    ```

- 方式二、 导入本机已登录凭证（**Windows 本地执行**，需已安装并登录官方 Qoder 客户端）：

    ```bash
    python qoder-checkin.py import
    ```

签到（青龙面板定时任务调用 / 手动执行，无参数等同）：

```bash
python qoder-checkin.py checkin
或
python qoder-checkin.py
```

其他：

```bash
python qoder-checkin.py list           # 列出 auths/ 下已保存的账号
```

## 运行示例

领取成功（当日官方活动刷新后首次运行）：

```text
== Qoder 签到  共 1 个账号 ==

[xxxxxx@xxxx.com · 国内版]
  ✓ [每天领 100 Credits] +100 积分，30 天有效
  额度余额: 300（基础额度 0 / 赠送/签到额度 300，已用 0）
  套餐: Free

== 完成 ==
```

重复执行（当日已领取，幂等安全）：

```text
[xxxxxx@xxxx.com · 国内版]
  ✓ 今日活动均已领取（每天领 100 Credits、9月限时福利，专业版/高级版首月 Credits 翻倍）
  额度余额: 300（基础额度 0 / 赠送/签到额度 300，已用 0）
  套餐: Free
```

## 青龙面板部署

1. 添加订阅拉取仓库
   在青龙「订阅管理」中添加订阅（或手动上传 `qoder-checkin.py` 到脚本目录）：

   - 订阅链接地址：`https://wget.la/https://github.com/xz0609/qoder-checkin-ql.git`

   - 添加完成后，点击 `运行` 按钮，拉取仓库代码。

2. 凭证：将本地 `login` / `import` 生成的 `auths/<uid>.json` 上传到青龙容器脚本目录auths目录下（凭证只从该目录读取），多账号放多个 `<uid>.json` 文件在auths目录下即可。

3. 定时任务：订阅拉取后青龙会按脚本头 `cron: 22 10,19 * * *`（每日 10:22 / 19:22 两次）自动创建定时任务，也可在面板「定时任务」中自行调整触发时间。
   官方活动每日 10:00（UTC+8）刷新新一天福利，10:22 首跑即可领到当天 +100 Credits；19:22 为兜底重试。
   重复执行安全：已领取会自动归一化为「今日活动均已领取」，多时段运行无副作用；token 临期刷新与额度/套餐查询每次照常执行。

4. （可选）随机延时环境变量，避免多账号同时刻打卡：

   - `RANDOM_SIGNIN`：是否启用随机延时，默认 `true`

   - `MAX_RANDOM_DELAY`：随机延时上限秒数，默认 `3600`（最多 1 小时）

   在青龙「环境变量」里配置即可，每个账号签到前会独立随机延时并打印倒计时。

5. （可选）通知：脚本目录放置 `notify.py`（青龙面板自带）后自动发送签到结果。

## 签到内容

| 项目   | 说明                                                            | 区域   |
| ---- | ------------------------------------------------------------- | ---- |
| 每日签到 | 官方 campaigns 框架：每天领 100 Credits（每日 10:00 UTC+8 刷新，领取后 30 天有效） | 仅国内版 |
| 福利活动 | 所有 CLAIM\_BENEFIT 可领福利自动领取（含限时活动等）                            | 仅国内版 |
| 额度查询 | 基础额度 + 赠送/签到额度聚合、超额标记                                         | 双区   |
| 套餐查询 | 套餐名（plan\_tier\_name）实时刷新                                     | 双区   |

## 工作原理（签到链路）

2026-09 官方将每日签到迁移至 growth campaigns 框架，以下链路逆向自官方桌面客户端（campaignMainService）与活动页（growth-page/activity-iframe）：

1. `GET /sash/api/v1/me/campaigns`：列出当前账号全部活动（campaignKey 形如 `act-20260920-044`，每日 10:00 UTC+8 滚动刷新）
2. 筛选 `actionType=CLAIM_BENEFIT` 且 `claimStatus=CLAIMABLE` 的可领福利
3. `POST /sash/api/v1/me/campaigns/<campaignId>/claim`：领取（空 JSON 体），返回 `status=CLAIMED` 与 grantId，额度即时到账
4. 刷新 quota/usage 与 user/plan 快照并回写凭证文件

> 关键点：campaigns 端点按请求头识别客户端——必须携带 `User-Agent: Qoder` + `Cosy-ClientType: 10` + `Cosy-Version`（桌面宿主头），否则服务端返回空活动列表（`campaigns: []`）；旧的 daily-check-in / pro-upgrade 端点已 DISABLED / 404。

## 凭证管理

- 凭证保存为 `auths/<uid>.json`（`<uid>` 为 Qoder 用户 ID），与 Qoder2API-Hub 账号文件同构，可互换使用

- token 临期前 24 小时自动用 refreshToken 刷新并回写

- refreshToken 失效（TOKEN\_EXPIRE / 会话被吊销）时账号自动停用，重新执行 `login` 或 `import`

- 多账号：`auths/` 下多个 `<uid>.json`，每账号独立设备指纹 + 独立随机延时 + 账号间 ≥ 1.5s 间隔

## 排查

- 网络 / 接口变更排查：设置 `DEBUG_HTTP=1` 打印完整请求与响应

- `当前无进行中的活动`：服务端暂无进行中的活动，正常状态，无需处理

- `session dead (TOKEN_EXPIRE)`：离线会话被上游吊销，重新执行 `login`

- `import` 探测不到凭证：确认本机已安装并登录官方 Qoder 桌面客户端（国内版目录 `com.qodercn.app.stable`）或 CLI（`~/.qoder-cn/.auth/user`）；DPAPI 解密仅支持 Windows

- 凭证文件被跳过：确认 `auths/<uid>.json` 为合法 JSON（UTF-8，带 BOM 亦可），且包含 `accessToken` 字段

## 致谢

- [shuishuipingan/qoder2api-hub](https://github.com/shuishuipingan/qoder2api-hub) —— 主要参考来源，核心协议逆向（OAuth 设备流 / 双区配置 / 凭证解密 / 签到与福利接口）

## License

[MIT](LICENSE)
