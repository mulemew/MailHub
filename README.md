# MailHub

基于 Cloudflare Workers 的全功能邮件收发管理系统。

## 架构

- **Cloudflare Workers** - 无服务器运行时
- **D1 Database** - SQLite 数据库，存储邮箱、邮件、设置等
- **R2 Storage** - 对象存储，存储附件和原始 EML 文件
- **Workers Assets** - 静态前端文件托管
- **CF Email Service** - Cloudflare 原生邮件发送（推荐）
- **Resend API** - 第三方邮件发送（备选方案）
- **Cloudflare Email Routing** - 原生邮件接收（catch-all → Worker）

## 功能

- 密码登录认证（支持 Turnstile 人机验证）
- 邮箱管理（创建、删除、置顶、收藏）
- 邮件收发（CF Email Service 或 Resend 发送，CF Email Routing 接收）
- 附件支持（存储在 R2，支持下载）
- 原始 EML 文件存储和下载
- 验证码自动提取（多语言支持）
- Telegram 通知（新邮件通知到 Bot）
- 邮件转发（单邮箱转发 + 全局转发）
- 域名管理（一键启用，自动 DNS + Email Routing 配置）
- 深色/浅色主题切换
- 中英文双语
- 搜索、分页、自动刷新
- 已发送邮件记录

## 一键部署

### 方式一：Cloudflare 直接部署（推荐）

点击下方按钮，一键部署到 Cloudflare Workers：

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/mulemew/MailHub)

部署完成后：

1. 访问 Worker 地址，用默认密码 `changeme123` 登录（**请立即修改**）
2. 进入「设置」页面，填写 Cloudflare API Token（见下方权限说明）
3. 选择域名服务商（CF Email Service 推荐，或 Resend）
4. 进入「域名管理」，选择域名添加，系统自动配置 DNS 和 Email Routing
5. 等待 DNS 生效（通常几分钟），即可收发邮件

> 部署后建议通过 Cloudflare Dashboard 设置以下 Worker 环境变量（Secrets）：
> - `ADMIN_PASSWORD` - 登录密码
> - `JWT_SECRET` - JWT 签名密钥（任意随机字符串）

### 方式二：GitHub Actions 部署

Fork 本项目，在 GitHub 仓库中配置 Secrets，推送代码即自动部署。

#### 1. 创建 Cloudflare API Token（部署用）

前往 [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens) → Create Token → Custom Token：

| 权限 | 类型 | 说明 |
|------|------|------|
| Workers Scripts | Edit (Account) | 部署 Worker |
| D1 | Edit (Account) | 创建和管理数据库 |
| R2 Storage | Edit (Account) | 创建和管理存储桶 |

#### 2. 配置 GitHub Secrets

在仓库 Settings → Secrets and variables → Actions 中添加：

| Secret | 必填 | 说明 |
|--------|------|------|
| `CF_API_TOKEN` | 是 | 上一步创建的 Cloudflare API Token |
| `CF_ACCOUNT_ID` | 是 | Cloudflare Account ID（Dashboard 首页右侧可见） |
| `ADMIN_PASSWORD` | 推荐 | 管理后台登录密码（不设则默认 `changeme123`） |
| `JWT_SECRET` | 推荐 | JWT 签名密钥（任意随机字符串） |
| `RESEND_API_KEY` | 可选 | Resend API Key（也可以部署后在网页设置中填写） |

#### 3. 触发部署

推送代码到 `main` 分支，或在 Actions 页面手动触发 `workflow_dispatch`。

GitHub Actions 会自动完成：
- 创建 D1 数据库和 R2 存储桶（如不存在）
- 执行数据库建表（`IF NOT EXISTS`，不影响已有数据）
- 注入 Secrets 到环境变量
- 部署 Worker 到 Cloudflare

## API Token 权限说明

MailHub 使用两类 Token，用途不同：

### 部署 Token（GitHub Actions 用）

仅用于 `wrangler deploy` 部署代码，在 GitHub Secrets 中配置：

| 权限 | 类型 | 说明 |
|------|------|------|
| Workers Scripts | Edit (Account) | 部署 Worker |
| D1 | Edit (Account) | 创建和管理数据库 |
| R2 Storage | Edit (Account) | 创建和管理存储桶 |

### 运行时 Token（MailHub 设置页填写）

用于域名管理、DNS 配置、Email Routing 等运行时功能。在 MailHub 登录后的「设置」页面填写：

| 权限 | 类型 | 用途 |
|------|------|------|
| **Zone** | Read (All zones) | 列出账户下的域名 |
| **DNS** | Edit (All zones) | 自动创建/管理 DNS 记录 |
| **Email Routing Rules** | Edit (All zones) | 配置 catch-all 规则指向 Worker |
| **Email Routing Addresses** | Edit (All zones) | 管理邮件路由地址 |
| **Email Sending** | Edit (All zones) | CF Email Service 发送子域名管理 |

> **注意**：这两个 Token 可以是同一个（包含所有权限），也可以分开创建。运行时 Token 也可以通过 GitHub Secrets 的 `CF_API_TOKEN` 自动注入。

### Resend API Key（仅 Resend 用户需要）

如果选择 Resend 作为域名服务商：

1. 前往 [Resend Dashboard](https://resend.com/api-keys) 创建 API Key
2. 权限需要：**Sending access** + **Domain management**
3. 在 MailHub 设置页填写，或通过 GitHub Secrets 的 `RESEND_API_KEY` 注入

## 两种发信模式对比

| | CF Email Service | Resend |
|---|---|---|
| **费用** | 免费（Cloudflare 内置） | 免费额度 100 封/天 |
| **配置** | 只需 CF API Token | 需额外注册 Resend + API Key |
| **DNS** | CF 自动管理 | 需通过 API 自动创建到 CF |
| **推荐** | 推荐 | 备选方案 |

两种模式都通过 **Cloudflare Email Routing** 接收邮件（catch-all 规则转发到 Worker）。

## Turnstile 人机验证（可选）

在 Cloudflare Dashboard → Turnstile 中创建站点，然后在 Worker 环境变量（Secrets）中设置：

| 变量 | 说明 |
|------|------|
| `TURNSTILE_SITE_KEY` | Turnstile 站点密钥（公开） |
| `TURNSTILE_SECRET_KEY` | Turnstile 密钥（私密） |

> 两个变量都设置后登录页才会启用验证。只设其中一个不会生效。

## 首次使用流程

1. 部署完成后，访问 Worker 地址，用密码登录
2. 进入「设置」→ 选择域名服务商 → 填写 CF API Token（及 Resend Key，如需）
3. 进入「域名管理」→ 从下拉框选择域名 → 点击添加
4. 系统自动完成：添加发送域名 → 创建 DNS 记录 → 配置 Email Routing → 验证
5. 等待 DNS 生效（通常几分钟），域名状态变为 `verified` 即可收发邮件

## 重复部署说明

重复部署不会冲突，不会丢失数据：
- D1/R2 资源创建使用"已存在则跳过"逻辑
- 数据库建表使用 `CREATE TABLE IF NOT EXISTS`
- DNS 和 Email Routing 配置在域名启用时按需创建
- `wrangler deploy` 是覆盖式部署，只更新代码，不影响数据

## 项目结构

```
├── src/worker.js          # Worker 后端（HTTP + Email 处理）
├── public/index.html       # 前端 SPA
├── d1-init.sql             # 数据库初始化 SQL
├── wrangler.toml           # Cloudflare Workers 配置
├── package.json            # 依赖管理
└── .github/workflows/      # GitHub Actions 自动部署
    └── deploy.yml
```

## 技术栈

- Cloudflare Workers + D1 + R2 + Email Routing + Email Sending
- Resend API（备选邮件发送 + 域名管理）
- postal-mime（邮件解析）
- 纯原生 HTML/CSS/JS SPA（无框架依赖）

## 致谢

本项目在开发过程中参考了以下优秀的开源项目，在此表示感谢：

- [cloud-mail](https://github.com/maillab/cloud-mail) — 基于 Cloudflare 的邮件系统实现
- [cf-mail](https://github.com/lyon-le/cf-mail) — Cloudflare Workers 邮件服务方案
