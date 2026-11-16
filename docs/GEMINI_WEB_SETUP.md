# 在 Gemini 网页版中使用 Nexus 操控本地项目

本教程介绍如何把 Nexus 接入 **Gemini 网页版（gemini.google.com）的“关联应用 → 自定义 MCP 服务器”**，让 Gemini 在你授权的范围内读取、修改、构建本地项目。

> 适用版本：Nexus v1.3.1+（包含 Bridge OAuth 2.1 授权服务器）。
> 平台：Windows 10/11（macOS / Linux 步骤类似，路径不同）。

---

## 目录

1. [工作原理](#1-工作原理)
2. [准备工作](#2-准备工作)
3. [第一步：启动 Nexus](#3-第一步启动-nexus)
4. [第二步：授权本地项目目录](#4-第二步授权本地项目目录)
5. [第三步：找到 Bridge 令牌](#5-第三步找到-bridge-令牌)
6. [第四步：用 Cloudflare 隧道暴露 HTTPS 地址](#6-第四步用-cloudflare-隧道暴露-https-地址)
7. [第五步：在 Gemini 中添加自定义 MCP 服务器](#7-第五步在-gemini-中添加自定义-mcp-服务器)
8. [第六步：开始使用](#8-第六步开始使用)
9. [进阶：固定域名（推荐长期使用）](#9-进阶固定域名推荐长期使用)
10. [进阶：手动填写客户端 ID / 密钥](#10-进阶手动填写客户端-id--密钥)
11. [安全说明与撤销授权](#11-安全说明与撤销授权)
12. [故障排查](#12-故障排查)
13. [配置项速查](#13-配置项速查)

---

## 1. 工作原理

```text
Gemini 网页 (Google 云端)
        │  HTTPS + OAuth 2.1 (DCR + PKCE)
        ▼
Cloudflare 隧道  https://xxxx.trycloudflare.com
        │
        ▼
Nexus MCP Bridge  127.0.0.1:8787   ← OAuth 授权服务器 + MCP 入口
        │
        ▼
Nexus Core 127.0.0.1:18080  →  Runner  →  你授权的项目目录
```

- Gemini 只接受 **https://** 开头的 MCP 地址，且只支持 **OAuth** 鉴权（不能填 Bearer 头），所以需要：
  1. 一个公网 HTTPS 地址 → 用 Cloudflare 隧道把本机 `127.0.0.1:8787` 暴露出去；
  2. 一个 OAuth 授权服务器 → Nexus Bridge 内置（`/.well-known/oauth-*`、`/oauth/register|authorize|token`）。
- Gemini 首次连接时会自动完成 **动态客户端注册（DCR）**，然后弹出 Nexus 授权页。**你必须在授权页输入本机的 Bridge 令牌才能批准**——仅知道隧道地址的人无法获得访问权。
- 通过隧道进来的请求**只能访问** MCP、OAuth、健康检查端点；Bridge 的其它管理接口（`/api/*`、`/unity/*`、浏览器门户等）对隧道一律返回 404，只允许本机直连访问。

---

## 2. 准备工作

| 项目 | 说明 |
| :--- | :--- |
| Nexus | 桌面安装包，或源码运行（Node.js ≥ 24、pnpm 10） |
| cloudflared | Cloudflare 隧道客户端，见下文安装方式 |
| Google 账号 | Gemini 网页中能看到「设置 → 关联应用 → 自定义」按钮 |

安装 cloudflared（任选其一）：

```powershell
# 方式 A：winget（推荐）
winget install --id Cloudflare.cloudflared

# 方式 B：手动下载
# https://github.com/cloudflare/cloudflared/releases  下载 cloudflared-windows-amd64.exe，重命名为 cloudflared.exe 并加入 PATH
```

安装后验证：

```powershell
cloudflared --version
```

---

## 3. 第一步：启动 Nexus

### 方式 A：桌面版（推荐）

双击运行 Nexus 桌面程序。它会自动拉起 Core（18080）、Runner 和 MCP Bridge（8787）。托盘图标变绿即表示就绪。

### 方式 B：源码运行

```powershell
git clone https://github.com/ysunyang4/Nexus.git
cd Nexus
pnpm install
pnpm --filter "./packages/*" build

# 启动桌面控制中心（会自动拉起 Core / Runner / Bridge）
pnpm --filter @localbridge/desktop dev
```

### 方式 C：不用桌面端，分别启动各服务（无 GUI / 服务器环境）

在**同一个 PowerShell 7（`pwsh`）会话**里先准备令牌（三个服务共用）：

```powershell
$env:LOCALBRIDGE_MANAGEMENT_TOKEN = "lm_" + [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower()
$env:NEXUS_MANAGEMENT_TOKEN = $env:LOCALBRIDGE_MANAGEMENT_TOKEN
$env:LOCALBRIDGE_BOOTSTRAP_RUNNER_TOKEN = "lbr_" + [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).ToLower()
# 关键：让 Core 不占用 8787，把端口留给 MCP Bridge
$env:NEXUS_DISABLE_INTERNAL_GATEWAY = "true"
```

然后分别启动（可用 `Start-Process pwsh` 或多个终端，确保环境变量一致）：

```powershell
# 1) Core :18080
cd apps\server;  npx tsx src/index.ts
# 2) Runner（连接 Core）
cd apps\runner;  npx tsx src/index.ts --token $env:LOCALBRIDGE_BOOTSTRAP_RUNNER_TOKEN --name "My PC"
# 3) MCP Bridge :8787
cd apps\bridge;  npx tsx src/index.ts
```

> 也可以用 `.\OPEN-SOURCE-START.ps1 -Mode server` / `-Mode bridge`（需先 `pnpm --dir apps/server build`、`pnpm --dir apps/bridge build`），脚本会自动设置 `NEXUS_DISABLE_INTERNAL_GATEWAY`。
> ⚠️ 如果 Core 先启动且没有关闭内置网关，它会占用 8787，Bridge 将无法启动。

### 验证 Bridge 已启动

```powershell
curl http://127.0.0.1:8787/health
```

返回 `"ok": true` 且 `nexus.connected` 为 `true` 即正常。

---

## 4. 第二步：授权本地项目目录

1. 打开 Nexus 桌面控制中心 → **项目 (Projects)** 标签页。
2. 点击 **添加项目 (Authorize Project)**，选择要让 Gemini 操作的目录（例如 `D:\Projects\my-app`）。
3. 设置：
   - **访问模式**：`只读` 或 `读写`
   - **执行模式**：`禁用执行` / `仅安全工具` / `允许项目脚本`

> 💡 第一次使用建议先选 **只读 + 禁用执行**，确认一切正常后再放开。Gemini 只能访问你在这里授权的目录。

没有桌面端时，用 Runner 命令行授权（授权后需**重启 Runner** 才会同步到 Core）：

```powershell
cd apps\runner
npx tsx src/cli/project-cli.ts add "D:\Projects\my-app" --name my-app
npx tsx src/cli/project-cli.ts set-access <项目ID> read-write          # 默认 read-only
npx tsx src/cli/project-cli.ts set-execution <项目ID> disabled          # disabled | safe-only | project-code
npx tsx src/cli/project-cli.ts list
```

---

## 5. 第三步：找到 Bridge 令牌

Bridge 令牌是 OAuth 授权页上用来“证明你是本机主人”的口令。根据启动方式不同，位置也不同：

| 启动方式 | 令牌位置 |
| :--- | :--- |
| 桌面版 / 直接 `pnpm --dir apps/bridge start` | `%LOCALAPPDATA%\LocalBridge\data\bridge-token.key` |
| `OPEN-SOURCE-START.ps1 -Mode bridge` | `<仓库根目录>\apps\nexus-open-cloud\.local-bridge-token` |
| 设置了环境变量 `NEXUS_BRIDGE_TOKEN` | 就是该环境变量的值 |

查看令牌（桌面版）：

```powershell
Get-Content "$env:LOCALAPPDATA\LocalBridge\data\bridge-token.key"
```

> ⚠️ 这个令牌等同于 Bridge 的最高访问凭证，**不要发给任何人、不要粘贴到 Gemini 对话里**，只在下文的 Nexus 授权页里输入。

---

## 6. 第四步：用 Cloudflare 隧道暴露 HTTPS 地址

新开一个 PowerShell 窗口，运行：

```powershell
cloudflared tunnel --url http://127.0.0.1:8787
```

稍等几秒，输出中会出现类似：

```text
Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):
https://random-words-1234.trycloudflare.com
```

记下这个地址（下文记为 `https://<你的隧道地址>`）。**保持这个窗口不要关闭**，关闭即断开。

### 验证隧道

```powershell
# 应返回 JSON，其中 resource 为 https://<你的隧道地址>/mcp
curl https://<你的隧道地址>/.well-known/oauth-protected-resource

# 应返回 401（说明鉴权生效）
curl -i -X POST https://<你的隧道地址>/mcp
```

> Quick Tunnel 地址**每次重启 cloudflared 都会变**，变了之后需要在 Gemini 里删掉旧连接器重新添加。长期使用请看 [第 9 节 固定域名](#9-进阶固定域名推荐长期使用)。

---

## 7. 第五步：在 Gemini 中添加自定义 MCP 服务器

1. 打开 <https://gemini.google.com>，左下角 **设置 → 关联应用**。
2. 点击右上角 **＋ 自定义**，弹出「连接到 MCP 服务器」对话框。
3. **MCP 服务器网址** 填：

   ```text
   https://<你的隧道地址>/mcp
   ```

   注意结尾的 `/mcp` 不能少。
4. **其他设置**（客户端 ID / 客户端密钥）**留空**。Gemini 会通过动态客户端注册自动向 Nexus 申请凭据。
5. 点击 **下一步**。浏览器会打开一个 **“授权访问本地 Nexus”** 页面（由你本机的 Nexus 提供）：
   - 核对“授权完成后将跳转到”的域名是 `oauth-redirect.googleusercontent.com`（或其 sandbox/test 变体）；
   - 在 **Bridge 令牌** 输入框粘贴第三步拿到的令牌；
   - 点击 **批准**。
6. 页面跳回 Gemini，连接器显示为已安装即成功。

> 输错令牌会提示“Bridge 令牌不正确”；同一 IP 每分钟最多尝试 5 次。

---

## 8. 第六步：开始使用

在 Gemini 对话中可以直接用自然语言下指令，例如：

```text
用 Nexus 列出我授权的项目。
读取 my-app 项目的 package.json，告诉我有哪些脚本。
在 my-app 的 src/utils 下新建 date.ts，实现一个 formatDate 函数。
查看 my-app 的 git 状态，总结一下当前改动。
```

如果 Gemini 没有调用工具，可以在提示里明确说“使用 Nexus 工具”。

**关于工具列表**：为了节省 Token，Bridge 只向 Gemini 暴露 3 个元工具，由它按需检索并调用底层 300+ 工具：

| 元工具 | 作用 |
| :--- | :--- |
| `nexus_discover_tools` | 按关键词搜索底层工具（如 “project list”、“文件”） |
| `nexus_execute_action` | 执行单个底层工具，例如 `localbridge_project_list`、`localbridge_file_read`、`localbridge_file_create` |
| `nexus_run_script` | 多步操作批量执行 |

因此在 Gemini 的连接器详情里只看到 3 个工具是正常的。注意修改已有文件的 `localbridge_file_write` 需要先读取得到 `expectedHash`（防止覆盖并发修改），新建文件用 `localbridge_file_create`。

- 访问令牌有效期 1 小时，Gemini 会用刷新令牌自动续期（刷新令牌 30 天，轮换使用）。
- 所有工具调用仍受 Nexus 本地权限策略约束：只读项目无法写入，高危命令会在桌面端弹出审批窗口，需要你本人点击确认。

---

## 9. 进阶：固定域名（推荐长期使用）

Quick Tunnel 地址不固定，适合临时试用。如果你在 Cloudflare 上有自己的域名，可以创建命名隧道：

```powershell
cloudflared tunnel login
cloudflared tunnel create nexus
cloudflared tunnel route dns nexus nexus.example.com
```

创建 `%USERPROFILE%\.cloudflared\config.yml`：

```yaml
tunnel: nexus
credentials-file: C:\Users\<你的用户名>\.cloudflared\<隧道ID>.json
ingress:
  - hostname: nexus.example.com
    service: http://127.0.0.1:8787
  - service: http_status:404
```

运行：

```powershell
cloudflared tunnel run nexus
```

（可选）让 Bridge 明确知道自己的公网地址，在启动 Bridge 前设置：

```powershell
$env:PUBLIC_BASE_URL = "https://nexus.example.com"
```

> 不设置也可以：Bridge 会根据隧道转发的 `Host` 头自动推断公网地址。设置后可避免反向代理改写 Host 带来的问题。

Gemini 中的 MCP 地址填 `https://nexus.example.com/mcp`，之后重启电脑也无需重新添加。

---

## 10. 进阶：手动填写客户端 ID / 密钥

一般不需要。如果你的网络环境导致动态注册失败，可以预置一个静态客户端：

```powershell
$env:NEXUS_OAUTH_CLIENT_ID = "gemini-nexus"
$env:NEXUS_OAUTH_CLIENT_SECRET = "<自己生成的长随机字符串>"
# 然后启动 Bridge
```

生成随机密钥：

```powershell
[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

然后在 Gemini「其他设置」中填写相同的客户端 ID 和密钥。静态客户端接受任意 https 回调地址，但批准时依然需要输入 Bridge 令牌。

---

## 11. 安全说明与撤销授权

**暴露范围**：通过隧道只能访问以下路径，其余全部 404：

| 路径 | 用途 |
| :--- | :--- |
| `/mcp`、`/mcp/*`、`/api/mcp`、`/` | MCP 入口（需 Bearer：OAuth 访问令牌或 Bridge 令牌） |
| `/.well-known/oauth-protected-resource*` | RFC 9728 资源元数据 |
| `/.well-known/oauth-authorization-server*`、`/.well-known/openid-configuration*` | RFC 8414 授权服务器元数据 |
| `/oauth/register`、`/oauth/authorize`、`/oauth/token` | OAuth 端点 |
| `/health` | 健康检查 |

如需临时恢复旧行为（不推荐），可设置 `NEXUS_BRIDGE_ALLOW_REMOTE_ADMIN=1`。

**Gemini 能做什么**：批准后，Gemini 可以调用 Bridge 暴露的全部 MCP 工具，与使用 Bridge 令牌的客户端权限相同；实际能力受 Nexus 项目授权（只读/读写、执行模式）和本地审批弹窗约束。请只授权你愿意让 AI 操作的目录。

**数据经过谁**：Cloudflare 隧道是 TLS 加密，但并非端到端加密——Cloudflare 和 Google 都能看到 Gemini 读取的文件内容。不要授权含敏感数据的目录（Nexus 也会硬性拦截 `.env*`、`*.pem`、`*.key` 等凭证文件）。

**撤销授权**：

1. 在 Gemini「关联应用」中移除该连接器；
2. 停止 Bridge（关闭桌面程序或 Ctrl+C）；
3. 删除 OAuth 存储文件：

   ```powershell
   Remove-Item "$env:LOCALAPPDATA\LocalBridge\data\oauth-store.json"
   ```

4. 重新启动 Bridge。所有已签发的访问/刷新令牌立即失效。

如怀疑 Bridge 令牌泄露：停止 Bridge，删除 `bridge-token.key`（或 `.local-bridge-token`）后重启，会自动生成新令牌；然后执行上面的撤销步骤。

**随时断开**：直接关闭 cloudflared 窗口，Gemini 就无法再访问你的电脑。

---

## 12. 故障排查

先看 Bridge 日志：桌面版位于 `%LOCALAPPDATA%\LocalBridge\logs\nexus-mcp-bridge.log`，失败请求另记录在 `%LOCALAPPDATA%\LocalBridge\data\bridge-http.log`。

| 现象 | 原因 / 解决 |
| :--- | :--- |
| Gemini 提示“请确保网址以 https:// 开头” | 必须填隧道给出的 `https://...trycloudflare.com/mcp`，不能填 `127.0.0.1` |
| Gemini 提示无法连接 / 超时 | cloudflared 窗口是否还开着？`curl https://<隧道>/health` 能否访问？Quick Tunnel 刚创建时可能需等待 10~30 秒 |
| Gemini 报 redirect URL 相关错误 | 通常是动态注册失败。查看 `bridge-http.log` 中 `/oauth/register` 的返回；或改用 [第 10 节](#10-进阶手动填写客户端-id--密钥) 的静态客户端 |
| 授权页显示“Unknown client_id” | Bridge 重启时 OAuth 存储被删，或换了数据目录。在 Gemini 中删除连接器重新添加 |
| 授权页提示“Bridge 令牌不正确” | 确认令牌来源与启动方式匹配（见第 5 节），注意不要复制多余空格 |
| 授权页提示“尝试次数过多” | 每 IP 每分钟 5 次，等 1 分钟再试 |
| 元数据里的地址是 `http://127.0.0.1:8787` | 隧道改写了 Host 头。设置 `PUBLIC_BASE_URL=https://<你的隧道地址>` 后重启 Bridge |
| 连接成功但 Gemini 说没有项目 | 在 Nexus 桌面端“项目”页授权目录；检查 `/health` 中 `nexus.connected` 是否为 `true` |
| 换了 Quick Tunnel 地址后失效 | Quick Tunnel 每次地址都变，需要在 Gemini 中重新添加；或改用固定域名 |
| 写文件 / 执行命令被拒绝 | 项目是只读或禁用执行，或桌面端审批弹窗未确认 |

自测完整 OAuth 流程（本机）：

```powershell
npx vitest run apps/bridge/src/oauth.test.ts
```

---

## 13. 配置项速查

| 环境变量 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PUBLIC_BASE_URL` | 自动推断 | Bridge 的公网 https 地址，用于 OAuth issuer 和元数据 |
| `NEXUS_BRIDGE_TOKEN` | 自动生成并保存到 `bridge-token.key` | Bridge 令牌，同时是 OAuth 授权页的批准口令 |
| `NEXUS_OAUTH_STORE_PATH` | `%LOCALAPPDATA%\LocalBridge\data\oauth-store.json` | OAuth 客户端与令牌存储（令牌只存 SHA-256 哈希） |
| `NEXUS_OAUTH_CLIENT_ID` / `NEXUS_OAUTH_CLIENT_SECRET` | 未设置 | 可选的静态 OAuth 客户端 |
| `NEXUS_BRIDGE_ALLOW_REMOTE_ADMIN` | 未设置 | 设为 `1` 时隧道可访问管理接口（不推荐） |

OAuth 实现细节：

- 授权码：一次性，5 分钟有效，强制 PKCE S256
- 访问令牌：1 小时；刷新令牌：30 天，每次刷新轮换
- 客户端认证：`client_secret_basic`、`client_secret_post`、`none`（公共客户端）
- 动态注册：最多 10 个 redirect URI，仅允许 https 或本机回环地址；最多保留 200 个动态客户端
- 源码：`apps/bridge/src/oauth.ts`
