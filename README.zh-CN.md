# Gemini Subagent for Codex

[English](README.md) · [给 Agent 的安装指南](INSTALL.md) · [安全与权限](SECURITY.md) · [源码审查报告](docs/SECURITY_REVIEW.md) · [配置说明](plugins/gemini-subagent/README.md) · [MIT 许可证](LICENSE)

让 Codex 像调用 subagent 一样，把任务交给 **Antigravity CLI（`agy`）** 或可选的 **Gemini CLI**。
Codex 负责启动、等待、获取结果、续接会话、取消任务和验证改动。

**macOS 稳定版为 `v0.3.0`；Windows 预发布版为 `v0.4.0-alpha.1`。**
Windows 正式目标保持为 Windows 11 24H2+ x64、PowerShell、原生 Python 3.10+ x64。

23H2 普通用户测试已经取得原生离线通过、Codex 控制 agy 读取和同会话续接的证据。
**Windows 尚未通过发布验收：普通项目写入失败、真实超时未触发、官方首次登录未独立验证。**
Codex 集成保留了正常的精确命令审批，不代表全部操作均在沙箱内免审批运行。

Windows 多账号切换和共享读保持禁用。插件使用你自己安装的官方 CLI 和账号，
不附带 Google 程序、凭据或 API 代理。详见包内的
[平台说明](plugins/gemini-subagent/references/platforms.md)和[版本绑定验证记录](docs/VALIDATION.md)。

## 让你的 Agent 安装和配置

把下面这句话交给 Codex：

> 帮我安装并配置 https://github.com/Liii8888/codex-gemini-subagent ，用于当前项目。
> macOS 选稳定版 v0.3.0，Windows 选实验性 v0.4.0-alpha.1。
> 先读所选版本的 INSTALL.md 并检查权限，再安装插件，按 setup Skill 完成配置。
> 最后告诉我哪个 provider 已经可用，以及以后怎么让你调用 Gemini。

[INSTALL.md](INSTALL.md) 是专门给安装 Agent 的入口，包含环境检查、安装、定位运行器、
工作目录授权、账号检查和后续调用。安装包内有完整的 5 个 Skill 和运行脚本，
新开的 Codex 任务可以自动发现它们，无需记住仓库里的命令。

## 已有功能

- 后台任务、持久化 job ID、进度查询、结果保存、超时与取消。
- Gemini session 和 Antigravity conversation 原生续接，绑定原账号和项目。
- 通过官方 `agy /usage` 查询额度及重置时间。
- 可选的操作系统凭据存储、多账号管理、冷却和受限的失败换号；macOS 使用 Keychain，
  Windows Credential Manager 的真实账号接入仍受原生证据门槛限制。
- 默认串行；同账号 Antigravity 只读双并发需要真实探针通过并由用户显式开启。
- 纯 Python 标准库运行器，无常驻 daemon、无前端。

## 安装

需要 macOS 或上述实验性 Windows 环境、Python 3.10+、Git、支持插件命令的 Codex CLI，
以及官方 provider CLI。新配置优先选择 `agy`；保留用户指定或已有可用的 `gemini`。
首次登录由你在官方交互流程里完成。
会员订阅不等于每个 CLI、模型或额度接口都必然可用。

阅读源码后选择一个渠道。macOS 稳定版：

```bash
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.3.0
codex plugin add gemini-subagent@gemini-subagent-public
```

Windows 预发布版（或明确选择体验新版的 macOS 用户）：

```bash
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.4.0-alpha.1
codex plugin add gemini-subagent@gemini-subagent-public
```

安装后新建一个 Codex 任务或 CLI 会话，再使用：

```text
用 $gemini-subagent:setup 检查这个项目的 Gemini 配置。
用 $gemini-subagent:rescue 让 Gemini 只读审查这个项目，并返回问题清单。
用 $gemini-subagent:status 查看任务、账号和额度。
用 $gemini-subagent:result 读取上次任务结果。
用 $gemini-subagent:cancel 取消指定任务。
```

公开版仍使用 `gemini-subagent` 名称；如果已有旧个人版，选择一个来源使用。
安装发现和新会话加载机制见 [OpenAI 官方插件说明](https://learn.chatgpt.com/docs/plugins)。
版本固定命令要求对应预发布标签已经存在；开发中的 checkout 不代表标签已经发布。
Windows 前置检查参考 [Codex 官方 Windows 文档](https://learn.chatgpt.com/docs/windows/windows-app)
和 [Antigravity 官方安装文档](https://antigravity.google/docs/cli/install)。
不要自动改执行策略、申请管理员或 Full Access，也不要默认通过 WSL 运行。

## 直接运行

```bash
git clone --branch v0.3.0 https://github.com/Liii8888/codex-gemini-subagent.git
cd codex-gemini-subagent
SUBAGENT="$PWD/plugins/gemini-subagent/scripts/gemini_subagent.py"

cd /你的项目绝对路径
python3 "$SUBAGENT" doctor --json
python3 "$SUBAGENT" account list
python3 "$SUBAGENT" start --provider agy --mode read --cwd "$PWD" \
  --prompt '检查项目结构，返回主要问题。' --wait
```

`--mode write` 用于需要改文件的任务；本次 Windows 实测的普通项目写入尚未通过。续接任务使用
`start --resume <job-id> --prompt-file <文件> --wait`。

Windows 使用实际安装结果中的 `installedPath`，并显式调用已经核验的原生 Python
3.10+ x64；不要依赖 `.py` 文件关联或 shebang。以下 `$InstalledPath` 和 `$Python`
须先从实际安装结果和本机 Python 解析得到，不能猜插件缓存路径：

```powershell
$Subagent = Join-Path $InstalledPath 'scripts\gemini_subagent.py'
Set-Location -LiteralPath 'C:\Projects\your-project'
& $Python $Subagent doctor --json
```

`doctor` 会初始化私有状态；Windows 的 `capabilities` 包含 `task_lifecycle`、
`credential_storage`、`credential_profiles`、`shared_reads`、`desktop_integration`。
生命周期虽显示 available，但标记为 `pending-native-acceptance`；凭据存储只有合成测试，
真实 profile 和共享读不可用，桌面集成待验收。23H2 的原生进程、锁与 ACL 证据不等于 24H2+ 发布验收。
新 macOS 用户的运行数据默认放在 `~/Library/Application Support/Gemini-Subagent/runtime`，
Windows 则使用真实操作系统用户的 `%LOCALAPPDATA%\Gemini-Subagent\runtime`。
首次初始化只授权当前项目；同系统的兼容升级保留既有状态，不跨系统迁移凭据或原生会话。
更多路径、Antigravity 多账号和并发配置见 [配置说明](plugins/gemini-subagent/README.md)。

## 适用范围

- Windows 为实验性支持；23H2 兼容性证据与待完成的 24H2+ 单账号发布验收分别记录。Linux 不属于发布目标。
- `read` 使用 provider 的 plan/approval 与 sandbox，属于只读意图，不能当作强制逐工具禁写。
- 操作系统凭据切换和同账号并发属于非官方兼容能力，provider 更新后可能失效。
- 任务及 provider 读取的相关项目内容会通过你的账号发送给 Google。
- prompt、事件流、结果和账号元数据保存在本地私有运行目录；凭据快照只留在对应系统的凭据存储中。
- 不要向 Codex 或 GitHub issue 提交密码、token、Cookie、2FA 或恢复码。

## 验证

```bash
python3 tools/check_package.py
python3 -W error::ResourceWarning -m unittest discover \
  -s plugins/gemini-subagent/tests -v
```

测试使用模拟 provider 与临时目录，不需要登录 Google，也不会发起付费模型调用。
测试通过不代表某个账号当前有额度，也不代表其他机器自动获得并发能力。
详见 [发布验证](docs/VALIDATION.md)。项目采用 MIT 许可证。
CI 在 main、预发布分支、PR 和版本标签上运行 macOS／Windows × Python 3.10／3.14。
执行结果以对应提交的 CI 和发行验证附件为准；Windows Server CI 不替代 Windows 11 桌面验收。
Darwin 专属跳过与实际执行的原生测试分别报告。
渠道、打包、升级退回和公开核验流程见[维护与发布说明](docs/RELEASING.md)。

没有 Codex 或 Google 登录的 Windows 机器也可以运行：

```powershell
.\tools\validate_windows.ps1 -Python 'C:\Path\To\python.exe'
```

脚本只检查本地前置条件、包和 mock 测试，输出精简脱敏 JSON；不会运行真实 `doctor`、
枚举或保存凭据、安装软件或访问网络。`-Live -ProjectPath 'C:\Projects\your-project'`
只增加真人验收步骤，`-SharedProbe` 单独增加共享并发检查清单，两者均不执行真实探针或启用并发。
