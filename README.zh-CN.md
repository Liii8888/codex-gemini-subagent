# Gemini Subagent for Codex

[English](README.md) · [给 Agent 的安装指南](INSTALL.md) · [安全与权限](SECURITY.md) · [配置说明](plugins/gemini-subagent/README.md) · [MIT 许可证](LICENSE)

让 Codex 像调用 subagent 一样，把任务交给 **Gemini CLI** 或 **Antigravity CLI**。
Codex 负责启动、等待、获取结果、续接会话、取消任务和验证改动。

这是用于 **macOS 本地 Codex** 的社区插件。使用你自己安装的官方 CLI 和账号，
不附带 Google 程序、凭据、代登录服务或 API 代理。

## 让你的 Agent 安装和配置

把下面这句话交给 Codex：

> 帮我安装并配置 https://github.com/Liii8888/codex-gemini-subagent ，用于当前项目。
> 先读 INSTALL.md 并检查权限，再安装插件，按 setup Skill 完成配置。
> 最后告诉我哪个 provider 已经可用，以及以后怎么让你调用 Gemini。

[INSTALL.md](INSTALL.md) 是专门给安装 Agent 的入口，包含环境检查、安装、定位运行器、
工作目录授权、账号检查和后续调用。安装包内有完整的 5 个 Skill 和运行脚本，
新开的 Codex 任务可以自动发现它们，无需记住仓库里的命令。

## 已有功能

- 后台任务、持久化 job ID、进度查询、结果保存、超时与取消。
- Gemini session 和 Antigravity conversation 原生续接，绑定原账号和项目。
- 通过官方 `agy /usage` 查询额度及重置时间。
- 可选的 macOS Keychain 多账号管理、冷却和受限的失败换号。
- 默认串行；同账号 Antigravity 只读双并发需要真实探针通过并由用户显式开启。
- 纯 Python 标准库运行器，无常驻 daemon、无前端。

## 安装

需要 macOS、Python 3.10+、Git、支持 `codex plugin add` 的 Codex CLI，以及
至少一个已经安装的 `gemini` 或 `agy`。首次登录由你在官方交互流程里完成。
会员订阅不等于每个 CLI、模型或额度接口都必然可用。

阅读源码后执行：

```bash
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.3.0
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

## 直接运行

```bash
git clone https://github.com/Liii8888/codex-gemini-subagent.git
cd codex-gemini-subagent
SUBAGENT="$PWD/plugins/gemini-subagent/scripts/gemini_subagent.py"

cd /你的项目绝对路径
"$SUBAGENT" doctor --json
"$SUBAGENT" account list
"$SUBAGENT" start --provider gemini --mode read --cwd "$PWD" \
  --prompt '检查项目结构，返回主要问题。' --wait
```

`--mode write` 用于需要改文件的任务。续接任务使用
`start --resume <job-id> --prompt-file <文件> --wait`。

新用户的运行数据默认放在 `~/Library/Application Support/Gemini-Subagent/runtime`，
首次初始化只授权当前项目目录。已有旧运行目录会被沿用，避免拆分账号状态和认证锁。
更多路径、Antigravity 多账号和并发配置见 [配置说明](plugins/gemini-subagent/README.md)。

## 适用范围

- 当前发布目标是 macOS；Linux、Windows 未经过发布验收。
- `read` 使用 provider 的 plan/approval 与 sandbox，属于只读意图，不能当作强制逐工具禁写。
- 多账号 Keychain 切换和同账号并发属于非官方兼容能力，provider 更新后可能失效。
- 任务及 provider 读取的相关项目内容会通过你的账号发送给 Google。
- prompt、事件流、结果和账号元数据保存在本地私有运行目录；凭据快照只留在 Keychain。
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
