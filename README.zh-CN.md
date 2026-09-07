# Gemini Subagent for Codex

[English](README.md) · [Agent 安装指南](INSTALL.md) · [配置说明](plugins/gemini-subagent/README.md) · [安全与权限](SECURITY.md)

让 Codex 把任务交给 **Antigravity CLI（`agy`）** 或可选的 **Gemini CLI**。
Codex 负责启动后台任务、查询进度、获取结果、续接会话、取消任务和验证改动。

**0.4.1 支持 macOS 和原生 Windows 11 23H2+ x64。** 一个通用插件包含五个
Skill 和 Python 运行代码，不捆绑 provider 程序、依赖、账号或开发测试。

## 安装

需要 Python 3.10+、支持插件命令的 Codex CLI，以及已经安装的官方 provider CLI。
Windows 使用原生 x64 Python 和 PowerShell。需要登录时，通过官方 CLI／浏览器完成。

把下面这句话交给 Codex：

> 帮我安装并配置 https://github.com/Liii8888/codex-gemini-subagent 的 v0.4.1，
> 用于当前项目。按 INSTALL.md 和 setup Skill 操作，最后告诉我哪个 provider 已经可用。

也可以在安装了 Git 的环境中执行：

```sh
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.4.1 --sparse .agents/plugins --sparse plugins/gemini-subagent
codex plugin add gemini-subagent@gemini-subagent-public
```

还可以从[发行页面](https://github.com/Liii8888/codex-gemini-subagent/releases/tag/v0.4.1)
下载安装 ZIP，核对 `SHA256SUMS` 后解压到准备保留的目录，将该目录的绝对路径传给
`codex plugin marketplace add`，再执行相同的 `plugin add` 命令。
更新和定位运行器的步骤见 [INSTALL.md](INSTALL.md)。

安装后新建 Codex 任务或 CLI 会话，直接说：

> 让 Gemini 检查这个项目，把主要问题告诉我。

| Skill | 用途 |
| --- | --- |
| `gemini-subagent:setup` | 配置 provider，检查是否可用 |
| `gemini-subagent:rescue` | 委派任务或续接上次工作 |
| `gemini-subagent:status` | 查询任务、账号、额度和会话 |
| `gemini-subagent:result` | 读取已保存的结果 |
| `gemini-subagent:cancel` | 取消指定任务 |

## 账号和权限

插件**只管理 agy 账号**：macOS 使用 Keychain，Windows 使用凭据管理器。
已有可用登录时，Agent 可调用 `account import-current` 保存，不需要重新登录。
命名账号属于可选的非官方兼容功能；Windows 适配限定于已核验的 agy 1.1.27 x64
和普通桌面用户。

默认串行执行。macOS 并行读取需要匹配的真实探针和明确启用；Windows 共享读关闭。
`read` 使用 provider 自身的 plan／sandbox 控制，不等于逐工具强制禁写。
正常的宿主审批仍然适用，详见[安全与权限](SECURITY.md)。

任务上下文通过你的账号发送给 provider；任务数据留在本地私有运行目录，保存的 agy
凭据留在操作系统凭据库。卸载插件不会删除既有登录或运行数据。

## 兼容范围

原生测试覆盖 Windows 11 23H2 x64，包括 agy 官方登录、读取、续接、项目文件写入、
取消、超时及进程收尾。[验证说明](docs/VALIDATION.md)区分各项证据对应的源码版本。
24H2+、桌面 App 集成、两个不同真实 agy 账号及真实 token 轮换尚未验证。
可选 Gemini CLI 的 Windows 真实使用另行验收；Linux 不属于发布目标。

## 开发

测试和 CI 保留在源码仓库，不随插件安装。

```sh
python3 tools/check_package.py
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

测试使用模拟 provider 和临时状态，无需 Google 登录，也不发起付费调用。
详见[开发约定](docs/DEVELOPMENT.md)和[发行维护](docs/RELEASING.md)。
项目采用 [MIT 许可证](LICENSE)。
