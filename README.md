# 工作区外访问守卫（outside-access-guard）

[English](README_EN.md) | 中文

给 DeepSeek Harness 补上「读取工作区之外要经过我」这一层，并把
[dsh-outsideread-switch](https://www.npmjs.com/package/dsh-outsideread-switch)
式的二值开关扩成三档模式。

## 背景

DSH 的文件沙箱在 `workspace-write` 模式下**只限制写入，不限制读取**：

- 读 `C:\Windows\win.ini`、列 `C:\`、读任意盘符文件，全部直接放行；
- 写工作区之外会被沙箱拒绝；`read-only` 模式同样允许读。

所以「模型能悄悄读走整台机器的文件」是默认行为。本插件挂在工具执行前的
`tools/pre-execute` 瀑布上，按模式决定放行、审批或拒绝。

## 设计权衡：子代理没有审批通道

> 这不是 bug，是设计上的取舍。

子代理（`subagent`、`workflow` 里的 `agent()`）是独立会话，没有绑定审批答复者，所以它发起的工作区外访问一律 **fail closed**：不弹窗、不挂起，立即被拒绝。

模型收到的文案是 `the user rejected tool "…"`，看起来像人拒绝，实际是“没有可用的审批通道”；这类调用在日志里只有 `ask`、没有 `approval` 结果行。

为什么这么设计：审批的前提是“有人看见”。自动拒绝的子代理至少不会在你无感知的情况下读取工作区外的内容；如果给它一条无确认的放行通道，护栏就形同虚设。

**影响**：子代理只能在工作区内活动；需要越界的操作请让父会话执行。

## 三种模式

| `mode` | 工作区内 | 工作区外 | 说明 |
| --- | --- | --- | --- |
| `deny` | 放行 | **直接拒绝** | 对应总开关"全禁止" |
| `ask`（默认） | 放行 | **每次审批** | 敏感路径需要**两次确认** |
| `allow` | 放行 | 放行 | 对应总开关"完全允许" |

模式有两个入口：

1. **持久默认值**：profile patch 里的 `mode`，重启后生效；
2. **运行时开关**：人类命令 `/outside-access deny|ask|allow|status`。
   斜杠命令只能由人发出，模型无法调用，因此不能用它给自己扩权。
   该开关**只存在于内存中**，重启回到配置默认值。

```yaml
- id: outside-access-guard
  config:
    mode: ask
```

## 子代理的独立模式：`subagentMode`

子代理（`subagent`、`workflow` 里的 `agent()`）没有审批通道，主模式的 `ask` 对它们只会 fail-closed。可以给它们单独一档：

| `subagentMode` | 行为 |
| --- | --- |
| 留空（默认） | 继承主模式；`/outside-access` 切换时两边一起变 |
| `deny` | 子代理一律不许越界，意图最明确 |
| `ask` | 与主模式相同（实际仍会 fail-closed） |
| `allow` | 子代理可自由访问工作区外（不推荐） |

判定用 `agents.roots()`（顶层 agent 列表）：不在列表里的视为子代理。服务不可用时按主会话处理。日志里的 `mode` 字段记录的是**实际生效**的模式，并附带 `scope`。

## 敏感路径：更高一级的报警 + 二次确认

普通工作区外访问只弹一次审批（第 1/1 次）。命中敏感规则的路径会升级：

1. **第 1/2 次确认**：只负责"开启最终确认"，本身不执行任何操作；
2. **停顿**：两次之间强制等待 `confirmGapMs`（默认 2000 毫秒）；
3. **第 2/2 次确认**：这次调用的常规审批——**高危警告文案在这一层**；
4. 两次都批准才执行；任一步拒绝或取消都不会执行。

默认敏感规则（可用 `sensitivePaths` 覆盖，传空数组即关闭）：

```
**/.ssh/**            **/.aws/**            **/.gnupg/**          **/.kube/**
**/.config/gcloud/**  **/.docker/config.json
**/.netrc             **/.git-credentials   **/.npmrc             **/.pypirc
**/.dsh/.credentials.yaml   **/.dsh/sessions/**   **/.dsh/storages/**
**/AppData/Roaming/Microsoft/Credentials/**
**/AppData/Local/Microsoft/Credentials/**
**/AppData/Local/Google/Chrome/User Data/**
**/AppData/Local/Microsoft/Edge/User Data/**
**/AppData/Local/BraveSoftware/**
**/AppData/Roaming/Mozilla/Firefox/Profiles/**
**/id_rsa*  **/id_ed25519*  **/id_ecdsa*  **/*.pfx  **/*.p12
**/Windows/System32/config/**  **/NTDS.dit
**/logins.json  **/key4.db  **/Login Data  **/Local State  **/Cookies
```

匹配同时使用**词法路径和真实路径**（符号链接解析后），Windows 下不区分大小写。
如果不想每次点两下，可设 `sensitiveConfirmations: single`，退回"单次但文案加重"。

## 覆盖范围

按路径参数判定：

| 工具 | 判定字段 |
| --- | --- |
| `read` / `read_image` | `file_path` |
| `grep` / `glob` | `path`（缺省时以工作区为根，放行） |
| `working_directory` | `cd`（防止先 `cd` 到外面再相对读取） |
| `pwsh` / `bash` / `shell` | `workdir`，命令文本里的绝对路径、`..`、`~`、`$env:`、`$HOME`、`%VAR%` |

判定细节：

- 边界取**该 agent 第一次调用时的会话目录**（在派发前固定），之后 `cd` 到外面也不会把围栏带走；
- 不使用 `sandboxPolicy.workspaceRoot`：桌面 profile 里它可能是 host 进程目录（profile 目录），会把 profile 误当成工作区；
- 相对路径按会话当前目录解析，绝对路径直接判定；
- 词法路径 + `realpath` 同时比较，工作区内指向外面的符号链接/junction 也会拦截；
- 不存在的路径会解析最深的已存在祖先；
- 盘符相对路径（`C:foo`）无法安全判定，按越界处理；
- `extraAllowedRoots` 可以显式放行额外根目录（绝对路径或相对工作区）。

## 配置

```yaml
- id: outside-access-guard
  config:
    mode: ask                 # deny | ask | allow，默认 ask
    subagentMode: ''          # deny | ask | allow；留空 = 继承 mode
    log: true                 # 记录拦截决定
    logDir: ''                # 默认 <DSH_HOME>/logs/outside-access-guard
    logRetentionDays: 7       # 超过 N 天的日志自动删除（0 = 永不删除）
    confirmGapMs: 2000        # 二次确认之间的强制停顿（毫秒，0 = 关闭）
    sensitiveConfirmations: double   # double | single
    sensitivePaths: []        # 省略 = 默认敏感规则；[] = 关闭敏感升级
    extraAllowedRoots: []     # 额外放行的根目录
    gateShell: true           # 是否检查 shell，默认 true
    gatePathTools: true       # 是否检查文件类工具，默认 true
```

## 日志

每次判定写一行 JSONL 到 `$DSH_HOME/logs/outside-access-guard/YYYY-MM-DD.log`，按本地日期分文件，默认保留 7 天（进程启动时清理一次，之后每 6 小时一次）：

```json
{"ts":"2026-10-24T20:38:35.123+08:00","event":"ask","mode":"ask","tool":"read","risk":"normal","agent":"...","callId":"...","reason":"..."}
```

- `event`：`ask` / `deny` / `cancel` / `mode` / `approval`（审批结果）；
- 只记录**被判定过**的调用（工作区内的读取不会产生日志）；
- 写日志失败只告警，不影响拦截；
- `log: false` 关闭，`logDir` 换目录，`logRetentionDays` 改保留天数。

## 已知限制

1. **shell 是启发式检查，不是系统级隔离。** 绝对路径、`..`、常见环境变量能识别；
   字符串拼接、二次展开、编码、子进程脚本仍可绕过。真正可靠需要沙箱本身支持"读也受限"。
2. **只覆盖工具层。** 附件、技能加载、会话日志、web 抓取等 Host 内部服务不经过
   `tools/pre-execute`。
3. **审批策略为 `never` 或没有应答者时**，`ask` 失败关闭（拒绝），不会放行。
4. **不改变写入策略**：写工作区外仍由沙箱拒绝；`allow` 只影响本插件，不会放宽内核沙箱。
5. **模式是进程全局的**，不按会话区分；运行时开关重启即失效。
6. **开发阶段的已知缺口**：插件源码位于工作区，模型可通过 `write`/`edit` 改写它
   （重启或热重载后生效）。正式发布前应把安装副本移出工作区，并加自我修改防护。
7. 敏感规则是"提醒"而不是"保证"：用户仍可能在两次确认里手滑放行；
   对真正不可读的路径，请用 `deny` 模式或沙箱策略。

## 验证

```powershell
# 纯函数判定测试（24 项）+ 插件装配测试（9 项）
# 直接执行，不要用 node --test（沙箱内 spawn EPERM）
node test/classify.test.mjs
node test/apply.test.mjs
```

安装后：

- `/outside-access status` → 显示当前模式；命令由 Host 在启动时注册，改完插件需要重启 DSH；
- 读工作区外普通文件 → 弹出一次审批；
- 读 `~/.ssh/id_rsa`、浏览器 `Login Data`、`.dsh/.credentials.yaml` → 弹出两次；
- `/outside-access deny` 后读任何工作区外文件 → 直接拒绝，不弹窗；
- `/outside-access allow` 后不再拦截。

> `/outside-access` 是 Host 斜杠命令，只在插件启动时注册；运行时开关只存在于内存，
> 重启后回到配置里的 `mode`。

## 安装 / 卸载

```powershell
# 安装（本地目录，或 GitHub / npm 的包）
dsh plugin --profile desktop add /absolute/path/to/outside-access-guard

# 卸载
dsh plugin --profile desktop remove outside-access-guard
```

插件纯 Host、零依赖、无网络请求、无 install 脚本。

## 与二值开关的区别

`dsh-outsideread-switch` 只有"禁止/允许"两档，且状态由人通过 UI 开关维护；
本插件在中间加了"逐次审批"，并把敏感路径升级为两次确认。两者都是工具层围栏，
shell 限制也同样是启发式的；`dsh-outsideread-switch` 对自身状态文件有自我提权防护，
本插件目前没有对应实现（见"已知限制"第 6 条）。

## 许可证

MIT，见 [LICENSE](LICENSE)。
