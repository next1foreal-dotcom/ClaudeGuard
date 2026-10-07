# ClaudeGuard

Windows 上的 Claude 网络保护启动器与常驻监测面板。当前是从已验证的本机实现整理出的源码版，尚未提供通用安装包或首次配置向导。

## 功能

- 启动前核验程序组件、防火墙、IPv6、FlClash 路由与批准出口。
- 对已登记的 Claude 可执行文件阻断非回环直连，并通过本机 HTTP 代理启动受管会话。
- 使用 Windows Job Object 管理受管进程；代理、路由或保护核验异常时停止该会话。
- 展示代理出口、直连对照、DNS 解析路径、隔离浏览器 WebRTC 抽检、第三方网段信誉与系统环境。
- 可调整尺寸、置顶、切换完整面板 / Widget；灰色与浅色主题及窗口尺寸可保存。
- 启动保护核验直接展示，红绿状态区分通过与异常；隐藏滚动条，保留鼠标滚轮。
- 可选的浏览器 / Codex UDP 直连阻断及移除入口。

## 当前要求与限制

仅支持 Windows。面板使用 Windows PowerShell 5.1、WPF 与系统 curl；路由审计需要 Python 3 和 PyYAML；隔离浏览器抽检需要 Edge 与安装于标准位置的 Node.js。

当前实现绑定 FlClash 的本地配置结构，HTTP 代理校验限定为 `http://127.0.0.1:7890`。组件登记逻辑目前要求同时安装 Claude Code 和 Claude 桌面版。尚未实现自动发现端口、仅安装一种客户端的配置适配、运行时随包分发或一键新用户配置。

此工具只保护已登记程序以及通过工具启动的受管会话。检测周期存在延迟，因此直连阻断依赖事先生效的防火墙规则。规则更新、代理自身的上游行为以及未登记程序不应被当作已经覆盖。

WebRTC 抽检不代表日常浏览器或 Claude 的全部网络行为；空候选本身不证明没有泄漏。第三方信誉评分不来自 Claude，不能预测账号状态。IP 地理数据库、语言和时区也不能证明物理位置或账号安全。

## 本机配置

1. 将 `guard-config.example.json` 复制为 `guard-config.json`。
2. 将示例中的出口地址、国家、Claude 路径、Python 路径、FlClash 目录、配置身份和节点指纹替换为用户明确批准的本机值。路径必须填写完整真实路径，示例不会自动展开环境变量。
3. `192.0.2.10` 是文档示例地址，零值节点指纹不是有效批准凭证；请勿将它们直接用于实际保护。
4. 依照本机需求预先配置 FlClash 与 IPv6。当前安装入口安装本工具的防火墙规则，不负责自动完成这些系统配置。
5. 双击 `Install-Protection.cmd`，完成 Windows 管理员授权后安装并核验规则。
6. 双击 `Open-ClaudeGuard.cmd` 打开面板。首次自动核验通过后，通过面板启动 Claude；也可使用 `Start-Claude-Code.cmd` 或 `Start-Claude-Desktop.cmd`。

浏览器 UDP 阻断会影响相应应用的 UDP 功能。`Remove-Protection.cmd` 和 `Remove-Browser-UDP.cmd` 分别移除对应的工具规则；不会撤销此前手动修改的代理、IPv6 或定位设置。

## 隐私与数据

仓库仅包含源码与脱敏配置示例。真实 `guard-config.json`、`.state`、浏览器抽检配置、日志、备份和本机预览均不纳入版本控制。

诊断会请求 IPinfo、Cloudflare trace、NetCoffee、Google / Cloudflare STUN 等第三方服务。完整出口与结果记录在本机 `.state`；界面的“隐藏 IP”仅遮盖展示，不会删除本地记录，也不会隐藏诊断请求中的出口。

## 开发验证

安装 Python 依赖：

```powershell
python -m pip install -r requirements.txt
python -m unittest -v test_route_audit.py
```

UI 展示与控件回归需要本地 `guard-config.json` 和 `.state` 目录：

```powershell
New-Item -ItemType Directory -Path .state -Force
powershell.exe -NoProfile -STA -File .\ClaudeGuardUI.ps1 -UiSmokeTest
```

`Test-ClaudeGuard.ps1` 是依赖真实本机配置、防火墙与网络的集成检查；不要把它当作无网络单元测试或在未配置机器上运行。静态检查和模拟事件测试不代替真实桌面操作验收。

## 后续计划

- 首次配置向导：识别客户端、代理与出口，用户确认后生成配置并安装保护。
- 解除固定端口、固定客户端组合和本机运行时路径约束。
- 在不继承发布者机器数据的前提下制作安装包。