# ClaudeGuard

Windows 上的 Claude / Codex 网络保护启动器与常驻监测面板，包含首次配置向导。当前提供源码与启动脚本，尚未制作独立安装包。

## 功能

- 启动前核验程序组件、防火墙、IPv6、FlClash 路由与批准出口。
- 对已登记客户端的可执行文件阻断非回环直连，并通过本机 HTTP 代理启动受管会话。
- 使用 Windows Job Object 管理受管进程；代理、路由或保护核验异常时停止该会话。
- 展示代理出口、直连对照、DNS 解析路径、隔离浏览器 WebRTC 抽检、第三方网段信誉与系统环境。
- 可调整尺寸、置顶、切换完整面板 / Widget；深色与浅色磨砂主题及窗口尺寸可保存。
- 启动保护核验直接展示，红绿状态区分通过与异常；隐藏滚动条，保留鼠标滚轮。
- 可选的浏览器 / Codex UDP 直连阻断及移除入口。
- 本地 Lucide 矢量图标，统一描边与点击区域；浅色主题使用柔和浅灰半透明底、深色文字与细微磨砂纹理，保持连续面板与清晰红绿状态；现有透明窗口使用纹理表现磨砂质感，未启用原生桌面背景模糊；设置集中于顶部，底部仅保留重新检查与启动 / 停止会话。最小化入口位于设置菜单。

## 当前要求与限制

仅支持 Windows。面板使用 Windows PowerShell 5.1、WPF 与系统 curl；路由审计需要 Python 3 和 PyYAML；隔离浏览器抽检需要 Edge 与安装于标准位置的 Node.js。

配置向导支持 Windows x64 和 FlClash 的配置审计。自动发现已安装的 Claude Code、Claude Desktop、Codex CLI、Codex Desktop、常见代理客户端与回环 HTTP 端口；仅登记用户选中的原生程序，不要求同时安装两种 Claude 客户端。共享 `node.exe` 不作为客户端登记；无法解析原生入口的脚本安装会明确提示未支持。端口不限于 7890，SOCKS 端口和带账号密码的代理 URL 不接受。发现其他代理客户端不代表其路由已核验；目前启用保护仍需要有效的 FlClash 配置和所选服务共用的固定节点。

此工具只保护已登记程序以及通过工具启动的受管会话。检测周期存在延迟，因此直连阻断依赖事先生效的防火墙规则。规则更新、代理自身的上游行为以及未登记程序不应被当作已经覆盖。

WebRTC 抽检不代表日常浏览器或 Claude 的全部网络行为；空候选本身不证明没有泄漏。第三方信誉评分不来自 Claude，不能预测账号状态。IP 地理数据库、语言和时区也不能证明物理位置或账号安全。

## 首次配置

1. 双击 `Open-ClaudeGuard.cmd`。没有完成配置时自动进入向导，扫描已安装程序、代理客户端和 HTTP 端口。选择需要保护的程序；核对代理地址。
2. 点击“检测出口”。工具检查 FlClash 分流与节点，要求所选服务的检测端点返回相同 IPv4 / 地区，展示出口、地区和节点。检测值不会自动变成批准值。
3. 勾选出口确认，点击“启用保护”。再次比对检测结果后，请求一次 Windows 管理员授权，登记所选程序的 IPv4 / IPv6 非回环直连阻断规则，完成路由、出口、程序与防火墙核验，最后保存配置并进入面板。管理员操作必须由同一 Windows 用户完成。

缺少 Python + PyYAML 时，可勾选准备工具专用组件；只通过所选 HTTP 代理从 Python / PyPI 官方文件源下载，验证 `runtime-lock.json` 的 SHA256 后安装到本地 `.state/runtime`。不修改系统 Python 或 PATH。此下载仅提供路由核验组件。

配置会记住；下次直接打开面板。程序的路径、版本或文件元数据变化时，启动与会话核验会拒绝继续，提示更新保护。面板设置提供“更新保护”和“重新配置”。更新已选程序会重新请求管理员授权；出口或节点变更需重新检测和确认，工具不会自动接受新出口。

先前配置保持兼容。安装或安装后核验失败不会替换旧配置；后者失败时新直连阻断规则仍保留。常驻监控使用 Windows Job Object 停止由工具启动的会话；网络断开时的直连阻断依赖已经生效的防火墙规则，不依赖轮询关闭进程。

可选的浏览器 UDP 阻断会影响已发现浏览器的 UDP 功能，向导默认不启用。`Remove-Protection.cmd` 与 `Remove-Browser-UDP.cmd` 分别移除对应工具规则；不撤销此前手动修改的代理、IPv6 或定位设置。新版对所选程序同时阻断 IPv4 / IPv6 直连，不自动修改整机 IPv6 开关。

`guard-config.example.json` 仅供开发或手动配置参考，文档 IP 和零值节点指纹不能用于真实保护；新用户不需要复制这个文件。

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
powershell.exe -NoProfile -STA -File .\GuardSetupUI.ps1 -UiSmokeTest
powershell.exe -NoProfile -File .\Test-GuardSetup.ps1
```

`Test-ClaudeGuard.ps1` 是依赖真实本机配置、防火墙与网络的集成检查；不要把它当作无网络单元测试或在未配置机器上运行。静态检查和模拟事件测试不代替真实桌面操作验收。

## 后续计划

- 在不继承发布者机器数据的前提下制作安装包。

## 图标许可

界面图标来自 [Lucide](https://lucide.dev/)，对应官方源版本记录在 `icons/lucide.json`。转换为 WPF 矢量几何后随程序离线加载；保留原始 ISC / MIT 许可于 `icons/LICENSE.txt`。
