# ClaudePreflight

打开 Claude 前，检查当前网络连接和电脑环境。网络切换后确认新的出口 IP，再从窗口启动 Claude。

这是一个 Windows x64 桌面工具，使用 C#、WinForms 和内置 WebView2。检查结果在窗口中展示，也可以导出 JSON。

## 下载与使用

从 [Releases](https://github.com/Yukinodot/ClaudePreflight/releases/latest) 下载 `ClaudePreflight-Windows.zip`，完整解压后运行 `ClaudePreflight.exe`。

点击“检查全部”，查看网络与系统、浏览器环境两个页面。出现“完整 IP 已改变”时，核对连接后点击“确认网络变化”。“打开桌面版”会重新检查网络，再调用本机注册的 Claude 应用。

运行需要 Windows x64、.NET Framework 4.x 和已安装的 Microsoft Edge WebView2 Runtime。无需安装 Python 或 Node，也无需 API Key。请保留压缩包中的 HTML、ICO 和 DLL 文件。

## 检查什么

网络页面显示 HTTPS 连通性、出口 IP 变化、响应时间、系统时间偏差、时区、Windows 代理配置、DNS 解析和查询服务的证书到期时间。IPv4、IPv6 分别保存基线，切换地址类型不会被当作同一地址发生变化。

浏览器页面通过内置 WebView2 测量 User-Agent、浏览器时区、WebRTC 候选、WebGL 渲染器、Canvas 摘要、屏幕参数和 CPU 逻辑线程数，并与上次结果比较。检测在程序内部完成，不另开 Edge 窗口。这里展示的是本工具内置引擎的参数。

网络检查结果有效期为 60 秒。连接失败、响应超过 10 秒、系统时间偏差超过 5 分钟或同类型出口 IP 改变时，工具会暂停自己的启动按钮，并说明原因。勾选“每 60 秒检查一次”后，定时任务只重复网络检查。

这些结果用于排查本机连接和环境变化，不用于预测账号状态。

## 数据存在哪里

设置与检查记录保存在程序目录的 `data/` 中。IP 默认遮盖；完整 IP 仅在勾选显示选项后出现在界面。浏览器出口 IP 和 WebRTC 地址不写入参数基线。

网络检查访问 Cloudflare 的 `cdn-cgi/trace`；WebRTC 测量使用 Google 的公共 STUN 服务。服务端会收到对应连接的出口 IP。`claude.ai` 只用于 DNS 解析。本地记录保存在电脑上，程序不上传这些记录。

## 从源码构建

仓库包含编译所需的 WebView2 SDK DLL，可直接在 Windows PowerShell 中运行：

```powershell
.\build.ps1
.\ClaudePreflight.exe
```

`ClaudePreflight.cs` 负责窗口、网络检查、数据存储和启动条件；`BrowserChecks.cs` 负责 WebView2 桥接与结果比较；`BrowserProbe.html` 是本地测量页面。`build.ps1` 调用 Windows 自带的 .NET Framework C# 编译器生成 x64 程序。

“打开桌面版”使用 `BrowserChecks.cs` 中的 `ClaudeAppId` 调用已注册应用。若本机安装方式对应的应用 ID 不同，需要修改该值并重新构建。

## 验证与打包

```powershell
# 离线自测：验证启动条件、双栈基线、IP 遮盖和消息来源校验
.\ClaudePreflight.exe --self-test "$PWD\artifacts\self-test.json"

# 实际网络检查：结果写入指定文件
.\ClaudePreflight.exe --diagnose "$PWD\artifacts\connection.json"

# 生成干净的发布包，只收录程序、源码、依赖和说明
.\scripts\package.ps1
```

内置自测包含 31 项断言。GitHub Actions 会重新编译并运行自测；实际网络与 WebView2 测量需在 Windows 桌面环境中运行。

## 第三方文件

WebView2 SDK 版本为 `1.0.4314.35`，许可见 [WebView2-LICENSE.txt](WebView2-LICENSE.txt)。图标来自原项目使用的本机 Claude 安装资源，归原权利人所有。项目为个人辅助工具。实现参考见 [docs/references.md](docs/references.md)。
