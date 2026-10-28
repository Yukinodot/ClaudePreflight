# 实现参考

WebView2 的嵌入方式和独立用户数据目录参考微软文档：[WinForms 入门](https://learn.microsoft.com/en-us/microsoft-edge/webview2/get-started/winforms)、[用户数据目录](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder)。检测页通过资源接口在本地提供，结果经 WebMessage 返回，并校验页面地址和本次会话标识。

WebRTC 候选收集参考 [WebRTC Trickle ICE 示例](https://webrtc.github.io/samples/src/content/peerconnection/trickle-ice/)。窗口展示实际候选数及观察到的地址。

原项目调研过 [CheckClaude](https://github.com/zzusec/CheckClaude) 和 [check-cc](https://github.com/yacuo/check-cc) 的检查方向。这里的代码独立编写，实际功能以仓库源码为准。
