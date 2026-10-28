using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace ClaudePreflight {
    public sealed class BrowserSnapshot {
        public bool Succeeded { get; set; }
        public string Error { get; set; }
        public string CheckedAt { get; set; }
        public string MeasurementSource { get; set; }
        public string RuntimeVersion { get; set; }
        public string UserAgent { get; set; }
        public string HttpUserAgent { get; set; }
        public string Platform { get; set; }
        public string ClientPlatform { get; set; }
        public string TimeZone { get; set; }
        public int OffsetMinutes { get; set; }
        public bool Webdriver { get; set; }
        public string WebGL { get; set; }
        public string CanvasHash { get; set; }
        public string Screen { get; set; }
        public int CpuThreads { get; set; }
        public string HttpIp { get; set; }
        public string HttpError { get; set; }
        public string[] WebRtcIps { get; set; }
        public int HostCandidates { get; set; }
        public int ServerCandidates { get; set; }
        public int RelayCandidates { get; set; }
        public string WebRtcState { get; set; }
    }
    public static class BrowserChecks {
        public const string ClaudeAppId="claude.ai-18877962_4k56vfyhbf6dg!App";
        public static string ClientDescription() {
            foreach(var parent in new [] {Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}) {
                string file=Path.Combine(parent,@"Microsoft\Edge\Application\msedge.exe");
                if(File.Exists(file)) return "Edge "+FileVersionInfo.GetVersionInfo(file).ProductVersion+" / 安装的 Claude 网页应用";
            }
            return "Edge 未安装";
        }
        public static List<string> Changed(BrowserSnapshot baseline,BrowserSnapshot current) {
            var changes=new List<string>();
            if(baseline==null || current==null || !baseline.Succeeded || !current.Succeeded) return changes;
            if(baseline.MeasurementSource!=current.MeasurementSource) { changes.Add("检测环境已更新"); return changes; }
            if(baseline.UserAgent!=current.UserAgent) changes.Add("浏览器版本 / UA");
            if(baseline.Platform!=current.Platform || baseline.ClientPlatform!=current.ClientPlatform) changes.Add("平台");
            if(baseline.TimeZone!=current.TimeZone || baseline.OffsetMinutes!=current.OffsetMinutes) changes.Add("浏览器时区");
            if(baseline.Webdriver!=current.Webdriver) changes.Add("自动化标志");
            if(baseline.WebGL!=current.WebGL) changes.Add("WebGL 渲染器");
            if(baseline.CanvasHash!=current.CanvasHash) changes.Add("本地绘图指纹");
            if(baseline.Screen!=current.Screen || baseline.CpuThreads!=current.CpuThreads) changes.Add("显示 / 硬件参数");
            return changes;
        }
        public static string RoutingSummary(BrowserSnapshot b,Scan scan,bool full) {
            if(b==null || !b.Succeeded) return "尚未检查";
            string http=string.IsNullOrEmpty(b.HttpIp)?"HTTP 未返回地址":(full?b.HttpIp:Checks.Mask(b.HttpIp));
            var ips=new List<string>();
            foreach(string ip in b.WebRtcIps??new string[0]) ips.Add(full?ip:Checks.Mask(ip));
            return "HTTP "+http+" / WebRTC "+(ips.Count>0?string.Join(", ",ips.ToArray()):"公网候选 0");
        }
        public static object Report(BrowserSnapshot b,bool full) {
            if(b==null) return null;
            if(!b.Succeeded) return new { measured=false, checkedAt=b.CheckedAt, error=b.Error };
            var ips=new List<string>();
            foreach(string ip in b.WebRtcIps??new string[0]) ips.Add(full?ip:Checks.Mask(ip));
            return new { measured=b.Succeeded, checkedAt=b.CheckedAt, installedClient=ClientDescription(), measurementSource=b.MeasurementSource, runtimeVersion=b.RuntimeVersion, userAgent=b.UserAgent, httpUserAgent=b.HttpUserAgent, platform=b.Platform, clientHintsPlatform=b.ClientPlatform, browserTimeZone=b.TimeZone, offsetMinutes=b.OffsetMinutes, webdriver=b.Webdriver, webgl=b.WebGL, canvasSampleHash=b.CanvasHash, screen=b.Screen, cpuThreads=b.CpuThreads, httpIp=full?b.HttpIp:Checks.Mask(b.HttpIp), httpError=b.HttpError, webRtcPublicIps=ips.ToArray(), hostCandidates=b.HostCandidates, serverReflexiveCandidates=b.ServerCandidates, relayCandidates=b.RelayCandidates, webRtcState=b.WebRtcState, error=b.Error };
        }
        public static bool SourceValid(string actual,string expected) { return !string.IsNullOrEmpty(expected) && string.Equals(actual,expected,StringComparison.Ordinal); }
        public static async Task<BrowserSnapshot> Run(WebView2 view,string pageFile,int timeoutSeconds) {
            var failure=new BrowserSnapshot { CheckedAt=DateTimeOffset.Now.ToString("o"), Succeeded=false };
            if(!File.Exists(pageFile)) { failure.Error="缺少 BrowserProbe.html，请保留完整程序文件夹。"; return failure; }
            CoreWebView2 core=null;
            EventHandler<CoreWebView2WebMessageReceivedEventArgs> message=null;
            EventHandler<CoreWebView2WebResourceRequestedEventArgs> resource=null;
            EventHandler<CoreWebView2NavigationStartingEventArgs> navigation=null;
            EventHandler<CoreWebView2NewWindowRequestedEventArgs> popup=null;
            EventHandler<CoreWebView2PermissionRequestedEventArgs> permission=null;
            try {
                if(view.CoreWebView2==null) {
                    var env=await CoreWebView2Environment.CreateAsync(null,Path.Combine(Storage.DirectoryPath,"webview2"));
                    await view.EnsureCoreWebView2Async(env);
                }
                core=view.CoreWebView2;
                core.Settings.AreDefaultScriptDialogsEnabled=false;
                core.Settings.AreDefaultContextMenusEnabled=false;
                core.Settings.AreDevToolsEnabled=false;
                core.Settings.AreHostObjectsAllowed=false;
                core.Settings.IsWebMessageEnabled=true;
                string root="https://preflight.invalid/BrowserProbe.html?session="+Guid.NewGuid().ToString("N");
                string html=File.ReadAllText(pageFile,Encoding.UTF8);
                string httpUa="";
                var completion=new TaskCompletionSource<BrowserSnapshot>();
                message=delegate(object sender,CoreWebView2WebMessageReceivedEventArgs e) {
                    if(!SourceValid(e.Source,root)) return;
                    try {
                        string json=e.WebMessageAsJson;
                        if(json.Length>32768) throw new FormatException("检测结果过大。");
                        var b=new JavaScriptSerializer().Deserialize<BrowserSnapshot>(json);
                        Validate(b);
                        b.HttpUserAgent=httpUa; b.Succeeded=true;
                        b.MeasurementSource="内置 WebView2"; b.RuntimeVersion=core.Environment.BrowserVersionString;
                        b.CheckedAt=DateTimeOffset.Now.ToString("o");
                        completion.TrySetResult(b);
                    }catch(Exception ex) { completion.TrySetException(ex); }
                };
                resource=delegate(object sender,CoreWebView2WebResourceRequestedEventArgs e) {
                    bool allowed=SourceValid(e.Request.Uri,root);
                    if(allowed && e.Request.Headers.Contains("User-Agent")) httpUa=e.Request.Headers.GetHeader("User-Agent");
                    string headers="Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src https://www.cloudflare.com; base-uri 'none'; frame-ancestors 'none'\r\n";
                    e.Response=core.Environment.CreateWebResourceResponse(new MemoryStream(Encoding.UTF8.GetBytes(allowed?html:"Denied")),allowed?200:403,allowed?"OK":"Forbidden",headers);
                };
                navigation=delegate(object sender,CoreWebView2NavigationStartingEventArgs e) { if(e.Uri!="about:blank" && !SourceValid(e.Uri,root)) e.Cancel=true; };
                popup=delegate(object sender,CoreWebView2NewWindowRequestedEventArgs e) { e.Handled=true; };
                permission=delegate(object sender,CoreWebView2PermissionRequestedEventArgs e) { e.State=CoreWebView2PermissionState.Deny; };
                core.AddWebResourceRequestedFilter("https://preflight.invalid/*",CoreWebView2WebResourceContext.All);
                core.WebResourceRequested+=resource; core.WebMessageReceived+=message;
                core.NavigationStarting+=navigation; core.NewWindowRequested+=popup; core.PermissionRequested+=permission;
                core.Navigate(root);
                if(await Task.WhenAny(completion.Task,Task.Delay(timeoutSeconds*1000))!=completion.Task) { failure.Error="内置检测超时，请重试。"; return failure; }
                return await completion.Task;
            }catch(Exception ex) { failure.Error="内置检测失败："+ex.Message; return failure; }
            finally {
                if(core!=null && !view.IsDisposed) {
                    core.Navigate("about:blank");
                    if(resource!=null) core.WebResourceRequested-=resource;
                    if(message!=null) core.WebMessageReceived-=message;
                    if(navigation!=null) core.NavigationStarting-=navigation;
                    if(popup!=null) core.NewWindowRequested-=popup;
                    if(permission!=null) core.PermissionRequested-=permission;
                    core.RemoveWebResourceRequestedFilter("https://preflight.invalid/*",CoreWebView2WebResourceContext.All);
                }
            }
        }
        public static void Validate(BrowserSnapshot b) {
            if(b==null || string.IsNullOrEmpty(b.UserAgent) || b.UserAgent.Length>1024 || string.IsNullOrEmpty(b.TimeZone) || b.TimeZone.Length>100 || b.OffsetMinutes < -900 || b.OffsetMinutes > 900) throw new FormatException("浏览器结果格式有误。");
            if((b.WebGL??"").Length>1024 || (b.CanvasHash??"").Length>100 || (b.Screen??"").Length>100 || b.CpuThreads<0 || b.CpuThreads>4096) throw new FormatException("浏览器参数超出范围。");
            IPAddress ip;
            if(!string.IsNullOrEmpty(b.HttpIp) && !IPAddress.TryParse(b.HttpIp,out ip)) throw new FormatException("浏览器 HTTP 地址无效。");
            if(b.WebRtcIps!=null) { if(b.WebRtcIps.Length>16) throw new FormatException("候选地址过多。"); foreach(var item in b.WebRtcIps) if(!IPAddress.TryParse(item,out ip)) throw new FormatException("WebRTC 地址无效。"); }
        }
    }
}
