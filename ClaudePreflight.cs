using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Web.WebView2.WinForms;

namespace ClaudePreflight {
    public sealed class Scan {
        public bool Connected { get; set; }
        public string Ip { get; set; }
        public string Fingerprint { get; set; }
        public string Error { get; set; }
        public double ClockOffsetSeconds { get; set; }
        public double RoundTripSeconds { get; set; }
        public DateTime CheckedUtc { get; set; }
        public string TimeZone { get; set; }
        public string Proxy { get; set; }
        public string ProxyConfig { get; set; }
        public string Dns { get; set; }
        public string Certificate { get; set; }
        public BrowserSnapshot Browser { get; set; }
        public string[] BrowserChanges { get; set; }
    }
    public sealed class Settings {
        public string IPv4Fingerprint { get; set; }
        public string IPv6Fingerprint { get; set; }
        public BrowserSnapshot PreviousBrowser { get; set; }
        public string Baseline(Scan scan) { return scan.Ip.Contains(":") ? IPv6Fingerprint : IPv4Fingerprint; }
        public void Remember(Scan scan) { if(scan.Ip.Contains(":")) IPv6Fingerprint=scan.Fingerprint; else IPv4Fingerprint=scan.Fingerprint; }
    }
    public static class Checks {
        public const string Endpoint = "https://www.cloudflare.com/cdn-cgi/trace";
        public static string Hash(string value) {
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(value))).Replace("-", "");
        }
        public static string Mask(string ip) {
            IPAddress parsed;
            if (!IPAddress.TryParse(ip, out parsed)) return "未取得";
            var bytes = parsed.GetAddressBytes();
            if (bytes.Length == 4) return bytes[0] + "." + bytes[1] + ".*.*";
            return bytes[0].ToString("x2") + bytes[1].ToString("x2") + ":" + bytes[2].ToString("x2") + bytes[3].ToString("x2") + ":…";
        }
        public static Scan Parse(string body, DateTime started, DateTime ended) {
            var values = new Dictionary<string,string>();
            foreach (var line in body.Split('\n')) {
                int equals = line.IndexOf('=');
                if (equals > 0) values[line.Substring(0, equals)] = line.Substring(equals + 1).Trim();
            }
            string ip, stamp; IPAddress parsed; double epoch;
            if (!values.TryGetValue("ip", out ip) || !IPAddress.TryParse(ip, out parsed)) throw new FormatException("查询结果没有有效的出口 IP。");
            if (!values.TryGetValue("ts", out stamp) || !double.TryParse(stamp, NumberStyles.Float, CultureInfo.InvariantCulture, out epoch) || double.IsNaN(epoch) || double.IsInfinity(epoch)) throw new FormatException("查询结果没有有效的服务器时间。");
            var remote = new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc).AddSeconds(epoch);
            var midpoint = started.AddTicks((ended-started).Ticks / 2);
            return new Scan { Connected=true, Ip=parsed.ToString(), Fingerprint=Hash(parsed.ToString()), ClockOffsetSeconds=(midpoint-remote).TotalSeconds, RoundTripSeconds=(ended-started).TotalSeconds, CheckedUtc=ended };
        }
        public static Scan Run() {
            var scan = new Scan();
            try {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                var uri = new Uri(Endpoint);
                var proxy = WebRequest.DefaultWebProxy;
                string proxyName = (proxy == null || proxy.IsBypassed(uri)) ? "直连（本次检查）" : "使用 Windows 系统代理";
                var request = (HttpWebRequest)WebRequest.Create(uri);
                request.Method = "GET";
                request.Timeout = 12000; request.ReadWriteTimeout = 12000;
                request.AllowAutoRedirect = false;
                request.UserAgent = "ClaudePreflight/1.2";
                request.Headers[HttpRequestHeader.CacheControl] = "no-cache";
                request.MaximumResponseHeadersLength = 32;
                var started = DateTime.UtcNow;
                using (var response = (HttpWebResponse)request.GetResponse()) {
                    if (response.StatusCode != HttpStatusCode.OK) throw new IOException("查询服务返回 HTTP " + (int)response.StatusCode);
                    using (var reader = new StreamReader(response.GetResponseStream())) {
                        char[] buffer = new char[16385];
                        int count = reader.ReadBlock(buffer, 0, buffer.Length);
                        if (count > 16384) throw new IOException("查询响应超出预期大小。");
                        scan = Parse(new string(buffer,0,count),started,DateTime.UtcNow);
                    }
                    if(request.ServicePoint.Certificate!=null) {
                        using(var certificate=new X509Certificate2(request.ServicePoint.Certificate)) scan.Certificate="验证通过 / 到期 "+certificate.NotAfter.ToString("yyyy-MM-dd");
                    }
                }
                scan.Proxy = proxyName;
            } catch (Exception ex) {
                scan.Connected = false;
                scan.Error = ex is WebException ? "网络请求失败：" + ((WebException)ex).Status : ex.Message;
                scan.CheckedUtc = DateTime.UtcNow;
            }
            scan.TimeZone = TimeZoneInfo.Local.DisplayName;
            scan.ProxyConfig=ProxyConfiguration();
            scan.Dns=ResolveClaude();
            return scan;
        }
        public static string ProxyConfiguration() {
            try {
                using(var key=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings")) {
                    bool enabled=key!=null && Convert.ToInt32(key.GetValue("ProxyEnable",0))!=0;
                    bool pac=key!=null && !string.IsNullOrWhiteSpace(Convert.ToString(key.GetValue("AutoConfigURL","")));
                    int variables=0;
                    foreach(var name in new [] {"HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"}) if(!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name))) variables++;
                    return "手动代理"+(enabled?"开":"关")+" / PAC "+(pac?"已设置":"未设置")+(variables>0?" / 代理变量 "+variables+" 项":"");
                }
            }catch { return "配置读取失败"; }
        }
        public static string ResolveClaude() {
            try {
                var pending=Dns.BeginGetHostAddresses("claude.ai",null,null);
                if(!pending.AsyncWaitHandle.WaitOne(2500)) return "claude.ai 解析超时";
                var ips=Dns.EndGetHostAddresses(pending); int v4=0,v6=0;
                foreach(var ip in ips) if(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork) v4++; else if(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetworkV6) v6++;
                return "claude.ai / IPv4 "+v4+" 个，IPv6 "+v6+" 个";
            }catch { return "claude.ai 解析失败"; }
        }
        public static string BlockReason(Scan scan, Settings settings, DateTime now, bool busy) {
            if (busy) return "正在检查连接";
            if (scan == null) return "请先检查环境";
            if (!scan.Connected) return "网络检查失败，请检查连接后重试";
            double age = (now-scan.CheckedUtc).TotalSeconds;
            if (age < -5 || age > 60) return "检查结果已过期，请重新检查";
            if (scan.RoundTripSeconds > 10) return "本次响应较慢，请重新检查";
            if (Math.Abs(scan.ClockOffsetSeconds) > 300) return "系统时间偏差超过 5 分钟，请先校时";
            if (!string.IsNullOrEmpty(settings.Baseline(scan)) && settings.Baseline(scan) != scan.Fingerprint) return "出口 IP 与已记录地址不同";
            return null;
        }
        public static object Report(Scan s) {
            return new { product="Claude 启动前检查", version="1.2", checkedAt=s.CheckedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz"), connected=s.Connected, exitIp=Mask(s.Ip), clockOffsetSeconds=s.Connected?(double?)Math.Round(s.ClockOffsetSeconds,2):null, roundTripSeconds=s.Connected?(double?)Math.Round(s.RoundTripSeconds,2):null, timeZone=s.TimeZone, proxy=s.Proxy, proxyConfiguration=s.ProxyConfig, dns=s.Dns, probeCertificate=s.Certificate, browser=BrowserChecks.Report(s.Browser,false), browserChanges=s.BrowserChanges, error=s.Error };
        }
    }
    public static class Storage {
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer();
        public static string DirectoryPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"data");
        public static string LoadError;
        public static Settings Load() {
            var path = Path.Combine(DirectoryPath,"settings.json");
            if (!File.Exists(path)) return new Settings();
            try {
                var s = Json.Deserialize<Settings>(File.ReadAllText(path,Encoding.UTF8));
                if (s == null) throw new IOException("空配置");
                return s;
            } catch { LoadError="本地网络记录无法读取，请检查 data/settings.json。"; return new Settings(); }
        }
        public static void WriteJson(string path, object value) {
            var parent = Path.GetDirectoryName(Path.GetFullPath(path));
            Directory.CreateDirectory(parent);
            var temp = path + ".tmp";
            File.WriteAllText(temp,Json.Serialize(value),new UTF8Encoding(false));
            if (File.Exists(path)) File.Replace(temp,path,null); else File.Move(temp,path);
        }
        public static void Save(Settings s) { WriteJson(Path.Combine(DirectoryPath,"settings.json"),s); }
        public static void Append(Scan s, bool changed) {
            Directory.CreateDirectory(DirectoryPath);
            var path = Path.Combine(DirectoryPath,"checks-" + DateTime.Now.ToString("yyyy-MM-dd") + ".jsonl");
            File.AppendAllText(path,Json.Serialize(new { scan=Checks.Report(s), networkChanged=changed })+Environment.NewLine,new UTF8Encoding(false));
        }
    }
    public sealed class MainForm : Form {
        // Visual tokens are declared before the layout.
        static readonly Color Paper=ColorTranslator.FromHtml("#F9F8F6");
        static readonly Color Ink=ColorTranslator.FromHtml("#141413");
        static readonly Color Quiet=ColorTranslator.FromHtml("#615C55");
        static readonly Color Rule=ColorTranslator.FromHtml("#D8D3C9");
        static readonly Color Accent=ColorTranslator.FromHtml("#384F3A");
        static readonly Color Alert=ColorTranslator.FromHtml("#8C3F23");
        static readonly Font BodyFont=new Font("Microsoft YaHei UI",10F);
        static readonly Font TitleFont=new Font("SimSun",25F,FontStyle.Bold);
        readonly Settings settings;
        Scan last;
        bool busy, savingFailed;
        Label headline, details, networkValue, ipValue, clockValue, zoneValue, proxyValue, stampValue, dnsValue, certificateValue;
        Label clientValue, platformValue, browserZoneValue, automationValue, rtcValue, routeValue, rendererValue, canvasValue, displayValue, changesValue;
        Button checkButton, acknowledgeButton, desktopButton, exportButton;
        TabControl tabs;
        WebView2 embeddedProbe;
        readonly ToolTip hints=new ToolTip { AutoPopDelay=20000, InitialDelay=350, ReshowDelay=100 };
        CheckBox monitor, showIp;
        readonly Timer ticker = new Timer();
        readonly string capturePath;
        public MainForm(string capture) {
            capturePath=capture;
            settings=Storage.Load();
            Text="Claude 启动前检查";
            string iconPath=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"claude.ico");
            if(File.Exists(iconPath)) Icon=new Icon(iconPath);
            BackColor=Paper; ForeColor=Ink; Font=BodyFont;
            AutoScaleMode=AutoScaleMode.Dpi;
            ClientSize=new Size(920,900); MinimumSize=new Size(850,850);
            StartPosition=FormStartPosition.CenterScreen;
            var root=new TableLayoutPanel { Dock=DockStyle.Fill, ColumnCount=1, RowCount=8, Padding=new Padding(32,25,32,22), BackColor=Paper, AutoScroll=true };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,45));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,34));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,96));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,360));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,44));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,56));
            root.RowStyles.Add(new RowStyle(SizeType.Percent,100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute,40));
            Controls.Add(root);
            embeddedProbe=new WebView2 { Size=new Size(32,32), Location=new Point(0,0), DefaultBackgroundColor=Paper, TabStop=false };
            Controls.Add(embeddedProbe); embeddedProbe.SendToBack();
            root.Controls.Add(new Label { Text="Claude 启动前检查", Font=TitleFont, Dock=DockStyle.Fill, TextAlign=ContentAlignment.MiddleLeft, Margin=Padding.Empty },0,0);
            root.Controls.Add(new Label { Text="检查网络与本地浏览器环境，再打开 Claude。", ForeColor=Quiet, Dock=DockStyle.Fill, TextAlign=ContentAlignment.MiddleLeft, Margin=Padding.Empty },0,1);
            var status=new TableLayoutPanel { Dock=DockStyle.Fill, RowCount=2, ColumnCount=1, Padding=new Padding(14,10,10,10), BackColor=ColorTranslator.FromHtml("#F1F0EC"), Margin=new Padding(0,3,0,10) };
            status.RowStyles.Add(new RowStyle(SizeType.Absolute,29));
            status.RowStyles.Add(new RowStyle(SizeType.Percent,100));
            headline=new Label { Text="尚未检查", Font=new Font(BodyFont,FontStyle.Bold), Dock=DockStyle.Fill, Margin=Padding.Empty };
            details=new Label { Text="点击“检查全部”获取当前结果。", Dock=DockStyle.Fill, ForeColor=Quiet, Margin=Padding.Empty };
            status.Controls.Add(headline,0,0); status.Controls.Add(details,0,1); root.Controls.Add(status,0,2);
            tabs=new TabControl { Dock=DockStyle.Fill, Margin=new Padding(0,4,0,0) };
            var netTab=new TabPage("网络与系统") { BackColor=Paper, Padding=new Padding(6,2,6,2) };
            var browserTab=new TabPage("浏览器环境") { BackColor=Paper, Padding=new Padding(6,2,6,2) };
            tabs.TabPages.Add(netTab); tabs.TabPages.Add(browserTab);
            var rows=new TableLayoutPanel { ColumnCount=2, RowCount=8, Dock=DockStyle.Fill, Margin=Padding.Empty };
            rows.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,180)); rows.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            networkValue=AddRow(rows,0,"网络连接"); ipValue=AddRow(rows,1,"出口 IP"); clockValue=AddRow(rows,2,"系统时间偏差");
            zoneValue=AddRow(rows,3,"当前时区"); proxyValue=AddRow(rows,4,"Windows 代理"); stampValue=AddRow(rows,5,"检查时间");
            dnsValue=AddRow(rows,6,"DNS 解析"); certificateValue=AddRow(rows,7,"检查连接证书");
            zoneValue.Text=TimeZoneInfo.Local.DisplayName;
            netTab.Controls.Add(rows);
            var browserRows=new TableLayoutPanel { ColumnCount=2, RowCount=10, Dock=DockStyle.Fill, Margin=Padding.Empty };
            browserRows.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,180)); browserRows.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            clientValue=AddRow(browserRows,0,"检测环境"); platformValue=AddRow(browserRows,1,"平台与浏览器 UA");
            browserZoneValue=AddRow(browserRows,2,"浏览器时区"); automationValue=AddRow(browserRows,3,"自动化标志");
            rtcValue=AddRow(browserRows,4,"WebRTC 候选"); routeValue=AddRow(browserRows,5,"HTTP / WebRTC");
            rendererValue=AddRow(browserRows,6,"WebGL 渲染器"); canvasValue=AddRow(browserRows,7,"本地绘图指纹");
            displayValue=AddRow(browserRows,8,"显示与硬件参数"); changesValue=AddRow(browserRows,9,"与上次环境比较");
            clientValue.Text="程序内置 WebView2"; hints.SetToolTip(clientValue,BrowserChecks.ClientDescription());
            foreach(var label in new [] {platformValue,browserZoneValue,automationValue,rtcValue,routeValue,rendererValue,canvasValue,displayValue,changesValue}) label.Text="点击“检查全部”测量";
            browserTab.Controls.Add(browserRows); root.Controls.Add(tabs,0,3);
            var options=new FlowLayoutPanel { Dock=DockStyle.Fill, Margin=Padding.Empty, Padding=new Padding(0,12,0,0), WrapContents=false };
            monitor=new CheckBox { Text="每 60 秒检查一次", AutoSize=true, Margin=new Padding(0,0,25,0) };
            showIp=new CheckBox { Text="显示完整 IP", AutoSize=true };
            showIp.CheckedChanged += delegate { RefreshValues(); };
            options.Controls.Add(monitor); options.Controls.Add(showIp); root.Controls.Add(options,0,4);
            var actions=new FlowLayoutPanel { Dock=DockStyle.Fill, Margin=Padding.Empty, WrapContents=false, Padding=new Padding(0,4,0,0) };
            checkButton=MakeButton("检查全部",125,true); acknowledgeButton=MakeButton("确认网络变化",145,false); desktopButton=MakeButton("打开桌面版",145,false);
            checkButton.Click += async delegate { await RunCheck(true); };
            acknowledgeButton.Click += delegate {
                if (last == null || !last.Connected || (DateTime.UtcNow-last.CheckedUtc).TotalSeconds>60) return;
                if(MessageBox.Show(this,"确认本次出口 IP 的变化来自你的操作？", "核对网络变化",MessageBoxButtons.YesNo,MessageBoxIcon.Question)!=DialogResult.Yes) return;
                try { settings.Remember(last); Storage.Save(settings); savingFailed=false; Storage.LoadError=null; UpdateGate(); }
                catch(Exception ex) { SaveError(ex); }
            };
            desktopButton.Click += async delegate { await OpenClaude(); };
            actions.Controls.Add(checkButton); actions.Controls.Add(acknowledgeButton); actions.Controls.Add(desktopButton); root.Controls.Add(actions,0,5);
            var note=new Label { Text="检查在主程序内完成，不另开浏览器窗口。\n定时检查只测网络；内置引擎结果见“浏览器环境”页。\n日志保存在程序旁的 data 文件夹，IP 默认遮盖。", Dock=DockStyle.Fill, ForeColor=Quiet, Margin=new Padding(0,14,0,0) };
            root.Controls.Add(note,0,6);
            var footer=new FlowLayoutPanel { Dock=DockStyle.Fill, FlowDirection=FlowDirection.LeftToRight, Margin=Padding.Empty, WrapContents=false };
            exportButton=MakeButton("导出检查记录",150,false);
            exportButton.Click += delegate { Export(); };
            var folderButton=MakeButton("查看本地记录",150,false);
            folderButton.Click += delegate { Directory.CreateDirectory(Storage.DirectoryPath); Process.Start("explorer.exe",Storage.DirectoryPath); };
            var timeButton=MakeButton("打开时间设置",150,false);
            timeButton.Click += delegate { Process.Start(new ProcessStartInfo("ms-settings:dateandtime") { UseShellExecute=true }); };
            footer.Controls.Add(exportButton); footer.Controls.Add(folderButton); footer.Controls.Add(timeButton); root.Controls.Add(footer,0,7);
            ticker.Interval=1000;
            ticker.Tick += async delegate { UpdateGate(); if (monitor.Checked && !busy && last != null && (DateTime.UtcNow-last.CheckedUtc).TotalSeconds>=60) await RunCheck(); };
            ticker.Start();
            FormClosed += delegate { ticker.Dispose(); hints.Dispose(); embeddedProbe.Dispose(); };
            Shown += async delegate {
                if(Storage.LoadError != null) { savingFailed=true; headline.Text="本地记录读取失败"; details.Text=Storage.LoadError; }
                if(capturePath != null) {
                    await RunCheck(true);
                    using(var bitmap=new Bitmap(Width,Height)) { DrawToBitmap(bitmap,new Rectangle(0,0,Width,Height)); bitmap.Save(capturePath); }
                    tabs.SelectedIndex=1;
                    using(var bitmap=new Bitmap(Width,Height)) { DrawToBitmap(bitmap,new Rectangle(0,0,Width,Height)); bitmap.Save(Path.ChangeExtension(capturePath,"browser.png")); }
                    Storage.WriteJson(Path.ChangeExtension(capturePath,"json"),Checks.Report(last));
                    Close();
                }
            };
            UpdateGate();
        }
        Label AddRow(TableLayoutPanel table,int row,string name) {
            table.RowStyles.Add(new RowStyle(SizeType.Percent,100F/table.RowCount));
            var caption=new Label { Text=name, ForeColor=Quiet, Dock=DockStyle.Fill, TextAlign=ContentAlignment.MiddleLeft, Margin=Padding.Empty };
            var value=new Label { Text="—", Dock=DockStyle.Fill, TextAlign=ContentAlignment.MiddleLeft, Margin=Padding.Empty, AutoEllipsis=true };
            table.Controls.Add(caption,0,row); table.Controls.Add(value,1,row);
            caption.Paint += delegate(object sender,PaintEventArgs e) { using(var pen=new Pen(Rule)) e.Graphics.DrawLine(pen,0,caption.Height-1,caption.Width,caption.Height-1); };
            value.Paint += delegate(object sender,PaintEventArgs e) { using(var pen=new Pen(Rule)) e.Graphics.DrawLine(pen,0,value.Height-1,value.Width,value.Height-1); };
            return value;
        }
        Button MakeButton(string text,int width,bool primary) {
            var b=new Button { Text=text, Width=width, Height=38, FlatStyle=FlatStyle.Flat, BackColor=primary?Ink:Paper, ForeColor=primary?Paper:Ink, Margin=new Padding(0,0,9,0), Cursor=Cursors.Hand, UseVisualStyleBackColor=false };
            b.FlatAppearance.BorderColor=primary?Ink:Rule;
            return b;
        }
        async Task RunCheck(bool includeBrowser=false) {
            if(busy) return;
            busy=true; headline.Text="正在检查环境"; details.Text="正在查询连接、系统时间、DNS 与代理配置…"; UpdateGate();
            BrowserSnapshot prior=last==null?null:last.Browser;
            string[] priorChanges=last==null?null:last.BrowserChanges;
            last=await Task.Run(()=>Checks.Run());
            last.Browser=prior; last.BrowserChanges=priorChanges;
            if(includeBrowser && !IsDisposed) {
                details.Text="正在主程序内测量浏览器引擎与网络环境…";
                last.Browser=await BrowserChecks.Run(embeddedProbe,Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"BrowserProbe.html"),45);
                if(last.Browser.Succeeded) {
                    last.BrowserChanges=BrowserChecks.Changed(settings.PreviousBrowser,last.Browser).ToArray();
                    settings.PreviousBrowser=new JavaScriptSerializer().Deserialize<BrowserSnapshot>(new JavaScriptSerializer().Serialize(last.Browser));
                    settings.PreviousBrowser.HttpIp=null; settings.PreviousBrowser.WebRtcIps=new string[0];
                }
            }
            try {
                bool changed=last.Connected && !string.IsNullOrEmpty(settings.Baseline(last)) && settings.Baseline(last)!=last.Fingerprint;
                Storage.Append(last,changed);
                if(last.Connected && string.IsNullOrEmpty(settings.Baseline(last)) && Storage.LoadError==null) { settings.Remember(last); Storage.Save(settings); }
                else if(includeBrowser && last.Browser!=null && last.Browser.Succeeded && Storage.LoadError==null) Storage.Save(settings);
                savingFailed=Storage.LoadError != null;
            } catch(Exception ex) { SaveError(ex); }
            busy=false;
            if(IsDisposed) return;
            RefreshValues(); UpdateGate();
        }
        void SaveError(Exception ex) { savingFailed=true; headline.Text="本地记录保存失败"; details.Text=ex.Message; }
        void RefreshValues() {
            if(last==null) return;
            networkValue.Text=last.Connected ? "HTTPS 已连接 · " + Math.Round(last.RoundTripSeconds*1000) + " ms" : "连接失败";
            bool changed=last.Connected && !string.IsNullOrEmpty(settings.Baseline(last)) && settings.Baseline(last)!=last.Fingerprint;
            ipValue.Text=last.Connected ? (showIp.Checked?last.Ip:Checks.Mask(last.Ip)) + (changed?"  /  与上次确认不同":"  /  已记录") : "未取得";
            clockValue.Text=last.Connected ? Math.Abs(last.ClockOffsetSeconds).ToString("0.0") + " 秒（近似值）" : "未取得";
            zoneValue.Text=last.TimeZone; proxyValue.Text=last.ProxyConfig ?? "未取得";
            hints.SetToolTip(proxyValue,last.Proxy??"");
            dnsValue.Text=last.Dns ?? "未检查"; certificateValue.Text=last.Certificate ?? "未取得证书";
            stampValue.Text=last.CheckedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss zzz");
            var b=last.Browser;
            if(b==null) return;
            if(!b.Succeeded) {
                foreach(var label in new [] {platformValue,browserZoneValue,automationValue,rtcValue,routeValue,rendererValue,canvasValue,displayValue}) label.Text="—";
                changesValue.Text=b.Error; hints.SetToolTip(changesValue,b.Error); return;
            }
            clientValue.Text=b.MeasurementSource+" "+b.RuntimeVersion;
            platformValue.Text=(b.ClientPlatform??b.Platform)+" / "+b.UserAgent;
            hints.SetToolTip(platformValue,"HTTP UA："+b.HttpUserAgent+"\nJavaScript UA："+b.UserAgent);
            browserZoneValue.Text=b.TimeZone+" / UTC"+(b.OffsetMinutes>=0?"+":"")+(b.OffsetMinutes/60.0).ToString("0.##")+" / "+b.CheckedAt.Substring(11,8);
            automationValue.Text="navigator.webdriver = "+b.Webdriver.ToString().ToLowerInvariant()+" / "+(b.UserAgent==b.HttpUserAgent?"HTTP 与脚本 UA 相同":"HTTP 与脚本 UA 不同");
            rtcValue.Text="主机 "+b.HostCandidates+" / 公网映射 "+b.ServerCandidates+" / 中继 "+b.RelayCandidates+" / "+b.WebRtcState;
            routeValue.Text=BrowserChecks.RoutingSummary(b,last,showIp.Checked); hints.SetToolTip(routeValue,routeValue.Text);
            rendererValue.Text=b.WebGL; hints.SetToolTip(rendererValue,b.WebGL);
            canvasValue.Text=string.IsNullOrEmpty(b.CanvasHash)?"未返回绘图摘要":b.CanvasHash.Substring(0,Math.Min(24,b.CanvasHash.Length))+"…（SHA-256）";
            displayValue.Text=b.Screen+" / CPU 逻辑线程 "+b.CpuThreads;
            changesValue.Text=last.BrowserChanges==null || last.BrowserChanges.Length==0?"已记录 / 未发现参数变化":string.Join("、",last.BrowserChanges);
            hints.SetToolTip(changesValue,changesValue.Text);
        }
        void UpdateGate() {
            string block=Checks.BlockReason(last,settings,DateTime.UtcNow,busy);
            if(savingFailed) block="本地记录异常，请检查 data 文件夹后重启工具";
            desktopButton.Enabled=(block==null);
            checkButton.Enabled=!busy;
            acknowledgeButton.Enabled=!busy && !savingFailed && last!=null && last.Connected && !string.IsNullOrEmpty(settings.Baseline(last)) && settings.Baseline(last)!=last.Fingerprint && (DateTime.UtcNow-last.CheckedUtc).TotalSeconds<=60;
            exportButton.Enabled=last!=null && !busy;
            if(busy) { headline.ForeColor=Quiet; return; }
            headline.ForeColor=block==null?Accent:Alert;
            headline.Text=block==null?"连接检查完成":block;
            if(!savingFailed) details.Text=last==null?"点击“检查全部”获取当前结果。":!last.Connected?last.Error:block==null?(last.Browser!=null && last.Browser.Succeeded?"网络与内置引擎结果已记录，可以打开 Claude。":"网络结果已记录，可以打开 Claude。其他项目请点“检查全部”。"):block=="出口 IP 与已记录地址不同"?"连接正常。完整 IP 已改变，确认网络变化后可继续。":"处理上述项目后，再检查一次。";
            RefreshValues();
        }
        async Task OpenClaude() {
            await RunCheck();
            if(savingFailed || Checks.BlockReason(last,settings,DateTime.UtcNow,busy)!=null) return;
            try {
                Process.Start("explorer.exe",@"shell:AppsFolder\"+BrowserChecks.ClaudeAppId);
            } catch(Exception ex) { MessageBox.Show(this,"未能打开 Claude："+ex.Message,"打开失败",MessageBoxButtons.OK,MessageBoxIcon.Information); }
        }
        void Export() {
            if(last==null) return;
            using(var dialog=new SaveFileDialog { Title="导出本次检查", Filter="JSON 检查记录|*.json", FileName="claude-check-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+".json" }) {
                if(dialog.ShowDialog(this)!=DialogResult.OK) return;
                try { Storage.WriteJson(dialog.FileName,Checks.Report(last)); MessageBox.Show(this,"检查记录已导出。","导出完成"); }
                catch(Exception ex) { MessageBox.Show(this,ex.Message,"导出失败"); }
            }
        }
    }
    static class Program {
        static int assertions;
        static void Assert(bool condition,string name) { assertions++; if(!condition) throw new Exception("FAILED: "+name); }
        static int Test(string path) {
            var now=new DateTime(2026,10,28,0,0,0,DateTimeKind.Utc);
            var epoch=(now-new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc)).TotalSeconds.ToString(CultureInfo.InvariantCulture);
            var good=Checks.Parse("ip=203.0.113.17\nts="+epoch+"\n",now,now.AddSeconds(1));
            var settings=new Settings(); settings.Remember(good);
            Assert(Checks.BlockReason(good,settings,now.AddSeconds(2),false)==null,"fresh connection opens gate");
            Assert(Checks.BlockReason(null,settings,now,false)!=null,"no scan blocked");
            Assert(Checks.BlockReason(good,settings,now,true)!=null,"busy blocked");
            Assert(Checks.BlockReason(good,settings,now.AddSeconds(62),false)!=null,"stale scan blocked");
            Assert(Checks.BlockReason(good,settings,now.AddSeconds(-10),false)!=null,"clock rollback blocked");
            var other=new Settings { IPv4Fingerprint="different" };
            Assert(Checks.BlockReason(good,other,now.AddSeconds(2),false)!=null,"network change blocked");
            other.Remember(good);
            Assert(Checks.BlockReason(good,other,now.AddSeconds(2),false)==null,"acknowledged change opens gate");
            good.Connected=false; Assert(Checks.BlockReason(good,settings,now,false)!=null,"offline blocked"); good.Connected=true;
            good.ClockOffsetSeconds=301; Assert(Checks.BlockReason(good,settings,now,false)!=null,"clock drift blocked");
            good.ClockOffsetSeconds=-301; Assert(Checks.BlockReason(good,settings,now,false)!=null,"negative clock drift blocked"); good.ClockOffsetSeconds=0;
            good.RoundTripSeconds=11; Assert(Checks.BlockReason(good,settings,now,false)!=null,"slow response blocked"); good.RoundTripSeconds=1;
            Assert(Checks.Mask("203.0.113.17")=="203.0.*.*","IPv4 redaction");
            Assert(!Checks.Mask("2001:db8::1").Contains("::1"),"IPv6 redaction");
            Assert(Checks.Mask(null)=="未取得","missing IP handled");
            var ipv6=Checks.Parse("ip=2001:db8::1\nts="+epoch,now,now.AddSeconds(1));
            Assert(Checks.BlockReason(ipv6,settings,now.AddSeconds(2),false)==null,"first IPv6 address independent of IPv4");
            settings.Remember(ipv6);
            Assert(Checks.BlockReason(good,settings,now.AddSeconds(2),false)==null,"IPv4 baseline survives IPv6 switch");
            var changedV6=Checks.Parse("ip=2001:db8::2\nts="+epoch,now,now.AddSeconds(1));
            Assert(Checks.BlockReason(changedV6,settings,now.AddSeconds(2),false)!=null,"same-family IPv6 change blocked");
            bool threw=false; try { Checks.Parse("ip=bad\nts="+epoch,now,now); } catch(FormatException) { threw=true; } Assert(threw,"invalid IP rejected");
            threw=false; try { Checks.Parse("ip=203.0.113.17\nts=NaN",now,now); } catch(FormatException) { threw=true; } Assert(threw,"nonfinite timestamp rejected");
            var saved=Storage.DirectoryPath;
            Storage.DirectoryPath=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(path)),"test-state-"+Guid.NewGuid().ToString("N"));
            Storage.Save(settings); var read=Storage.Load(); Assert(read.Baseline(good)==good.Fingerprint && read.Baseline(ipv6)==ipv6.Fingerprint,"dual-stack baseline round trip");
            Storage.Append(good,false);
            var text=File.ReadAllText(Directory.GetFiles(Storage.DirectoryPath,"*.jsonl")[0]);
            Assert(!text.Contains("203.0.113.17"),"journal redacts IP");
            var browser=new BrowserSnapshot { Succeeded=true,UserAgent="Edge test",HttpUserAgent="Edge test",Platform="Win32",ClientPlatform="Windows",TimeZone="Asia/Tokyo",OffsetMinutes=540,WebGL="test-renderer",CanvasHash="abc123",Screen="1920x1080",CpuThreads=8,HttpIp="203.0.113.17",WebRtcIps=new [] {"2001:db8::1"} };
            BrowserChecks.Validate(browser);
            var browserJson=new JavaScriptSerializer().Serialize(BrowserChecks.Report(browser,false));
            Assert(!browserJson.Contains("203.0.113.17") && !browserJson.Contains("2001:db8::1"),"browser report redacts HTTP and WebRTC addresses");
            Assert(BrowserChecks.Changed(browser,browser).Count==0,"same browser environment unchanged");
            var nextBrowser=new JavaScriptSerializer().Deserialize<BrowserSnapshot>(new JavaScriptSerializer().Serialize(browser)); nextBrowser.WebGL="new-renderer";
            Assert(BrowserChecks.Changed(browser,nextBrowser).Count==1,"render environment change detected");
            Assert(BrowserChecks.SourceValid("https://preflight.invalid/check?session=secret","https://preflight.invalid/check?session=secret"),"embedded result exact source accepted");
            Assert(!BrowserChecks.SourceValid("https://evil.invalid/check?session=secret","https://preflight.invalid/check?session=secret"),"embedded result external source rejected");
            Assert(!BrowserChecks.SourceValid("https://preflight.invalid/check?session=other","https://preflight.invalid/check?session=secret"),"embedded result other session rejected");
            nextBrowser.MeasurementSource="different engine";
            Assert(BrowserChecks.Changed(browser,nextBrowser).Count==1 && BrowserChecks.Changed(browser,nextBrowser)[0]=="检测环境已更新","separate engine baselines not compared as fingerprint changes");
            nextBrowser.HttpIp="not-an-ip"; threw=false; try { BrowserChecks.Validate(nextBrowser); } catch(FormatException) { threw=true; } Assert(threw,"browser invalid IP rejected");
            var failedJson=new JavaScriptSerializer().Serialize(BrowserChecks.Report(new BrowserSnapshot {Succeeded=false,Error="timeout"},false));
            Assert(!failedJson.Contains("webdriver") && failedJson.Contains("timeout"),"failed browser measurement omits synthetic values");
            File.WriteAllText(Path.Combine(Storage.DirectoryPath,"settings.json"),"invalid json"); Storage.Load(); Assert(Storage.LoadError!=null,"corrupt state detected");
            Storage.DirectoryPath=saved;
            Storage.WriteJson(path,new { passed=assertions, failed=0, framework=Environment.Version.ToString(), checkedUtc=DateTime.UtcNow.ToString("o") });
            return 0;
        }
        [STAThread]
        static int Main(string[] args) {
            try {
                if(args.Length==2 && args[0]=="--self-test") return Test(args[1]);
                if(args.Length==2 && args[0]=="--diagnose") { var scan=Checks.Run(); Storage.WriteJson(args[1],Checks.Report(scan)); return scan.Connected?0:2; }
                string capture=null;
                if(args.Length==2 && args[0]=="--capture") { capture=Path.GetFullPath(args[1]); Storage.DirectoryPath=Path.Combine(Path.GetDirectoryName(capture),"capture-data"); }
                Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm(capture)); return 0;
            } catch(Exception ex) {
                if(args.Length==2) { File.WriteAllText(args[1]+".error.txt",ex.ToString(),Encoding.UTF8); return 1; }
                MessageBox.Show(ex.Message,"启动失败",MessageBoxButtons.OK,MessageBoxIcon.Error); return 1;
            }
        }
    }
}
