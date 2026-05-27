# SSLClaw v1.1.1 架构清单

## 一、项目基本信息

- 仓库：DiskClaw/SSLClaw，分支 master
- 版本：v1.1.1
- 语言：C++ (Win32 API)，无第三方框架依赖
- 编译：MSBuild v145 平台工具集（VS18: `C:\Program Files\Microsoft Visual Studio\18\Community\`）
- GitHub Actions：.github/workflows/build.yml，tag v* 触发编译+发布
- 本地图标脚本：_make_icon.ps1
- ICO 路径：C:\Users\YUN\Desktop\SSLClaw\SSLClaw.ico

## 二、源码文件结构（共 6019 行）

| 文件 | 行数 | 大小 | 职责 |
|------|------|------|------|
| main.cpp | 179 | 7.3 KB | 入口：单实例检测、COM/WinSock 初始化、配置加载、主消息循环、异常过滤器 |
| ssl_acme.cpp | 300 | 15.8 KB | ACME 协议：账户密钥生成/加载、JWK 构建、JWS 签名、AcmePost 请求 |
| ssl_core.cpp | 796 | 44.8 KB | 核心申请流程：ApplyThread 主逻辑、HTTP-01/DNS-01 验证、CSR 构建、证书获取与部署 |
| ssl_deploy.cpp | 153 | 8.3 KB | 部署模块：PFX 导出（瞬态 NCrypt 密钥 + CERT_KEY_CONTEXT_PROP_ID 关联） |
| ssl_dnsapi.cpp | 496 | 23.9 KB | DNS API：阿里云/腾讯云/Cloudflare TXT 记录操作、权威服务器预验证 |
| ssl_http.cpp | 248 | 13.7 KB | HTTP：WinHttp 封装、临时 HTTP 服务器（端口 80 占用检测）、自检 |
| ssl_keyfmt.cpp | 282 | 10.7 KB | 密钥格式：BCRYPT_RSAFULLPRIVATE_BLOB → PKCS#1/PKCS#8 PEM 转换 |
| ssl_renewal.cpp | 1321 | 63.5 KB | 续签系统：后台线程、续签记录持久化、指数退避重试、IIS 自动部署、邮件通知 |
| ssl_ui.cpp | 1799 | 90.3 KB | UI：窗口创建、控件布局、事件处理、托盘图标、DNS API 配置对话框、续签列表管理 |
| ssl_utils.cpp | 445 | 22.4 KB | 工具：编码转换、B64 编码、JSON 提取、GUID 生成、AES 加密、DPAPI 保护、邮件发送 |

## 三、头文件

| 文件 | 职责 |
|------|------|
| ssl_core.h | 全局状态声明、ACME 目录 URL、续签记录结构体、DNS API 接口声明、证书查询接口 |
| ssl_ui.h | 控件句柄声明、状态栏 IP 轮播、安全 UI 操作宏、DNS 配置加载/保存 |
| ssl_keyfmt.h | 密钥格式转换函数声明（PKCS#1/PKCS#8 互转） |

## 四、核心数据结构

### RenewalRecord（续签记录）

```cpp
struct RenewalRecord {
    std::wstring domain;        // 域名
    bool wildcard = false;      // 通配符标志
    int serverType = 0;         // 服务器类型索引
    int verifyMode = 0;         // 验证方式 0=HTTP-01, 1=DNS-01
    std::wstring webRoot;       // 网站目录
    std::wstring saveDir;       // 保存目录
    std::wstring email;         // 邮箱
    bool autoRenew = false;     // 自动续签
    std::wstring thumbprint;     // 证书指纹
    std::wstring friendlyName;   // 友好名称
    FILETIME issueTime = {};    // 签发时间
    FILETIME expiryTime = {};   // 过期时间
    int renewalDays = 60;       // 提前续签天数
    std::wstring preScript;     // 前置脚本
    std::wstring postScript;    // 后置脚本
    int dnsProvider = 0;        // DNS 提供商
    std::wstring dnsApiId;      // [运行时填充，不持久化]
    std::wstring dnsApiSecret;  // [运行时填充，不持久化]
};
```

### 全局状态

- `g_AccKey`：ACME 账户密钥句柄（BCRYPT_KEY_HANDLE）
- `g_AccPubB64`、`g_AccExpB64`：账户公钥指数/模数的 Base64Url 编码
- `g_AccURL`：账户 URL
- `g_IniPath`：配置文件路径（exe 同目录 sslclaw.ini）
- `g_LogFilePath`：日志文件路径
- `g_SaveDir`：默认证书保存目录
- `g_WebRoot`：HTTP-01 验证的网站根目录
- `g_CAIndex`：CA 选择（0=Let's Encrypt，1=Let's Encrypt Staging）
- `g_AcmeBusyFlag`：ACME 操作互斥锁（原子操作）
- `g_RenewingDomains`：正在续签的域名集合

## 五、主要功能模块

### 1. 证书申请流程（ApplyThread）

- 入口：点击"申请"按钮
- 参数：域名、邮箱、服务器类型、验证方式、保存目录、续签天数、CA 环境
- HTTP-01 验证：检测端口 80 是否空闲 → 启动临时 HTTP 服务器 → 等待 ACME 验证
- DNS-01 验证：调用 DNS API 创建 TXT 记录 → 权威服务器预验证 → 等待 ACME 验证 → 清理 TXT 记录
- CSR 生成：BCryptGenerateKeyPair → BuildCSR（支持 SAN 扩展）
- 证书获取：AcmePost 请求 order → finalize → download
- 部署：保存 PEM 文件 → 生成 PFX → 导入 Certificate Store → 绑定 IIS 站点
- 续签记录：自动创建或更新 RenewalRecord

### 2. 续签系统

- 后台线程：`RenewalCheckThread`，每 6 小时检查一次
- 续签判断：`GetRenewalsDue`，比较 `expiryTime - renewalDays` 与当前时间
- 重试机制：指数退避，最大重试间隔 24 小时
- 持久化：续签记录存于 `sslclaw.ini` 的 `[RenewalList]` 节
- CLI 模式：`--renew` 参数启动命令行续签
- 邮件通知：续签成功/失败发送邮件（需配置 SMTP）

### 3. DNS API 自动化

- 支持提供商：阿里云、腾讯云、Cloudflare
- 接口函数：`DnsCreateTxtRecord`、`DnsDeleteTxtRecord`、`DnsFindZone`
- 预验证：`DnsPreValidateAuthoritative`，递归查询 NS 记录，直接向权威 DNS 查询 TXT
- 配置存储：每个域名独立 DNS API 配置，存于 `[DNS_xxx]` 节，密钥用 DPAPI 加密

### 4. IIS 部署

- Certificate Store：导入到 `MY` 存储（Personal）
- 绑定：自动查找 IIS 站点，设置 HTTPS 绑定
- 指纹：返回证书指纹用于续签记录

### 5. UI 模块

- 主窗口：固定大小 480×560，无最大化/最小化/调整大小
- 控件：域名输入、邮箱输入、服务器类型下拉、验证方式下拉、保存目录、CA 环境切换、通配符复选框、日志区域、状态栏
- 状态栏：左侧状态文字，右侧本机 IP 轮播（多网卡时 5 秒切换，点击可复制）
- 托盘图标：最小化到托盘，右键菜单
- 续签窗口：列表显示续签记录，支持手动续签、删除、编辑
- DNS 配置对话框：选择 DNS 提供商，输入 API 密钥

## 六、关键函数清单

### ssl_acme.cpp

- `MakeAccountKey()`：生成 2048 位 RSA 账户密钥
- `LoadAccountKey(path)`：从 PEM 文件加载账户密钥
- `ExtractPublicKey()`：提取公钥指数/模数
- `MakeJWK()`：构建 JWK JSON
- `AccThumbprint()`：计算账户指纹
- `SignJWS(payload, nonce, url, useJWK)`：JWS 签名（RSA-SHA256）
- `AcmePost(url, payload, nonce, useJWK, outLocation, outStatus)`：ACME POST 请求

### ssl_core.cpp

- `ApplyThreadInner()`：申请流程核心逻辑
- `BuildCSR(domain, key, extraSans)`：生成 CSR（支持多域名 SAN）
- `EnsureCertChain(certPem)`：确保 PEM 包含完整链

### ssl_deploy.cpp

- `SavePFX(dk, certPem, pfxPath)`：生成 PFX 文件（瞬态密钥导入）

### ssl_dnsapi.cpp

- `DnsCreateTxtRecord()`：创建 TXT 记录
- `DnsDeleteTxtRecord()`：删除 TXT 记录
- `DnsFindZone()`：查找域名对应的 DNS Zone
- `DnsPreValidateAuthoritative()`：权威服务器预验证

### ssl_http.cpp

- `HttpJson()`：WinHttp 封装
- `IsPort80Free()`：检测端口 80 占用
- `StartTempHttpServer()`：启动临时 HTTP 服务器
- `StopTempHttpServer()`：停止临时 HTTP 服务器

### ssl_renewal.cpp

- `LoadRenewalRecords()`：加载续签记录
- `SaveRenewalRecords()`：保存续签记录
- `GetRenewalsDue()`：获取需续签的记录索引
- `PerformRenewal()`：执行单个续签
- `PerformRenewalWithRetry()`：带重试的续签
- `StartRenewalBackgroundThread()`：启动后台续签线程
- `StopRenewalBackgroundThread()`：停止后台续签线程

### ssl_ui.cpp

- `WndProc()`：主窗口消息处理
- `RenewWndProc()`：续签窗口消息处理
- `Log()`：日志输出
- `SetStatus()`：设置状态栏文字
- `ShowDnsConfigDialog()`：显示 DNS 配置对话框
- `SyncWebRootVis()`：同步 WebRoot 控件可见性

### ssl_utils.cpp

- `W2A()`、`A2W()`：编码转换
- `B64Url()`、`B64Pem()`：Base64 编码
- `Sha256B64()`：SHA-256 Base64Url
- `JsonStr()`：JSON 字符串提取
- `NewGuid()`：生成 GUID
- `ProtectString()`、`UnprotectString()`：DPAPI 加密/解密
- `EnsureIniUtf16()`：确保 INI 文件为 UTF-16 LE BOM

## 七、配置文件（sslclaw.ini）

- 位置：exe 同目录
- 编码：UTF-16 LE BOM（程序启动时强制转换）
- 节点：
  - `[SSLClaw]`：主配置（Domain、Email、ServerType、SaveDir、VerifyMode、WebRoot、Wildcard）
  - `[Account]`：账户 URL（持久化）
  - `[DNS_xxx]`：各域名的 DNS API 配置（Provider、ApiId、ApiSecret 加密存储）
  - `[RenewalList]`：续签记录列表

## 八、已知问题与待实现

### 头文件空头声明（ssl_core.h）

以下函数已声明但未实现：
- `DeployToIIS()`：IIS 部署函数
- `BindCertToIIS()`：IIS 绑定函数
- `EnsureCertChain()`：证书链处理
- `RevokeCertificate()`：证书吊销
- `ScanAllCertificates()`：证书扫描
- `GetAvailableDnsProviders()`：DNS 提供商列表
- `GetRenewalIniPath()`：续签配置路径（静态版本在 ssl_renewal.cpp）

> 注：`GetRenewalsDue()` 已在 ssl_renewal.cpp 实现（非静态），但头文件声明为非静态，存在链接不一致风险。

### 未解决 BUG

- 无已知未解决 BUG（状态栏 IP 显示已在 v1.1.1 修复：改用 `GetAdaptersAddresses`，移除了 `gethostbyname` 备用方案，中文字符串已正确显示）

## 九、版本历史要点

- v1.0：基础证书申请功能
- v1.1：增加续签系统、DNS-01 支持
- v1.2：修复续签崩溃（临界区初始化）
- v1.1.1：
  - 新增正式/测试环境切换按钮
  - 修复 EnterCriticalSection 崩溃（静态初始化临界区）
  - 修复状态栏卡住
  - 修复续签锁冲突
  - 修复证书过期时间读取
  - UI 教程/日志分离
  - 删除自动重载代码改用 postScript 字段
  - 蓝色向下箭头+白色 S 字母图标
  - 状态栏 IP 显示修复

## 十、编译与发布

- 本地编译：`msbuild SSLClaw.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145`
- GitHub Actions：tag v* 自动触发构建发布
- 发布包：SSLClaw_<tag>.zip（仅含 SSLClaw.exe）

---

*清单生成时间：2026-05-27*
