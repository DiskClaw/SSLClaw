// ssl_core.cpp - SSL 证书核心（精简版：仅全局状态 + 交互式申请线程）
// 其他功能已拆分到独立模块
#include "ssl_core.h"
#include "ssl_keyfmt.h"

// 链接库
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dnsapi.lib")

// TLS 1.3 兼容性
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

// ── 外部模块函数声明 ──
extern bool LoadAccountKey(const std::string& path);
extern bool MakeAccountKey();
extern bool ExtractPublicKey();
extern void SavePKEY(const std::string& path);
extern std::string AccThumbprint();
extern std::vector<BYTE> BuildCSR(const std::string& domain, BCRYPT_KEY_HANDLE key, const std::vector<std::string>* extraSans);
extern std::string AcmePost(const std::string& urlStr, const std::string& payload, std::string& nonce, bool useJWK, std::string* outLocation, DWORD* outStatus);
extern std::string HttpJson(const wchar_t* url, const wchar_t* method, const char* body, int bodyLen, std::string* outNonce, std::string* outLocation, DWORD* outStatusCode);
extern std::string JsonStr(const std::string& json, const char* key);
extern std::string B64UrlS(const std::string& s);
extern std::string B64Pem(const std::vector<BYTE>& d);
extern std::string W2A(const std::wstring& w);
extern std::wstring A2W(const std::string& a);
extern std::string Sha256B64(const std::string& data);
extern bool WriteFileAtomic(const std::string& path, const std::string& content);
extern bool IsPort80Free();
extern bool StartTempHttpServer(const std::string& token, const std::string& keyAuth);
extern void StopTempHttpServer();

// DNS API 模块
extern bool DnsTxtExists(const std::wstring& queryName);
extern std::wstring DnsCreateTxtRecord(int provider, const std::wstring& apiId, const std::wstring& apiSecret, const std::wstring& domain, const std::wstring& subDomain, const std::wstring& value);
extern std::wstring DnsDeleteTxtRecord(int provider, const std::wstring& apiId, const std::wstring& apiSecret, const std::wstring& domain, const std::wstring& subDomain);
extern std::wstring DnsFindZone(int provider, const std::wstring& apiId, const std::wstring& apiSecret, const std::wstring& recordName, std::wstring& outZone, std::wstring& outSubDomain);

// 部署模块
extern bool SavePFX(BCRYPT_KEY_HANDLE dk, const std::string& certPem, const std::wstring& pfxPath);

// 续签模块
extern void SendNotificationEmail(const std::wstring& subject, const std::wstring& body, const std::wstring& saveDir, const std::wstring& iniPath);
extern void SaveRenewalRecord(const RenewalRecord& rec);
extern bool DnsPreValidateAuthoritative(const std::wstring& queryName, const std::wstring& expectedValue, int maxRetries, int retryInterval);

// 全局状态
extern void Log(const wchar_t* fmt, ...);
BCRYPT_KEY_HANDLE g_AccKey = NULL;
std::string g_AccPubB64, g_AccExpB64;
std::string g_AccURL;
bool g_Running = false;
bool g_AutoScroll = false;
HANDLE g_hDnsReady = NULL;
std::wstring g_WebRoot;
int g_CAIndex = 0;
std::string g_AcmeNonce;
std::wstring g_LogFilePath;

// 线程同步
CRITICAL_SECTION g_cs;
struct _CsInit { _CsInit() { InitializeCriticalSection(&g_cs); } ~_CsInit() { DeleteCriticalSection(&g_cs); } } _cs_init;

// CA 机构目录 URL（根据 g_CAIndex 选择生产/测试）
const wchar_t* GetAcmeDirectory() {
    if (g_CAIndex == CA_LE_STAGING)
        return L"https://acme-staging-v02.api.letsencrypt.org/directory";
    return L"https://acme-v02.api.letsencrypt.org/directory";
}

const wchar_t* GetAcmeStagingDirectory() {
    return L"https://acme-staging-v02.api.letsencrypt.org/directory";
}

const wchar_t* GetAccountKeySuffix() {
    return L"_le";
}

// ── 证书申请线程（UI 驱动） ──
extern void SetStatus(const wchar_t* t);
extern HWND g_hWnd;
extern HWND g_hDomain, g_hEmail, g_hSaveDirEdit, g_hServer, g_hBtnApply, g_hVerifyMode, g_hDaysEdit;
extern HWND g_hWildcard;
extern std::wstring g_SaveDir;
extern int g_DnsProvider;
extern std::wstring g_DnsApiId;
extern std::wstring g_DnsApiSecret;
extern void LoadDnsConfigForDomain(const std::wstring& domain);

static unsigned ApplyThreadInner() {
    const int MAX_DOMAIN_LEN = 256;
    wchar_t td[MAX_DOMAIN_LEN]; 
    int domainLen = GetWindowTextW(g_hDomain, td, MAX_DOMAIN_LEN);
    if (domainLen >= MAX_DOMAIN_LEN - 1) {
        SetStatus(L"域名过长(最大255字符)");
        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
    }
    wchar_t* p = td; while (*p == L' ') p++; std::wstring wd = p;
    while (!wd.empty() && wd.back() == L' ') wd.pop_back();
    if (wd.empty()) { SetStatus(L"域名不能为空"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }

    int verifyMode = (int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0);
    bool isWild = g_hWildcard && (SendMessageW(g_hWildcard, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (isWild) {
        if (verifyMode == 0) {
            Log(L"[错误] 通配符证书仅支持 DNS-01 验证方式");
            SetStatus(L"通配符需 DNS-01");
            EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        if (wd.size() < 2 || wd[0] != L'*') wd = L"*." + wd;
    }

    wchar_t em[256]; GetWindowTextW(g_hEmail, em, 256);
    std::wstring email; p = em; while (*p == L' ') p++; email = p;
    while (!email.empty() && email.back() == L' ') email.pop_back();

    wchar_t dtx[MAX_PATH]; GetWindowTextW(g_hSaveDirEdit, dtx, MAX_PATH);
    if (dtx[0]) g_SaveDir = dtx;
    if (g_SaveDir.empty()) { SetStatus(L"保存目录不能为空"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }

    std::wstring nt = wd;
    if (nt.size() >= 2 && nt[0] == L'*' && nt[1] == L'.') nt = L"wildcard." + nt.substr(2);
    for (wchar_t& c : nt) if (c == L'/' || c == L'\\' || c == L':' || c == L'*' || c == L'?' || c == L'"' || c == L'<' || c == L'>' || c == L'|') c = '_';
    // 限制文件名长度，防止超长文件名导致的问题
    if (nt.size() > 200) nt = nt.substr(0, 200);

    int si = (int)SendMessageW(g_hServer, CB_GETCURSEL, 0, 0);
    std::wstring srv; const wchar_t* sn[] = { L"Apache (PEM PKCS#1)",L"Nginx (PEM PKCS#1)",L"IIS (PFX)",L"通用 (PEM PKCS#8)" };
    srv = sn[si < 4 ? si : 3];

    std::wstring verifyName = verifyMode == 0 ? L"HTTP-01" : L"DNS-01";
    g_CAIndex = 0;
    const wchar_t* caName = L"Let's Encrypt";
    EnableWindow(g_hBtnApply, FALSE);
    EnableWindow(g_hDaysEdit, FALSE);
    SetStatus(L"正在申请证书...");
    Log(L"----------------------------------------");
    Log(L"  域名: %s", wd.c_str());
    if (!email.empty()) Log(L"  邮箱: %s", email.c_str());
    Log(L"  CA: %s", caName);
    Log(L"  服务器: %s", srv.c_str());
    Log(L"  验证: %s", verifyName.c_str());
    Log(L"  目录: %s", g_SaveDir.c_str());
    Log(L"  文件: %s", nt.c_str());
    Log(L"----------------------------------------");

    // Step 1: 加载账户密钥
    SetStatus(L"加载帐户密钥...");
    Log(L"Step 1: 加载 ACME 帐户密钥...");
    std::string keyPath = W2A(g_SaveDir + L"\\acme_account" + GetAccountKeySuffix() + L".key");
    if (!LoadAccountKey(keyPath)) {
        Log(L"  未找到现有密钥，生成新密钥...");
        if (!MakeAccountKey()) {
            Log(L"[错误] 密钥生成失败"); SetStatus(L"失败");
            EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        SavePKEY(keyPath);
        Log(L"  新密钥已保存");
    } else {
        ExtractPublicKey();
        Log(L"  已加载现有账户密钥");
    }

    // Step 2: 获取 ACME 目录
    SetStatus(L"连接 CA 服务器...");
    Log(L"Step 2: 获取 ACME 目录 (%s)...", caName);
    g_AcmeNonce.clear();
    std::string dir = HttpJson(GetAcmeDirectory(), L"GET", NULL, 0, &g_AcmeNonce);
    std::string newAcct = JsonStr(dir, "newAccount");
    std::string newOrder = JsonStr(dir, "newOrder");
    if (dir.empty()) {
        Log(L"[错误] 无法连接 ACME 服务器"); SetStatus(L"失败");
        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
    }
    if (newAcct.empty() || newOrder.empty()) {
        Log(L"[错误] 无法解析 ACME 目录响应"); SetStatus(L"失败");
        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
    }
    auto getNonce = [&]() {
        g_AcmeNonce.clear();
        std::string nu = JsonStr(dir, "newNonce");
        if (nu.empty()) return;
        std::wstring wnu = A2W(nu);
        HttpJson(wnu.c_str(), L"HEAD", NULL, 0, &g_AcmeNonce);
        Log(L"  获取 Nonce: %s", A2W(g_AcmeNonce.substr(0, 32)).c_str());
    };
    if (g_AcmeNonce.empty()) getNonce();

    // Step 3: 注册 ACME 账户
    SetStatus(L"注册 ACME 帐户...");
    Log(L"Step 3: 注册帐户...");
    {
        std::string regBody = "{\"termsOfServiceAgreed\":true";
        if (!email.empty()) regBody += ",\"contact\":[\"mailto:" + W2A(email) + "\"]";
        regBody += "}";
        std::string loc; DWORD regHttp = 0;
        std::string regResp; bool regOK = false;
        for (int retry = 0; retry < 10; retry++) {
            if (g_AcmeNonce.empty()) getNonce();
            if (g_AcmeNonce.empty()) { Log(L"[错误] 无法获取 Nonce"); break; }
            regResp = AcmePost(newAcct, regBody, g_AcmeNonce, true, &loc, &regHttp);
            if (!loc.empty()) { regOK = true; break; }
            if (regResp.find("badNonce") != std::string::npos || regResp.find("invalid anti-replay") != std::string::npos) {
                Log(L"  badNonce, 重试 %d/10...", retry + 1);
                g_AcmeNonce.clear(); getNonce();
                Sleep(1000); continue;
            }
            break;
        }
        if (!regOK) {
            Log(L"[错误] 帐户注册失败 (HTTP %d)", regHttp);
            Log(L"  响应: %s", A2W(regResp.substr(0, 500)).c_str());
            SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        g_AccURL = loc;
        std::string regStatus = JsonStr(regResp, "status");
        Log(L"  帐户状态: %s", A2W(regStatus.empty() ? std::string("已存在") : regStatus).c_str());
    }

    // Step 4: 创建订单
    SetStatus(L"创建订单...");
    Log(L"Step 4: 创建订单...");
    std::string orderUrl, authzUrl, finalizeUrl, certUrl;
    std::string domainA = W2A(wd);
    {
        std::string ordBody = "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"" + domainA + "\"}]}";
        DWORD orderHttpCode = 0;
        std::string order = AcmePost(newOrder, ordBody, g_AcmeNonce, false, &orderUrl, &orderHttpCode);
        int retries = 0;
        while (orderHttpCode == 400 && order.find("badNonce") != std::string::npos && retries < 2) {
            retries++; Log(L"  重试订单请求 (badNonce, 第%d次)...", retries);
            orderUrl.clear(); order = AcmePost(newOrder, ordBody, g_AcmeNonce, false, &orderUrl, &orderHttpCode);
        }
        if (order.empty()) {
            Log(L"[错误] 订单创建失败 (HTTP %d)", orderHttpCode);
            if (orderHttpCode == 429) Log(L"  速率限制: 每周最多签发 50 张证书");
            SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        std::string orderStatus = JsonStr(order, "status");
        Log(L"  订单状态: %s", A2W(orderStatus).c_str());
        finalizeUrl = JsonStr(order, "finalize");
        if (!finalizeUrl.empty()) Log(L"  完成URL: %s", A2W(finalizeUrl.substr(0, 100)).c_str());

        // 处理速率限制 (429)
        if (orderHttpCode == 429 || order.find("rateLimited") != std::string::npos) {
            std::string rateDetail = JsonStr(order, "detail");
            Log(L"[错误] Let's Encrypt 速率限制: %s", A2W(rateDetail.empty() ? order.substr(0, 300) : rateDetail).c_str());
            Log(L"  提示: 同一域名每周最多签发 5 张证书，请稍后重试");
            SetStatus(L"速率限制"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }

        if (order.empty() || orderHttpCode >= 400) {
            std::string errDetail = JsonStr(order, "detail");
            Log(L"[错误] 订单创建失败 (HTTP %d): %s", orderHttpCode, A2W(errDetail.empty() ? order.substr(0, 300) : errDetail).c_str());
            SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }

        if (orderStatus == "ready") {
            Log(L"  域名已验证，跳过挑战");
            finalizeUrl = JsonStr(order, "finalize");
        } else {
            // 解析 authorizations 数组，用 JsonStr 逻辑提取第一个 URL
            size_t aPos = order.find("\"authorizations\"");
            if (aPos == std::string::npos) {
                Log(L"[错误] 订单响应缺少 authorizations 字段"); SetStatus(L"失败");
                EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            // 查找数组开始
            size_t arrStart = order.find('[', aPos);
            if (arrStart == std::string::npos) {
                Log(L"[错误] authorizations 不是数组"); SetStatus(L"失败");
                EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            // 查找第一个引号
            size_t quoteStart = order.find('"', arrStart);
            if (quoteStart == std::string::npos) {
                Log(L"[错误] authorizations 数组为空"); SetStatus(L"失败");
                EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            quoteStart++;
            size_t quoteEnd = order.find('"', quoteStart);
            if (quoteEnd == std::string::npos) {
                Log(L"[错误] authorizations URL 解析失败"); SetStatus(L"失败");
                EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            authzUrl = order.substr(quoteStart, quoteEnd - quoteStart);
            finalizeUrl = JsonStr(order, "finalize");
            Log(L"  授权URL: %s", A2W(authzUrl.substr(0, 80)).c_str());
        }
    }

    bool skipChallenge = false;
    std::wstring challFile;
    bool useTempServer = false;
    std::wstring dnsApiZone, dnsApiSubDomain;
    bool dnsApiCreated = false;
    std::wstring baseDomain = wd;
    if (isWild && baseDomain.size() >= 2 && baseDomain[0] == L'*' && baseDomain[1] == L'.')
        baseDomain = baseDomain.substr(2);

    if (!skipChallenge) {
        SetStatus(L"获取授权...");
        Log(L"Step 5: 获取域名授权...");
        std::string authz = AcmePost(authzUrl, "", g_AcmeNonce, false);
        if (authz.empty()) { Log(L"[错误] 授权获取失败"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
        if (authz.find("\"pending\"") == std::string::npos && authz.find("\"valid\"") == std::string::npos && authz.find("\"ready\"") == std::string::npos) {
            Log(L"  [调试] 授权响应: %s", A2W(authz.substr(0, 500)).c_str());
        }

        std::string challUrl, token, keyAuth;

        if (verifyMode == 0) {
            // HTTP-01
            size_t cPos = authz.find("\"http-01\"");
            if (cPos == std::string::npos) cPos = authz.find("\"type\":\"http-01\"");
            if (cPos == std::string::npos) { Log(L"[错误] 未找到 HTTP-01 挑战"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            cPos = authz.find("\"url\"", cPos); if (cPos == std::string::npos) { Log(L"[错误] 挑战无 url"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            cPos = authz.find(":", cPos); cPos = authz.find("\"", cPos) + 1; size_t cEnd = authz.find("\"", cPos);
            challUrl = authz.substr(cPos, cEnd - cPos);
            size_t tPos = authz.find("\"token\"", cPos); if (tPos == std::string::npos) { Log(L"[错误] 挑战无 token"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            tPos = authz.find(":", tPos); tPos = authz.find("\"", tPos) + 1; size_t tEnd = authz.find("\"", tPos);
            token = authz.substr(tPos, tEnd - tPos);
            keyAuth = token + "." + AccThumbprint();

            bool port80Free = IsPort80Free();
            if (port80Free) {
                SetStatus(L"启动验证服务器...");
                Log(L"Step 6: 80 端口空闲，启动临时验证服务器...");
                if (!StartTempHttpServer(token, keyAuth)) {
                    Log(L"[错误] 临时验证服务器启动失败"); SetStatus(L"失败");
                    EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                }
                useTempServer = true;
                Log(L"  临时验证服务器已启动（监听80端口）");
            } else {
                SetStatus(L"写入验证文件...");
                Log(L"Step 6: Web 服务器运行中，写入验证文件...");
                if (g_WebRoot.empty()) { Log(L"[错误] 需填写网站目录"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
                std::wstring challDir = g_WebRoot + L"\\.well-known\\acme-challenge";
                challFile = challDir + L"\\" + A2W(token);
                CreateDirectoryW((g_WebRoot + L"\\.well-known").c_str(), NULL);
                if (!CreateDirectoryW(challDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    Log(L"[错误] 无法创建目录 %s", challDir.c_str()); SetStatus(L"目录创建失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                }
                {
                    HANDLE hcf = CreateFileW(challFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hcf == INVALID_HANDLE_VALUE) { Log(L"[错误] 无法写入验证文件 %s", challFile.c_str()); SetStatus(L"写入失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
                    DWORD written2 = 0; WriteFile(hcf, keyAuth.data(), (DWORD)keyAuth.size(), &written2, NULL); CloseHandle(hcf);
                }
                Log(L"  已写入: .well-known/acme-challenge/%s", A2W(token).c_str());
            }
        } else {
            // DNS-01
            size_t cPos = authz.find("\"dns-01\"");
            if (cPos == std::string::npos) cPos = authz.find("\"type\":\"dns-01\"");
            if (cPos == std::string::npos) { Log(L"[错误] 未找到 DNS-01 挑战"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            cPos = authz.find("\"url\"", cPos); if (cPos == std::string::npos) { Log(L"[错误] 挑战无 url"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            cPos = authz.find(":", cPos); cPos = authz.find("\"", cPos) + 1; size_t cEnd = authz.find("\"", cPos);
            challUrl = authz.substr(cPos, cEnd - cPos);
            size_t tPos = authz.find("\"token\"", cPos); if (tPos == std::string::npos) { Log(L"[错误] 挑战无 token"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            tPos = authz.find(":", tPos); tPos = authz.find("\"", tPos) + 1; size_t tEnd = authz.find("\"", tPos);
            token = authz.substr(tPos, tEnd - tPos);
            keyAuth = token + "." + AccThumbprint();
            std::string challengeB64 = Sha256B64(keyAuth);
            std::wstring wQueryName = L"_acme-challenge." + baseDomain;
            std::wstring wChallenge = A2W(challengeB64);

            LoadDnsConfigForDomain(wd);
            bool hasApi = (g_DnsProvider > 0 && ((!g_DnsApiId.empty() && !g_DnsApiSecret.empty()) || (g_DnsProvider == DNS_PROVIDER_CLOUDFLARE && !g_DnsApiSecret.empty())));

            if (hasApi) {
            // API 自动模式：自动创建 TXT 记录
            SetStatus(L"自动创建 TXT 记录...");
            Log(L"Step 6: DNS-01 验证 (API 自动模式 - %s)", g_DnsProvider == 1 ? L"阿里云" : g_DnsProvider == 2 ? L"腾讯云" : L"Cloudflare");

            std::wstring zone, subDomain;
            DnsFindZone(g_DnsProvider, g_DnsApiId, g_DnsApiSecret, wQueryName, zone, subDomain);
            if (zone.empty()) { Log(L"[错误] 无法找到 DNS Zone，请检查 API 配置"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            Log(L"  Zone: %s, 子域: %s", zone.c_str(), subDomain.c_str());

            std::wstring dnsErr = DnsCreateTxtRecord(g_DnsProvider, g_DnsApiId, g_DnsApiSecret, zone, subDomain, wChallenge);
            if (!dnsErr.empty()) { Log(L"[错误] TXT 记录创建失败: %s", dnsErr.c_str()); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
            Log(L"  TXT 记录已自动创建");
            dnsApiZone = zone; dnsApiSubDomain = subDomain; dnsApiCreated = true;

            SetStatus(L"等待 DNS 传播...");
            Log(L"  等待 DNS 传播 (30秒)...");
            for (int ew = 30; ew > 0; ew -= 5) { Sleep(5000); if (!g_Running) return 0; }

            // DNS 权威预验证
            SetStatus(L"检查 DNS 传播...");
            bool dnsFound = false;
            if (DnsPreValidateAuthoritative(wQueryName, wChallenge, 5, 10)) {
                dnsFound = true;
                Log(L"  DNS 权威预验证通过");
            } else {
                PDNS_RECORD dr = NULL;
                DNS_STATUS ds = DnsQuery_W(wQueryName.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &dr, NULL);
                if (ds == 0 && dr) {
                    for (PDNS_RECORD p = dr; p; p = p->pNext) {
                        if (p->wType == DNS_TYPE_TEXT && p->Data.Txt.dwStringCount > 0) {
                            std::string txtVal = W2A(p->Data.Txt.pStringArray[0]);
                            if (txtVal == challengeB64) { dnsFound = true; Log(L"  DNS 本地自检通过"); break; }
                        }
                    }
                    DnsRecordListFree(dr, DnsFreeRecordList);
                }
                if (!dnsFound) {
                    Log(L"  [警告] DNS 未生效，额外等待 30 秒...");
                    for (int ew = 30; ew > 0; ew -= 5) { Sleep(5000); if (!g_Running) return 0; }
                }
            }
        } else {
            // 手工模式：提示用户手动添加 TXT 记录
            SetStatus(L"请添加 TXT 记录...");
            Log(L"Step 6: DNS-01 验证 (手工模式)");
            Log(L"");
            Log(L"----------------------------------------");
            Log(L"DNS-01 验证步骤：");
            Log(L"  1. 登录域名 DNS 管理后台");
            Log(L"  2. 添加以下 TXT 记录：");
            Log(L"");
            Log(L"     主机记录: _acme-challenge");
            Log(L"     记录类型: TXT");
            Log(L"     记录值: %s", wChallenge.c_str());
            if (isWild) Log(L"     完整名称: _acme-challenge.%s", baseDomain.c_str());
            Log(L"");
            Log(L"  3. 等待 DNS 记录生效（通常需数分钟）");
            Log(L"  4. 点击「继续验证」按钮");
            Log(L"");
            if (isWild) Log(L"  通配符: TXT 记录添加在根域名 %s 下（非 *.%s）", baseDomain.c_str(), baseDomain.c_str());
            Log(L"  记录值区分大小写，完整复制");
            Log(L"  提示: 可在「DNS API 配置」中设置 API 自动创建");
            Log(L"----------------------------------------");
            Log(L"");

            {
                EnterCriticalSection(&g_cs);
                if (g_hDnsReady) {
                    CloseHandle(g_hDnsReady);
                    g_hDnsReady = NULL;
                }
                g_hDnsReady = CreateEventW(NULL, TRUE, FALSE, NULL);
                HANDLE localDnsReady = g_hDnsReady;
                LeaveCriticalSection(&g_cs);
                
                if (!localDnsReady) {
                    SetStatus(L"内部错误");
                    EnableWindow(g_hBtnApply, TRUE);
                    SetWindowTextW(g_hBtnApply, L"申请证书");
                    return 0;
                }
                
                EnableWindow(g_hBtnApply, TRUE);
                SetWindowTextW(g_hBtnApply, L"继续验证");
                SetStatus(L"请添加 TXT 记录后点击「继续验证」");
                Log(L"  请添加 TXT 记录后点击「继续验证」按钮...");
                
                bool shouldExit = false;
                
                while (WaitForSingleObject(localDnsReady, 500) != WAIT_OBJECT_0) {
                    EnterCriticalSection(&g_cs);
                    bool running = g_Running;
                    HANDLE currentEvent = g_hDnsReady;
                    LeaveCriticalSection(&g_cs);
                    
                    if (!running || currentEvent != localDnsReady) {
                        shouldExit = true;
                        break;
                    }
                }
                
                EnterCriticalSection(&g_cs);
                if (g_hDnsReady == localDnsReady) {
                    CloseHandle(g_hDnsReady);
                    g_hDnsReady = NULL;
                }
                LeaveCriticalSection(&g_cs);
                
                if (shouldExit) {
                    EnableWindow(g_hBtnApply, TRUE);
                    SetWindowTextW(g_hBtnApply, L"申请证书");
                    return 0;
                }
                
                EnableWindow(g_hBtnApply, FALSE);
                SetWindowTextW(g_hBtnApply, L"申请证书");

                    // DNS 传播自检
                    SetStatus(L"检查 DNS 传播...");
                    bool dnsFound = false;
                    if (DnsPreValidateAuthoritative(wQueryName, wChallenge, 5, 10)) {
                        dnsFound = true;
                        Log(L"  DNS 权威预验证通过");
                    } else {
                        PDNS_RECORD dr = NULL;
                        DNS_STATUS ds = DnsQuery_W(wQueryName.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &dr, NULL);
                        if (ds == 0 && dr) {
                            for (PDNS_RECORD p = dr; p; p = p->pNext) {
                                if (p->wType == DNS_TYPE_TEXT && p->Data.Txt.dwStringCount > 0) {
                                    std::string txtVal = W2A(p->Data.Txt.pStringArray[0]);
                                    if (txtVal == challengeB64) { dnsFound = true; Log(L"  DNS 本地自检通过"); break; }
                                }
                            }
                            DnsRecordListFree(dr, DnsFreeRecordList);
                        }
                        if (!dnsFound) {
                            Log(L"  [警告] DNS 未生效，额外等待 30 秒...");
                            for (int ew = 30; ew > 0; ew -= 5) { Sleep(5000); if (!g_Running) return 0; }
                        }
                    }
                }
            }
        }

        // Step 7: 通知 ACME 验证
        SetStatus(L"验证域名...");
        Log(L"Step 7: 请求 ACME 验证...");
        AcmePost(challUrl, "{}", g_AcmeNonce, false);
        Log(L"  已通知验证");

        // Step 8: 轮询验证结果
        Log(L"Step 8: 轮询验证结果...");
        bool verified = false;
        for (int i = 0; i < (verifyMode == 0 ? 12 : 60); i++) {
            Sleep(5000);
            std::string check = AcmePost(authzUrl, "", g_AcmeNonce, false);
            std::string authStatus = JsonStr(check, "status");
            if (authStatus == "valid") { verified = true; break; }
            if (authStatus == "invalid") {
                std::string errDetail = JsonStr(check, "detail");
                if (!errDetail.empty()) Log(L"  验证失败详情: %s", A2W(errDetail).c_str());
                break;
            }
            if (authStatus.empty()) {
                Log(L"  等待... (%d/%d) [状态解析失败]", i + 1, verifyMode == 0 ? 12 : 60);
            } else {
                Log(L"  等待... (%d/%d) [状态: %s]", i + 1, verifyMode == 0 ? 12 : 60, A2W(authStatus).c_str());
            }
        }
        if (!verified) {
            if (useTempServer) StopTempHttpServer();
            else if (verifyMode == 0 && !challFile.empty()) DeleteFileW(challFile.c_str());
            if (dnsApiCreated) DnsDeleteTxtRecord(g_DnsProvider, g_DnsApiId, g_DnsApiSecret, dnsApiZone, dnsApiSubDomain);
            Log(L"[错误] 域名验证失败");
            SetStatus(L"验证失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        Log(L"  验证通过");
        if (useTempServer) StopTempHttpServer();
        else if (verifyMode == 0 && !challFile.empty()) _wunlink(challFile.c_str());
        if (dnsApiCreated) { DnsDeleteTxtRecord(g_DnsProvider, g_DnsApiId, g_DnsApiSecret, dnsApiZone, dnsApiSubDomain); Log(L"  TXT 记录已清理"); }
    }

    // Step 9: 生成域密钥和 CSR
    SetStatus(L"生成域密钥和 CSR...");
    Log(L"Step 9: 生成域密钥和 CSR...");
    BCRYPT_ALG_HANDLE ha = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&ha, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (st != 0) { Log(L"[错误] 无法打开算法提供者"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
    
    BCRYPT_KEY_HANDLE dk = NULL;
    st = BCryptGenerateKeyPair(ha, &dk, 2048, 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(ha, 0); Log(L"[错误] 无法生成密钥对"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
    
    st = BCryptFinalizeKeyPair(dk, 0);
    if (st != 0) { BCryptDestroyKey(dk); BCryptCloseAlgorithmProvider(ha, 0); Log(L"[错误] 无法完成密钥对"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
    
    BCryptCloseAlgorithmProvider(ha, 0);
    std::vector<BYTE> csrDer = BuildCSR(domainA, dk, NULL);
    std::string csrB64 = B64Url(csrDer);
    Log(L"  CSR %d 字节", (int)csrDer.size());

    // Step 10: 提交 CSR
    SetStatus(L"正在签发证书...");
    Log(L"Step 10: 提交 CSR 申请签发...");
    std::string finBody = "{\"csr\":\"" + csrB64 + "\"}";
    DWORD finHttpCode = 0;
    std::string finResp = AcmePost(finalizeUrl, finBody, g_AcmeNonce, false, NULL, &finHttpCode);
    int finRetries = 0;
    while (finHttpCode == 400 && finResp.find("badNonce") != std::string::npos && finRetries < 2) {
        finRetries++; Log(L"  重试提交 CSR (badNonce, 第%d次)...", finRetries);
        finResp = AcmePost(finalizeUrl, finBody, g_AcmeNonce, false, NULL, &finHttpCode);
    }
    if (finResp.empty()) {
        Log(L"[错误] 订单完成失败 (HTTP %d)", finHttpCode); (void)BCryptDestroyKey(dk);
        SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
    }
    if (finHttpCode >= 400) {
        std::string finErr = JsonStr(finResp, "detail");
        Log(L"[错误] CSR 提交被拒 (HTTP %d): %s", finHttpCode, A2W(finErr.empty() ? finResp.substr(0, 200) : finErr).c_str());
        (void)BCryptDestroyKey(dk); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
    }
    std::string finStatus = JsonStr(finResp, "status");
    certUrl = JsonStr(finResp, "certificate");
    Log(L"  订单状态: %s", A2W(finStatus.empty() ? std::string("未知") : finStatus).c_str());

    // Step 11: 等待证书
    if (certUrl.empty()) {
        SetStatus(L"正在下载证书...");
        Log(L"Step 11: 等待服务器打包证书...");
        for (int i = 0; i < 15; i++) {
            Sleep(3000);
            std::string check = AcmePost(orderUrl, "", g_AcmeNonce, false);
            std::string orderCheckStatus = JsonStr(check, "status");
            if (orderCheckStatus == "invalid") {
                std::string errDetail = JsonStr(check, "error");
                Log(L"[错误] 订单状态无效: %s", A2W(errDetail.empty() ? check.substr(0, 200) : errDetail).c_str());
                (void)BCryptDestroyKey(dk); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            certUrl = JsonStr(check, "certificate");
            if (!certUrl.empty()) break;
            if (orderCheckStatus == "ready") {
                Log(L"  等待... (%d/15) finalize 未生效，重新提交 CSR...", i + 1);
                DWORD retryCode = 0;
                std::string retryResp = AcmePost(finalizeUrl, finBody, g_AcmeNonce, false, NULL, &retryCode);
                if (!retryResp.empty()) certUrl = JsonStr(retryResp, "certificate");
                if (!certUrl.empty()) break;
            } else {
                Log(L"  等待... (%d/15) 状态: %s", i + 1, A2W(orderCheckStatus.empty() ? std::string("未知") : orderCheckStatus).c_str());
            }
        }
    }
    if (certUrl.empty()) { Log(L"[错误] 获取证书下载链接超时"); (void)BCryptDestroyKey(dk); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }

    // Step 12: 下载证书
    Log(L"Step 12: 下载证书链...");
    std::string certPem = AcmePost(certUrl, "", g_AcmeNonce, false);
    if (certPem.empty()) { Log(L"[错误] 证书下载失败"); (void)BCryptDestroyKey(dk); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }

    // 保存私钥和证书
    bool needPkcs1 = (si == 0 || si == 1);
    bool needPem = (si == 3);
    {
        std::string keyExt = needPem ? "_key.pem" : ".key";
        std::string keyPath = W2A(g_SaveDir + L"\\" + nt + A2W(keyExt));
        std::string pem; NTSTATUS status = 0;
        if (needPkcs1) {
            DWORD fl = 0; status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, 0, 0, &fl, 0);
            if (status == 0 && fl > 0) { std::vector<BYTE> fb(fl); status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, fb.data(), fl, &fl, 0); if (status == 0) pem = RsaFullBlobToPkcs1Pem(fb); }
            if (pem.empty()) { DWORD pl = 0; status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, 0, &pl, 0); if (status == 0 && pl > 0) { std::vector<BYTE> pkv(pl); status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkv.data(), pl, &pl, 0); if (status == 0) { std::string bp = B64Pem(pkv); std::string pkcs8 = "-----BEGIN PRIVATE KEY-----\r\n" + bp + "\r\n-----END PRIVATE KEY-----\r\n"; pem = Pkcs8PemToPkcs1Pem(pkcs8); } } }
        } else {
            DWORD fl = 0; status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, 0, 0, &fl, 0);
            if (status == 0 && fl > 0) { std::vector<BYTE> fb(fl); status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, fb.data(), fl, &fl, 0); if (status == 0) pem = RsaFullBlobToPkcs8Pem(fb); }
            if (pem.empty()) { DWORD pl = 0; status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, 0, &pl, 0); if (status == 0 && pl > 0) { std::vector<BYTE> pkv(pl); status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkv.data(), pl, &pl, 0); if (status == 0) { std::string bp = B64Pem(pkv); pem = "-----BEGIN PRIVATE KEY-----\r\n" + bp + "\r\n-----END PRIVATE KEY-----\r\n"; } } }
        }
        bool keySaved = !pem.empty();
        if (pem.empty()) { Log(L"[错误] 私钥导出失败 (0x%08X)", status); keySaved = false; }
        else if (!WriteFileAtomic(keyPath, pem)) { Log(L"[错误] 私钥保存失败: %s%s", nt.c_str(), A2W(keyExt).c_str()); keySaved = false; }
        else { Log(L"  私钥已保存: %s%s (%s)", nt.c_str(), A2W(keyExt).c_str(), needPkcs1 ? L"PKCS#1" : L"PKCS#8"); }

        if (!keySaved) {
            Log(L"[错误] 私钥保存失败，无法完成申请");
            (void)BCryptDestroyKey(dk);
            SetStatus(L"私钥保存失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }

        bool certSaved = false;
        {
            std::string certExt = needPem ? "_cert.pem" : ".crt";
            std::string certPath = W2A(g_SaveDir + L"\\" + nt + A2W(certExt));
            if (WriteFileAtomic(certPath, certPem)) { Log(L"  证书已保存: %s%s", nt.c_str(), A2W(certExt).c_str()); certSaved = true; }
            else { Log(L"[错误] 证书保存失败: %s%s", nt.c_str(), A2W(certExt).c_str()); }
        }

        bool pfxSaved = false;
        if (si == 2) {
            std::wstring pfxPath = g_SaveDir + L"\\" + nt + L".pfx";
            if (SavePFX(dk, certPem, pfxPath)) { Log(L"  IIS 证书已保存: %s.pfx", nt.c_str()); pfxSaved = true; }
            else { Log(L"[错误] PFX 导出失败"); }
        }

        if (!certSaved) {
            Log(L"[错误] 证书保存失败，无法完成申请");
            (void)BCryptDestroyKey(dk);
            SetStatus(L"证书保存失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }

        if (si == 2) Log(L"  提示: IIS 请导入 .pfx 文件（无密码）");
        else if (si == 3) Log(L"  提示: _key.pem 为 PKCS#8 私钥，_cert.pem 为 PEM 证书");
        else Log(L"  提示: .key 为 PKCS#1 私钥，.crt 为 PEM 证书");
    }

    // 保存续签记录，从证书中提取实际到期时间
    FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
    FILETIME expFt = {};
    {
        // 从证书 PEM 解析到期时间
        wchar_t tempCert[MAX_PATH]; GetTempPathW(MAX_PATH, tempCert);
        std::wstring tempPem = std::wstring(tempCert) + L"SSLClaw_exp_cert.pem";
        bool fileCreated = false;
        HANDLE hTmp = CreateFileW(tempPem.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTmp != INVALID_HANDLE_VALUE) {
            DWORD wr = 0; 
            BOOL writeOk = WriteFile(hTmp, certPem.data(), (DWORD)certPem.size(), &wr, NULL);
            CloseHandle(hTmp);
            fileCreated = writeOk && (wr == certPem.size());
        }
        
        if (fileCreated) {
            HCERTSTORE hTmpStore = CertOpenStore(CERT_STORE_PROV_FILENAME, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, tempPem.c_str());
            if (hTmpStore) {
                PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hTmpStore, NULL);
                if (pCert) {
                    expFt = pCert->pCertInfo->NotAfter;
                    CertFreeCertificateContext(pCert);
                }
                CertCloseStore(hTmpStore, 0);
            }
            DeleteFileW(tempPem.c_str());
        }
        
        if (expFt.dwLowDateTime == 0 && expFt.dwHighDateTime == 0) {
            // 解析失败，回退到 90 天（使用 UTC 时间）
            ULARGE_INTEGER expUl; expUl.LowPart = nowFt.dwLowDateTime; expUl.HighPart = nowFt.dwHighDateTime;
            expUl.QuadPart += 90ULL * 24ULL * 60ULL * 60ULL * 10000000ULL; // 90天
            expFt.dwLowDateTime = expUl.LowPart; expFt.dwHighDateTime = expUl.HighPart;
        }
    }

    RenewalRecord rec;
    rec.domain = wd;
    rec.verifyMode = verifyMode;
    rec.serverType = si;
    rec.webRoot = g_WebRoot;
    rec.saveDir = g_SaveDir;
    rec.email = email;
    rec.autoRenew = false;
    rec.thumbprint = L"";
    rec.friendlyName = wd;
    rec.issueTime = nowFt;
    rec.expiryTime = expFt;
    rec.renewalDays = 60;
    rec.preScript = L"";
    rec.postScript = L"";
    int wc = (int)SendMessageW(g_hWildcard, BM_GETCHECK, 0, 0);
    rec.wildcard = (wc == BST_CHECKED);
    // DNS-01 配置（密钥不存续签记录，续签时从主配置读取）
    rec.dnsProvider = (verifyMode == 1) ? g_DnsProvider : 0;
    AddOrUpdateRenewal(rec);
    Log(L"  续签记录已保存: %s (保存目录: %s)", wd.c_str(), g_SaveDir.c_str());

    (void)BCryptDestroyKey(dk);
    SetStatus(L"完成 - 证书已获取");
    SetWindowTextW(g_hBtnApply, L"申请证书");
    EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE);
    g_Running = false;
    return 0;
}

unsigned __stdcall ApplyThread(void*) {
    EnterCriticalSection(&g_cs);
    if (g_Running) { LeaveCriticalSection(&g_cs); return 0; }
    g_Running = true;
    LeaveCriticalSection(&g_cs);
    __try { ApplyThreadInner(); }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        Log(L"[致命错误] 证书申请线程异常终止"); SetStatus(L"失败 - 异常");
    }
    if (g_Running) {
        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE);
        SetWindowTextW(g_hBtnApply, L"申请证书");
        EnterCriticalSection(&g_cs);
        if (g_hDnsReady) { 
            CloseHandle(g_hDnsReady); 
            g_hDnsReady = NULL; 
        }
        LeaveCriticalSection(&g_cs);
        g_Running = false;
    }
    return 0;
}
