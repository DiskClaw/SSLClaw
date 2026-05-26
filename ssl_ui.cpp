// ssl_ui.cpp - SSL 证书工具 UI 实现
#include "ssl_ui.h"
#include "ssl_core.h"
#include <commctrl.h>
#include <thread>
#pragma comment(lib, "comctl32.lib")
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <functional>
#include <process.h>
#include <tlhelp32.h>
#include <set>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "version.lib")

// ── 检测本地 Web 服务器 ──
// 从进程 PID 获取可执行文件路径
static std::wstring GetProcessPath(DWORD pid) {
    std::wstring path;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        wchar_t buf[MAX_PATH] = {};
        DWORD sz = MAX_PATH;
        if (QueryFullProcessImageNameW(hProc, 0, buf, &sz)) path = buf;
        CloseHandle(hProc);
    }
    return path;
}

// 从 PE 文件提取产品版本号
static std::wstring GetFileVersion(const wchar_t* path) {
    DWORD handle = 0;
    DWORD sz = GetFileVersionInfoSizeW(path, &handle);
    if (sz == 0) return L"";
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(path, handle, sz, buf.data())) return L"";
    VS_FIXEDFILEINFO* fi = nullptr; UINT fiLen = 0;
    if (VerQueryValueW(buf.data(), L"\\", (void**)&fi, &fiLen) && fi && fiLen >= sizeof(*fi)) {
        wchar_t v[64]; swprintf_s(v, L"%d.%d", HIWORD(fi->dwFileVersionMS), LOWORD(fi->dwFileVersionMS));
        if (LOWORD(fi->dwFileVersionLS) || HIWORD(fi->dwFileVersionLS))
            swprintf_s(v, L"%d.%d.%d", HIWORD(fi->dwFileVersionMS), LOWORD(fi->dwFileVersionMS), LOWORD(fi->dwFileVersionLS));
        return v;
    }
    return L"";
}

// 截取文件所在目录的简短路径（最多取最后 2 级）
static std::wstring ShortDir(const std::wstring& fullPath) {
    if (fullPath.empty()) return L"";
    size_t lastSlash = fullPath.rfind(L'\\');
    if (lastSlash == std::wstring::npos) return L"";
    std::wstring dir = fullPath.substr(0, lastSlash);
    size_t prevSlash = dir.rfind(L'\\');
    if (prevSlash != std::wstring::npos && prevSlash > 0) {
        size_t ppSlash = dir.rfind(L'\\', prevSlash - 1);
        if (ppSlash != std::wstring::npos) dir = dir.substr(ppSlash + 1);
    }
    return dir;
}

struct WebServerInfo { std::wstring name; std::wstring version; std::wstring path; };

static std::wstring DetectWebServer() {
    std::vector<WebServerInfo> results;
    std::set<std::wstring> seen;  // 按 name 去重

    // 1) 扫描 Windows 服务 — 拿到服务名 + 可执行路径 + 版本
    struct SvcInfo { const wchar_t* svcName; const wchar_t* tag; };
    SvcInfo svcList[] = {
        { L"W3SVC",         L"IIS" },
        { L"nginx",         L"Nginx" },
        { L"Apache2.4",     L"Apache" },
        { L"Apache2.2",     L"Apache" },
        { L"wampapache64",  L"Apache" },
        { L"wampapache",    L"Apache" },
        { L"caddy",         L"Caddy" },
    };
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCM) {
        for (auto& si : svcList) {
            SC_HANDLE hSvc = OpenServiceW(hSCM, si.svcName, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
            if (!hSvc) continue;
            SERVICE_STATUS status = {};
            if (QueryServiceStatus(hSvc, &status) && status.dwCurrentState == SERVICE_RUNNING) {
                if (seen.find(si.tag) == seen.end()) {
                    seen.insert(si.tag);
                    WebServerInfo info; info.name = si.tag;
                    // 尝试读取服务可执行路径
                    DWORD need = 0; QueryServiceConfigW(hSvc, NULL, 0, &need);
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        std::vector<BYTE> cfg(need);
                        QUERY_SERVICE_CONFIGW* qsc = (QUERY_SERVICE_CONFIGW*)cfg.data();
                        if (QueryServiceConfigW(hSvc, qsc, need, &need) && qsc->lpBinaryPathName) {
                            // 去掉引号和参数，取实际 exe 路径
                            std::wstring bp = qsc->lpBinaryPathName;
                            if (bp[0] == L'\"') { bp = bp.substr(1); size_t q = bp.find(L'\"'); if (q != std::wstring::npos) bp = bp.substr(0, q); }
                            else { size_t sp = bp.find(L' '); if (sp != std::wstring::npos) bp = bp.substr(0, sp); }
                            info.path = bp;
                            info.version = GetFileVersion(bp.c_str());
                        }
                    }
                    results.push_back(info);
                }
            }
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    // 2) 扫描进程 — 补充服务检测不到的（非服务方式运行）
    struct ProcInfo { const wchar_t* exeName; const wchar_t* tag; };
    ProcInfo procList[] = {
        { L"nginx.exe",     L"Nginx" },
        { L"httpd.exe",     L"Apache" },
        { L"apache.exe",    L"Apache" },
        { L"caddy.exe",     L"Caddy" },
        { L"h2o.exe",       L"H2O" },
        { L"openresty.exe", L"OpenResty" },
        { L"w3wp.exe",      L"IIS" },
    };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                for (auto& pi : procList) {
                    if (_wcsicmp(pe.szExeFile, pi.exeName) == 0) {
                        if (seen.find(pi.tag) == seen.end()) {
                            seen.insert(pi.tag);
                            WebServerInfo info; info.name = pi.tag;
                            info.path = GetProcessPath(pe.th32ProcessID);
                            if (!info.path.empty()) info.version = GetFileVersion(info.path.c_str());
                            results.push_back(info);
                        }
                        break;
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    if (results.empty()) return L"";
    std::wstring result;
    for (size_t i = 0; i < results.size(); i++) {
        if (i > 0) result += L"  ";
        auto& r = results[i];
        result += L"\u25CF " + r.name;
        if (!r.version.empty()) result += L" " + r.version;
    }
    return result;
}

// 续签窗口原过程（全局变量，用于子类化恢复）
static WNDPROC g_OrigRenewProc = NULL;
HWND g_RenewWnd = NULL;

// ── 托盘图标 ──
UINT WM_TASKBARCREATED = 0;  // 任务栏重建消息
static bool g_TrayVisible = false;
static NOTIFYICONDATAW g_TrayNid = {};
#define TRAY_ID  1001
#define WM_TRAY  (WM_USER + 0x200)
#define WM_LOG_MSG (WM_USER + 0x201)
#define IDM_SHOW  40001
#define IDM_EXIT  40002

// DNS API 配置状态
int g_DnsProvider = DNS_PROVIDER_ALIYUN;
std::wstring g_DnsApiId;
std::wstring g_DnsApiSecret;
static std::wstring g_DnsConfigDomain;

// 日志临界区：保护 g_hLog 编辑控件不被并发操作
static CRITICAL_SECTION g_LogCs;
static bool g_LogCsInit = false;
static void InitLogCs() {
    if (!g_LogCsInit) { InitializeCriticalSection(&g_LogCs); g_LogCsInit = true; }
}

static std::wstring DnsSectionName(const std::wstring& domain) {
    return L"DNS:" + domain;
}

void LoadDnsConfig() {
    std::wstring ini = g_IniPath;
    wchar_t buf[512];
    GetPrivateProfileStringW(L"DNSConfig", L"Provider", L"1", buf, 512, ini.c_str());
    int prov = _wtoi(buf);
    if (prov < 1 || prov > 3) prov = DNS_PROVIDER_ALIYUN;
    g_DnsProvider = prov;
    GetPrivateProfileStringW(L"DNSConfig", L"ApiId", L"", buf, 512, ini.c_str());
    g_DnsApiId = buf;
    if (g_DnsApiId.size() >= 4 && (g_DnsApiId.substr(0, 4) == L"aes-" || g_DnsApiId.substr(0, 4) == L"enc-")) {
        g_DnsApiId = GetProtectedProfileStringW(ini.c_str(), L"DNSConfig", L"ApiId", L"");
    }
    GetPrivateProfileStringW(L"DNSConfig", L"ApiSecret", L"", buf, 512, ini.c_str());
    g_DnsApiSecret = buf;
    if (g_DnsApiSecret.size() >= 4 && (g_DnsApiSecret.substr(0, 4) == L"aes-" || g_DnsApiSecret.substr(0, 4) == L"enc-")) {
        g_DnsApiSecret = GetProtectedProfileStringW(ini.c_str(), L"DNSConfig", L"ApiSecret", L"");
    }
}

void LoadDnsConfigForDomain(const std::wstring& domain) {
    std::wstring baseDomain = domain;
    if (baseDomain.size() >= 2 && baseDomain[0] == L'*' && baseDomain[1] == L'.')
        baseDomain = baseDomain.substr(2);
    std::wstring sec = DnsSectionName(baseDomain);
    std::wstring ini = g_IniPath;
    wchar_t buf[512];
    GetPrivateProfileStringW(sec.c_str(), L"Provider", L"", buf, 512, ini.c_str());
    if (buf[0] == 0) {
        LoadDnsConfig();
        return;
    }
    int prov = _wtoi(buf);
    if (prov < 1 || prov > 3) { LoadDnsConfig(); return; }
    g_DnsProvider = prov;
    GetPrivateProfileStringW(sec.c_str(), L"ApiId", L"", buf, 512, ini.c_str());
    g_DnsApiId = buf;
    if (g_DnsApiId.size() >= 4 && (g_DnsApiId.substr(0, 4) == L"aes-" || g_DnsApiId.substr(0, 4) == L"enc-")) {
        g_DnsApiId = GetProtectedProfileStringW(ini.c_str(), sec.c_str(), L"ApiId", L"");
    }
    GetPrivateProfileStringW(sec.c_str(), L"ApiSecret", L"", buf, 512, ini.c_str());
    g_DnsApiSecret = buf;
    if (g_DnsApiSecret.size() >= 4 && (g_DnsApiSecret.substr(0, 4) == L"aes-" || g_DnsApiSecret.substr(0, 4) == L"enc-")) {
        g_DnsApiSecret = GetProtectedProfileStringW(ini.c_str(), sec.c_str(), L"ApiSecret", L"");
    }
}

void SaveDnsConfigForDomain(const std::wstring& domain) {
    std::wstring baseDomain = domain;
    if (baseDomain.size() >= 2 && baseDomain[0] == L'*' && baseDomain[1] == L'.')
        baseDomain = baseDomain.substr(2);
    std::wstring sec = DnsSectionName(baseDomain);
    std::wstring ini = g_IniPath;
    wchar_t buf[32]; swprintf_s(buf, L"%d", g_DnsProvider);
    WritePrivateProfileStringW(sec.c_str(), L"Provider", buf, ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"ApiId", g_DnsApiId.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"ApiSecret", g_DnsApiSecret.c_str(), ini.c_str());
}

// 子类化对话框控件 ID
#define IDC_DNS_PROV 10
#define IDC_DNS_LBL_ID 20
#define IDC_DNS_LBL_SECRET 21
#define IDC_DNS_ID 11
#define IDC_DNS_SECRET 12
#define IDC_DNS_OK 1
#define IDC_DNS_CANCEL 2
#define IDC_DNS_DOMAIN 40

// 子类化对话框过程
static WNDPROC g_OrigDnsDlgProc = NULL;
static LRESULT CALLBACK DnsConfigDlgProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        if (id == IDC_DNS_OK) {
            int sel = (int)SendMessageW(GetDlgItem(hw, IDC_DNS_PROV), CB_GETCURSEL, 0, 0) + 1;
            wchar_t buf[512];
            GetWindowTextW(GetDlgItem(hw, IDC_DNS_ID), buf, 512);
            std::wstring idVal = buf;
            GetWindowTextW(GetDlgItem(hw, IDC_DNS_SECRET), buf, 512);
            std::wstring secVal = buf;
            g_DnsProvider = sel;
            g_DnsApiId = idVal;
            g_DnsApiSecret = secVal;
            SaveDnsConfigForDomain(g_DnsConfigDomain);
            SetWindowTextW(GetDlgItem(hw, 30), L"已保存");
            DestroyWindow(hw);
            return 0;
        } else if (id == IDC_DNS_PROV && HIWORD(wp) == CBN_SELCHANGE) {
            int sel = (int)SendMessageW(GetDlgItem(hw, IDC_DNS_PROV), CB_GETCURSEL, 0, 0) + 1;
            SetWindowTextW(GetDlgItem(hw, IDC_DNS_ID), L"");
            SetWindowTextW(GetDlgItem(hw, IDC_DNS_SECRET), L"");
            if (sel == DNS_PROVIDER_ALIYUN) {
                SetWindowTextW(GetDlgItem(hw, IDC_DNS_LBL_ID), L"AccessKey ID");
                SetWindowTextW(GetDlgItem(hw, IDC_DNS_LBL_SECRET), L"AccessKey Secret");
            } else if (sel == DNS_PROVIDER_TENCENT) {
                SetWindowTextW(GetDlgItem(hw, IDC_DNS_LBL_ID), L"SecretId");
                SetWindowTextW(GetDlgItem(hw, IDC_DNS_LBL_SECRET), L"SecretKey");
            } else if (sel == DNS_PROVIDER_CLOUDFLARE) {
                SetWindowTextW(GetDlgItem(hw, IDC_DNS_LBL_ID), L"备注(可选)");
                SetWindowTextW(GetDlgItem(hw, IDC_DNS_LBL_SECRET), L"API Token");
            }
            // 更新教程文本
            HWND hTut = (HWND)GetWindowLongPtrW(hw, GWLP_USERDATA);
            if (hTut) {
                const wchar_t* txt = nullptr;
                if (sel == DNS_PROVIDER_ALIYUN) {
                    txt = L"1. 登录阿里云控制台 https://home.console.aliyun.com\r\n"
                        L"2. 右上角头像 → AccessKey 管理\r\n"
                        L"3. 建议创建 RAM 子用户（最小权限原则）:\r\n"
                        L"   - 授权策略: AliyunDNSFullAccess\r\n"
                        L"   - 或自定义策略，只允许 DNS 相关操作\r\n"
                        L"4. 创建 AccessKey，记录 AccessKey ID 和 AccessKey Secret\r\n"
                        L"5. 将 AccessKey ID 填入上方 ID 栏，AccessKey Secret 填入 Secret 栏\r\n"
                        L"\r\n"
                        L"注意事项:\r\n"
                        L"• AccessKey Secret 只在创建时显示一次，请妥善保存\r\n"
                        L"• 主账号 Key 拥有全部权限，强烈建议使用 RAM 子账号\r\n"
                        L"• 域名必须在阿里云 DNS 解析中管理（非万网DNS需先迁移）";
                } else if (sel == DNS_PROVIDER_TENCENT) {
                    txt = L"1. 登录腾讯云控制台 https://console.cloud.tencent.com\r\n"
                        L"2. 访问 API 密钥管理 https://console.cloud.tencent.com/cam/capi\r\n"
                        L"3. 建议创建子账号（最小权限原则）:\r\n"
                        L"   - 授权策略: QcloudDNSPodFullAccess\r\n"
                        L"   - 或自定义策略，只允许 DNSPOD 相关操作\r\n"
                        L"4. 创建密钥，记录 SecretId 和 SecretKey\r\n"
                        L"5. 将 SecretId 填入上方 ID 栏，SecretKey 填入 Secret 栏\r\n"
                        L"\r\n"
                        L"注意事项:\r\n"
                        L"• SecretKey 只在创建时显示一次，请妥善保存\r\n"
                        L"• 主账号 Key 拥有全部权限，强烈建议使用子账号\r\n"
                        L"• 域名必须在 DNSPod 解析中管理（非腾讯云DNS需先迁移）";
                } else {
                    txt = L"Cloudflare API Token 获取方法:\r\n"
                        L"\r\n"
                        L"1. 登录 Cloudflare https://dash.cloudflare.com\r\n"
                        L"2. 右上角头像 → My Profile → API Tokens\r\n"
                        L"3. 点击 Create Token\r\n"
                        L"4. 使用模板「Edit zone DNS」或自定义:\r\n"
                        L"   - Permissions: Zone - DNS - Edit\r\n"
                        L"   - Zone Resources: Include - Specific zone - 你的域名\r\n"
                        L"5. 创建后复制 Token（只显示一次）\r\n"
                        L"6. 将 Token 填入上方 Secret 栏，ID 栏可留空\r\n"
                        L"\r\n"
                        L"注意事项:\r\n"
                        L"• 使用 API Token 而非 Global API Key（Token 可限定权限范围）\r\n"
                        L"• Global API Key 拥有账户全部权限，不推荐使用\r\n"
                        L"• 域名必须在 Cloudflare DNS 中管理（NS 指向 Cloudflare）";
                }
                SetWindowTextW(hTut, txt);
            }
            return 0;
        } else if (id == 31) {
            HWND hStatus = GetDlgItem(hw, 30);
            SetWindowTextW(hStatus, L"验证中...");
            SetWindowTextW(GetDlgItem(hw, 31), L"验证中...");
            EnableWindow(GetDlgItem(hw, 31), FALSE);
            wchar_t buf[512];
            GetWindowTextW(GetDlgItem(hw, IDC_DNS_ID), buf, 512);
            std::wstring idVal = buf;
            GetWindowTextW(GetDlgItem(hw, IDC_DNS_SECRET), buf, 512);
            std::wstring secVal = buf;
            int curProv = (int)SendMessageW(GetDlgItem(hw, IDC_DNS_PROV), CB_GETCURSEL, 0, 0) + 1;
            if ((curProv == DNS_PROVIDER_CLOUDFLARE && secVal.empty()) ||
                (curProv != DNS_PROVIDER_CLOUDFLARE && (idVal.empty() || secVal.empty()))) {
                SetWindowTextW(hStatus, L"密钥不能为空");
                SetWindowTextW(GetDlgItem(hw, 31), L"验证密钥");
                EnableWindow(GetDlgItem(hw, 31), TRUE);
            } else {
                int sel = (int)SendMessageW(GetDlgItem(hw, IDC_DNS_PROV), CB_GETCURSEL, 0, 0) + 1;
                HWND hBtn = GetDlgItem(hw, 31);
                struct VerifyParams { HWND hw; HWND hStatus; HWND hBtn; int provider; std::wstring apiId; std::wstring apiSecret; };
                VerifyParams* params = new VerifyParams{ hw, hStatus, hBtn, sel, idVal, secVal };
                HANDLE hThread = (HANDLE)_beginthreadex(0, 0, [](void* p)->unsigned {
                    VerifyParams* params = (VerifyParams*)p;
                    bool apiOk = DnsVerifyApi(params->provider, params->apiId, params->apiSecret);
                    SafeSetWindowText(params->hStatus, apiOk ? L"验证通过" : L"验证失败(密钥无效)");
                    SafeSetWindowText(params->hBtn, L"验证密钥");
                    SafeEnableWindow(params->hBtn, TRUE);
                    delete params;
                    return 0;
                }, params, 0, 0);
                if (hThread) CloseHandle(hThread);
            }
            return 0;
        }
    } else if (msg == WM_CLOSE) {
        DestroyWindow(hw);
        return 0;
    } else if (msg == WM_DESTROY) {
        SetWindowLongPtrW(hw, GWLP_WNDPROC, (LONG_PTR)g_OrigDnsDlgProc);
        g_OrigDnsDlgProc = NULL;
        return 0;
    }
    return CallWindowProcW(g_OrigDnsDlgProc, hw, msg, wp, lp);
}

// 显示 DNS API 配置对话框
void ShowDnsConfigDialog(HWND hwParent, const std::wstring& overrideDomain) {
    // 优先使用传入域名，否则读主界面域名
    if (!overrideDomain.empty()) {
        g_DnsConfigDomain = overrideDomain;
    } else {
        wchar_t domainBuf[512];
        GetWindowTextW(g_hDomain, domainBuf, 512);
        g_DnsConfigDomain = domainBuf;
    }

    // 从 INI 独立加载指定域名的 DNS 配置（不污染全局变量）
    int dnsProv = DNS_PROVIDER_ALIYUN;
    std::wstring dnsApiId, dnsApiSecret;
    {
        std::wstring baseDomain = g_DnsConfigDomain;
        if (baseDomain.size() >= 2 && baseDomain[0] == L'*' && baseDomain[1] == L'.')
            baseDomain = baseDomain.substr(2);
        std::wstring sec = DnsSectionName(baseDomain);
        std::wstring ini = g_IniPath;
        wchar_t buf[512];
        GetPrivateProfileStringW(sec.c_str(), L"Provider", L"", buf, 512, ini.c_str());
        if (buf[0] != 0) {
            int p = _wtoi(buf);
            if (p >= 1 && p <= 3) dnsProv = p;
            GetPrivateProfileStringW(sec.c_str(), L"ApiId", L"", buf, 512, ini.c_str());
            dnsApiId = buf;
            if (dnsApiId.size() >= 4 && (dnsApiId.substr(0, 4) == L"aes-" || dnsApiId.substr(0, 4) == L"enc-"))
                dnsApiId = GetProtectedProfileStringW(ini.c_str(), sec.c_str(), L"ApiId", L"");
            GetPrivateProfileStringW(sec.c_str(), L"ApiSecret", L"", buf, 512, ini.c_str());
            dnsApiSecret = buf;
            if (dnsApiSecret.size() >= 4 && (dnsApiSecret.substr(0, 4) == L"aes-" || dnsApiSecret.substr(0, 4) == L"enc-"))
                dnsApiSecret = GetProtectedProfileStringW(ini.c_str(), sec.c_str(), L"ApiSecret", L"");
        } else {
            // 该域名无独立配置，回退读全局默认
            GetPrivateProfileStringW(L"DNSConfig", L"Provider", L"1", buf, 512, ini.c_str());
            int p = _wtoi(buf);
            if (p >= 1 && p <= 3) dnsProv = p;
            GetPrivateProfileStringW(L"DNSConfig", L"ApiId", L"", buf, 512, ini.c_str());
            dnsApiId = buf;
            if (dnsApiId.size() >= 4 && (dnsApiId.substr(0, 4) == L"aes-" || dnsApiId.substr(0, 4) == L"enc-"))
                dnsApiId = GetProtectedProfileStringW(ini.c_str(), L"DNSConfig", L"ApiId", L"");
            GetPrivateProfileStringW(L"DNSConfig", L"ApiSecret", L"", buf, 512, ini.c_str());
            dnsApiSecret = buf;
            if (dnsApiSecret.size() >= 4 && (dnsApiSecret.substr(0, 4) == L"aes-" || dnsApiSecret.substr(0, 4) == L"enc-"))
                dnsApiSecret = GetProtectedProfileStringW(ini.c_str(), L"DNSConfig", L"ApiSecret", L"");
        }
    }

    const int DLG_W = 480, DLG_H = 480;
    RECT rcParent; GetWindowRect(hwParent, &rcParent);
    int cx = rcParent.left + (rcParent.right - rcParent.left - DLG_W) / 2;
    int cy = rcParent.top + (rcParent.bottom - rcParent.top - DLG_H) / 2;

    std::wstring dlgTitle = L"DNS API 配置";
    if (!g_DnsConfigDomain.empty()) dlgTitle += L" - " + g_DnsConfigDomain;
    HWND hDlg = CreateWindowExW(WS_EX_WINDOWEDGE | WS_EX_CONTROLPARENT,
        L"#32770", dlgTitle.c_str(),
        WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        cx, cy, DLG_W, DLG_H, hwParent, 0, 0, 0);

    HFONT f = (HFONT)GetPropW(hwParent, L"F");
    RECT rcClient; GetClientRect(hDlg, &rcClient);
    int clientW = rcClient.right - rcClient.left;
    int padX = 20, padY = 20;
    int contentW = clientW - padX * 2;
    int lblW = 90, gap = 12;
    int inpX = padX + lblW + gap;
    int inpW = contentW - lblW - gap;
    int rowH = 28, gapY = 10, y = padY;
    HWND hStatus = NULL;

    // 域名提示（只读，显示当前域名）
    std::wstring domainHint = g_DnsConfigDomain.empty() ? L"(未填写域名)" : g_DnsConfigDomain;
    CreateWindowW(L"STATIC", L"域名", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
        padX, y, lblW, rowH, hDlg, 0, 0, 0);
    SendMessageW(GetDlgItem(hDlg, 0xFFFF), WM_SETFONT, (WPARAM)f, 0);
    CreateWindowW(L"STATIC", domainHint.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        inpX, y, inpW, rowH, hDlg, 0, 0, 0);
    SendMessageW(GetDlgItem(hDlg, 0xFFFF), WM_SETFONT, (WPARAM)f, 0);

    y += rowH + gapY;
    // 提供商下拉框
    CreateWindowW(L"STATIC", L"提供商", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
        padX, y, lblW, rowH, hDlg, 0, 0, 0);
    SendMessageW(GetDlgItem(hDlg, 0xFFFF), WM_SETFONT, (WPARAM)f, 0);
    HWND hProv = CreateWindowW(L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL | WS_TABSTOP,
        inpX, y, inpW, 120, hDlg, (HMENU)IDC_DNS_PROV, 0, 0);
    SendMessageW(hProv, WM_SETFONT, (WPARAM)f, 0);
    SendMessageW(hProv, CB_ADDSTRING, 0, (LPARAM)L"阿里云 DNS");
    SendMessageW(hProv, CB_ADDSTRING, 0, (LPARAM)L"腾讯云 DNS");
    SendMessageW(hProv, CB_ADDSTRING, 0, (LPARAM)L"Cloudflare");
    SendMessageW(hProv, CB_SETCURSEL, dnsProv - 1, 0);

    y += rowH + gapY;
    CreateWindowW(L"STATIC", L"AccessKey ID", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
        padX, y, lblW, rowH, hDlg, (HMENU)IDC_DNS_LBL_ID, 0, 0);
    SendMessageW(GetDlgItem(hDlg, IDC_DNS_LBL_ID), WM_SETFONT, (WPARAM)f, 0);
    CreateWindowW(L"EDIT", dnsApiId.c_str(), WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP,
        inpX, y, inpW, rowH, hDlg, (HMENU)IDC_DNS_ID, 0, 0);
    SendMessageW(GetDlgItem(hDlg, IDC_DNS_ID), WM_SETFONT, (WPARAM)f, 0);

    y += rowH + gapY;
    CreateWindowW(L"STATIC", L"AccessKey Secret", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
        padX, y, lblW, rowH, hDlg, (HMENU)IDC_DNS_LBL_SECRET, 0, 0);
    SendMessageW(GetDlgItem(hDlg, IDC_DNS_LBL_SECRET), WM_SETFONT, (WPARAM)f, 0);
    CreateWindowW(L"EDIT", dnsApiSecret.c_str(), WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_PASSWORD | WS_TABSTOP,
        inpX, y, inpW, rowH, hDlg, (HMENU)IDC_DNS_SECRET, 0, 0);
    SendMessageW(GetDlgItem(hDlg, IDC_DNS_SECRET), WM_SETFONT, (WPARAM)f, 0);

    // 根据当前提供商初始化标签文本
    if (dnsProv == DNS_PROVIDER_TENCENT) {
        SetWindowTextW(GetDlgItem(hDlg, IDC_DNS_LBL_ID), L"SecretId");
        SetWindowTextW(GetDlgItem(hDlg, IDC_DNS_LBL_SECRET), L"SecretKey");
    } else if (dnsProv == DNS_PROVIDER_CLOUDFLARE) {
        SetWindowTextW(GetDlgItem(hDlg, IDC_DNS_LBL_ID), L"备注(可选)");
        SetWindowTextW(GetDlgItem(hDlg, IDC_DNS_LBL_SECRET), L"API Token");
    }

    y += rowH + gapY;
    // 验证状态行 + 验证密钥按钮 + 保存按钮同一行
    CreateWindowW(L"STATIC", L"验证状态", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
        padX, y, lblW, rowH, hDlg, 0, 0, 0);
    SendMessageW(GetDlgItem(hDlg, 0xFFFF), WM_SETFONT, (WPARAM)f, 0);
    hStatus = CreateWindowW(L"STATIC", L"未验证", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        inpX, y, 80, rowH, hDlg, (HMENU)30, 0, 0);
    SendMessageW(hStatus, WM_SETFONT, (WPARAM)f, 0);
    HWND hVerify = CreateWindowW(L"BUTTON", L"验证", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
        inpX + 88, y, 80, rowH, hDlg, (HMENU)31, 0, 0);
    SendMessageW(hVerify, WM_SETFONT, (WPARAM)f, 0);
    HWND hSave = CreateWindowW(L"BUTTON", L"保存", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP | BS_DEFPUSHBUTTON,
        inpX + 88 + 80 + 8, y, 80, rowH, hDlg, (HMENU)IDC_DNS_OK, 0, 0);
    SendMessageW(hSave, WM_SETFONT, (WPARAM)f, 0);

    // ── 分隔线 + 教程区域 ──
    y += rowH + 8;
    CreateWindowW(L"STATIC", L"SS_ETCHEDHORZ", WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
        padX, y, contentW, 2, hDlg, 0, 0, 0);
    y += 8;
    CreateWindowW(L"STATIC", L"密钥获取方法", WS_CHILD | WS_VISIBLE | SS_LEFT,
        padX, y, contentW, 18, hDlg, 0, 0, 0);
    SendMessageW(GetDlgItem(hDlg, 0xFFFF), WM_SETFONT, (WPARAM)f, 0);
    y += 20;
    // 教程文本（多行只读编辑框，ID=40）
    HWND hTutorial = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY,
        padX, y, contentW, rcClient.bottom - y - padY, hDlg, (HMENU)40, 0, 0);
    SendMessageW(hTutorial, WM_SETFONT, (WPARAM)f, 0);

    // 根据当前提供商显示教程
    auto showTutorial = [hTutorial](int prov) {
        const wchar_t* txt = nullptr;
        if (prov == DNS_PROVIDER_ALIYUN) {
            txt = L"1. 登录阿里云控制台 https://home.console.aliyun.com\r\n"
                L"2. 右上角头像 → AccessKey 管理\r\n"
                L"3. 建议创建 RAM 子用户（最小权限原则）:\r\n"
                L"   - 授权策略: AliyunDNSFullAccess\r\n"
                L"   - 或自定义策略，只允许 DNS 相关操作\r\n"
                L"4. 创建 AccessKey，记录 AccessKey ID 和 AccessKey Secret\r\n"
                L"5. 将 AccessKey ID 填入上方 ID 栏，AccessKey Secret 填入 Secret 栏\r\n"
                L"\r\n"
                L"注意事项:\r\n"
                L"• AccessKey Secret 只在创建时显示一次，请妥善保存\r\n"
                L"• 主账号 Key 拥有全部权限，强烈建议使用 RAM 子账号\r\n"
                L"• 域名必须在阿里云 DNS 解析中管理（非万网DNS需先迁移）";
        } else if (prov == DNS_PROVIDER_TENCENT) {
            txt = L"1. 登录腾讯云控制台 https://console.cloud.tencent.com\r\n"
                L"2. 访问 API 密钥管理 https://console.cloud.tencent.com/cam/capi\r\n"
                L"3. 建议创建子账号（最小权限原则）:\r\n"
                L"   - 授权策略: QcloudDNSPodFullAccess\r\n"
                L"   - 或自定义策略，只允许 DNSPOD 相关操作\r\n"
                L"4. 创建密钥，记录 SecretId 和 SecretKey\r\n"
                L"5. 将 SecretId 填入上方 ID 栏，SecretKey 填入 Secret 栏\r\n"
                L"\r\n"
                L"注意事项:\r\n"
                L"• SecretKey 只在创建时显示一次，请妥善保存\r\n"
                L"• 主账号 Key 拥有全部权限，强烈建议使用子账号\r\n"
                L"• 域名必须在 DNSPod 解析中管理（非腾讯云DNS需先迁移）";
        } else {
            txt = L"Cloudflare API Token 获取方法:\r\n"
                L"\r\n"
                L"1. 登录 Cloudflare https://dash.cloudflare.com\r\n"
                L"2. 右上角头像 → My Profile → API Tokens\r\n"
                L"3. 点击 Create Token\r\n"
                L"4. 使用模板「Edit zone DNS」或自定义:\r\n"
                L"   - Permissions: Zone - DNS - Edit\r\n"
                L"   - Zone Resources: Include - Specific zone - 你的域名\r\n"
                L"5. 创建后复制 Token（只显示一次）\r\n"
                L"6. 将 Token 填入上方 Secret 栏，ID 栏可留空\r\n"
                L"\r\n"
                L"注意事项:\r\n"
                L"• 使用 API Token 而非 Global API Key（Token 可限定权限范围）\r\n"
                L"• Global API Key 拥有账户全部权限，不推荐使用\r\n"
                L"• 域名必须在 Cloudflare DNS 中管理（NS 指向 Cloudflare）";
        }
        SetWindowTextW(hTutorial, txt);
    };
    showTutorial(dnsProv);
    // 切换提供商时更新教程
    SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)hTutorial);

    g_OrigDnsDlgProc = (WNDPROC)SetWindowLongPtrW(hDlg, GWLP_WNDPROC, (LONG_PTR)DnsConfigDlgProc);

    ShowWindow(hDlg, SW_SHOW);
    SetFocus(hSave);
}

// 显示续签详情对话框（含吊销按钮）
static void ShowDetailDialog(HWND hwParent) {
    HWND hL = GetDlgItem(hwParent, 100);
    int sel = ListView_GetNextItem(hL, -1, LVNI_SELECTED);
    if (sel < 0) { MessageBoxW(hwParent, L"请先选择一条记录", L"提示", MB_OK); return; }
    std::vector<RenewalRecord> records; LoadRenewalRecords(records);
    if (sel >= (int)records.size()) return;
    auto& r = records[sel];

    wchar_t expiryStr[64] = L"未知";
    if (r.expiryTime.dwLowDateTime || r.expiryTime.dwHighDateTime) {
        FILETIME ft2; SYSTEMTIME st2;
        FileTimeToLocalFileTime(&r.expiryTime, &ft2);
        FileTimeToSystemTime(&ft2, &st2);
        swprintf_s(expiryStr, L"%04d-%02d-%02d", st2.wYear, st2.wMonth, st2.wDay);
    }
    wchar_t issueStr[64] = L"未知";
    if (r.issueTime.dwLowDateTime || r.issueTime.dwHighDateTime) {
        FILETIME ft2; SYSTEMTIME st2;
        FileTimeToLocalFileTime(&r.issueTime, &ft2);
        FileTimeToSystemTime(&ft2, &st2);
        swprintf_s(issueStr, L"%04d-%02d-%02d", st2.wYear, st2.wMonth, st2.wDay);
    }
    wchar_t daysStr[32] = L"未知";
    if (r.expiryTime.dwLowDateTime || r.expiryTime.dwHighDateTime) {
        FILETIME now; GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER u1, u2;
        u1.LowPart = r.expiryTime.dwLowDateTime; u1.HighPart = r.expiryTime.dwHighDateTime;
        u2.LowPart = now.dwLowDateTime; u2.HighPart = now.dwHighDateTime;
        int d = (int)((u1.QuadPart - u2.QuadPart) / 864000000000LL);
        if (d >= 0) swprintf_s(daysStr, L"%d 天", d);
        else swprintf_s(daysStr, L"已过期 %d 天", -d);
    }

    extern std::wstring g_IniPath;
    wchar_t iniBuf[2048];
    GetPrivateProfileStringW(L"SSLClaw", L"SaveDir", L"", iniBuf, 2048, g_IniPath.c_str());
    std::wstring displaySaveDir(iniBuf);
    if (displaySaveDir.empty()) displaySaveDir = r.saveDir;

    wchar_t msg[2048];
    swprintf_s(msg, L"域名: %s%s\nFriendlyName: %s\n签发: %s  过期: %s\n剩余: %s\n自动续签: %s  阈值: %d 天\n验证: %s  邮箱: %s\n保存目录: %s\n指纹: %s",
        r.wildcard ? L"*." : L"", r.domain.c_str(),
        r.friendlyName.empty() ? L"(无)" : r.friendlyName.c_str(),
        issueStr, expiryStr, daysStr,
        r.autoRenew ? L"是" : L"否", r.renewalDays,
        r.verifyMode == 0 ? L"HTTP-01" : L"DNS-01",
        r.email.empty() ? L"(无)" : r.email.c_str(),
        displaySaveDir.empty() ? L"(未设置)" : displaySaveDir.c_str(),
        r.thumbprint.empty() ? L"(无)" : r.thumbprint.c_str());

    MessageBoxW(hwParent, msg, L"续签详情", MB_OK | MB_ICONINFORMATION);
}

// 续签窗口过程函数
LRESULT CALLBACK RenewWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_COMMAND) {
        int id = LOWORD(wp);
        HWND hL = GetDlgItem(hw, 100);

        if (id == 101) {
            // 立即续签（后台线程，避免UI卡死）
            int sel = ListView_GetNextItem(hL, -1, LVNI_SELECTED);
            if (sel < 0) { MessageBoxW(hw, L"请先选择一个证书", L"提示", MB_OK); return 0; }
            wchar_t domain[256] = {};
            ListView_GetItemText(hL, sel, 0, domain, 256);
            std::vector<RenewalRecord> records; LoadRenewalRecords(records);
            int ri = FindRenewalByDomain(records, std::wstring(domain));
            if (ri >= 0) {
                if (IsDomainRenewing(records[ri].domain)) {
                    MessageBoxW(hw, L"该域名正在后台续签中，请稍候", L"提示", MB_OK);
                    return 0;
                }
                // 禁用按钮防止重复点击
                EnableWindow(GetDlgItem(hw, 101), FALSE);
                std::wstring renewDomain = records[ri].domain;
                {
                    extern std::wstring g_IniPath;
                    wchar_t iniBuf[2048];
                    GetPrivateProfileStringW(L"SSLClaw", L"SaveDir", L"", iniBuf, 2048, g_IniPath.c_str());
                    std::wstring mainSaveDir(iniBuf);
                    if (!mainSaveDir.empty()) records[ri].saveDir = mainSaveDir;
                }
                std::thread([hw, record = records[ri]]() mutable {
                    bool ok = PerformRenewalWithRetry(record);
                    if (ok) AddOrUpdateRenewal(record);
                    PostMessageW(hw, WM_USER + 2, ok ? 1 : 0, 0);
                }).detach();
            } else {
                MessageBoxW(hw, L"未找到续签记录，请通过主界面重新申请", L"提示", MB_OK);
            }
        } else if (id == 102) {
            SendMessageW(hw, WM_USER+1, 0, 0);
        } else if (id == 103) {
            // 切换自动续签
            int sel = ListView_GetNextItem(hL, -1, LVNI_SELECTED);
            if (sel < 0) { MessageBoxW(hw, L"请先选择一个证书", L"提示", MB_OK); return 0; }
            wchar_t domain[256] = {};
            ListView_GetItemText(hL, sel, 0, domain, 256);
            std::vector<RenewalRecord> records; LoadRenewalRecords(records);
            int ri = FindRenewalByDomain(records, std::wstring(domain));
            if (ri >= 0) {
                records[ri].autoRenew = !records[ri].autoRenew;
                SaveRenewalRecords(records);
                wchar_t arText[16]; wcscpy_s(arText, records[ri].autoRenew ? L"已开启" : L"未开启");
                ListView_SetItemText(hL, sel, 3, arText);
                ListView_SetCheckState(hL, sel, records[ri].autoRenew ? TRUE : FALSE);
                if (records[ri].autoRenew && !IsRenewalBackgroundRunning()) {
                    StartRenewalBackgroundThread();
                    MessageBoxW(hw, L"已启动后台续签检查（每 6 小时自动检查）\n无需 Windows 计划任务", L"自动续签", MB_OK);
                }
                if (!records[ri].autoRenew) {
                    bool anyAuto = false;
                    for (auto& r : records) if (r.autoRenew) { anyAuto = true; break; }
                    if (!anyAuto) StopRenewalBackgroundThread();
                }
            } else {
                MessageBoxW(hw, L"未找到续签记录，请通过主界面重新申请", L"提示", MB_OK);
            }
        } else if (id == 104) {
            // DNS API 配置 - 使用选中记录的域名
            int sel = ListView_GetNextItem(hL, -1, LVNI_SELECTED);
            std::wstring dnsDomain;
            if (sel >= 0) {
                wchar_t domain[256] = {};
                ListView_GetItemText(hL, sel, 0, domain, 256);
                dnsDomain = domain;
            }
            if (dnsDomain.empty()) {
                MessageBoxW(hw, L"请先选择一条续签记录", L"提示", MB_OK);
                return 0;
            }
            ShowDnsConfigDialog(hw, dnsDomain);
        } else if (id == 105 || id == 107 || id == 1099) {
            // 已移除的按钮ID，忽略
        }
    } else if (msg == WM_USER + 2) {
        // 续签完成回调（后台线程通过 PostMessage 触发）
        EnableWindow(GetDlgItem(hw, 101), TRUE);
        SendMessageW(hw, WM_USER + 1, 0, 0);
        if (wp == 1) MessageBoxW(hw, L"续签成功", L"提示", MB_OK);
        else MessageBoxW(hw, L"续签失败，请查看日志", L"错误", MB_ICONERROR);
    } else if (msg == WM_USER+1) {
        // 刷新列表 - 基于 RenewalRecord，不扫 Certificate Store
        HWND hL = GetDlgItem(hw, 100);
        HWND hSt = GetDlgItem(hw, 106);
        ListView_DeleteAllItems(hL);

        std::vector<RenewalRecord> records;
        LoadRenewalRecords(records);
        if (records.empty()) {
            SetWindowTextW(hSt, L"暂无续签记录，请先通过主界面申请证书");
            return 0;
        }

        int idx = 0;
        for (auto& r : records) {
            LVITEMW item = {};
            item.mask = LVIF_TEXT;
            item.iItem = idx;
            // 域名列固定显示 domain（续签查找需用 domain 匹配）
            wchar_t subjBuf[256]; wcscpy_s(subjBuf, r.domain.c_str());
            item.pszText = subjBuf;
            ListView_InsertItem(hL, &item);

            // 过期时间
            wchar_t expiryStr[64] = L"未知";
            if (r.expiryTime.dwLowDateTime || r.expiryTime.dwHighDateTime) {
                FILETIME ft2; SYSTEMTIME st2;
                FileTimeToLocalFileTime(&r.expiryTime, &ft2);
                FileTimeToSystemTime(&ft2, &st2);
                swprintf_s(expiryStr, L"%04d-%02d-%02d", st2.wYear, st2.wMonth, st2.wDay);
            }
            ListView_SetItemText(hL, idx, 1, expiryStr);

            // 剩余天数
            wchar_t daysStr[32] = L"未知";
            if (r.expiryTime.dwLowDateTime || r.expiryTime.dwHighDateTime) {
                FILETIME now; GetSystemTimeAsFileTime(&now);
                ULARGE_INTEGER u1, u2;
                u1.LowPart = r.expiryTime.dwLowDateTime; u1.HighPart = r.expiryTime.dwHighDateTime;
                u2.LowPart = now.dwLowDateTime; u2.HighPart = now.dwHighDateTime;
                int daysLeft = (int)((u1.QuadPart - u2.QuadPart) / 864000000000LL);
                if (daysLeft >= 0) swprintf_s(daysStr, L"%d", daysLeft);
                else swprintf_s(daysStr, L"过期%d", -daysLeft);
            }
            ListView_SetItemText(hL, idx, 2, daysStr);

            // 自动续签
            ListView_SetCheckState(hL, idx, r.autoRenew ? TRUE : FALSE);
            wchar_t arText[8]; wcscpy_s(arText, r.autoRenew ? L"开" : L"关");
            ListView_SetItemText(hL, idx, 3, arText);

            // DNS 提供商
            wchar_t vmText[32];
            if (r.verifyMode == 0) wcscpy_s(vmText, L"HTTP-01");
            else if (r.dnsProvider == DNS_PROVIDER_ALIYUN) wcscpy_s(vmText, L"阿里云");
            else if (r.dnsProvider == DNS_PROVIDER_TENCENT) wcscpy_s(vmText, L"腾讯云");
            else if (r.dnsProvider == DNS_PROVIDER_CLOUDFLARE) wcscpy_s(vmText, L"Cloudflare");
            else wcscpy_s(vmText, L"DNS-01手动");
            ListView_SetItemText(hL, idx, 4, vmText);
            idx++;
        }
        wchar_t buf[64]; swprintf_s(buf, L"共 %d 个续签记录", idx);
        SetWindowTextW(hSt, buf);

        // 检测本地 Web 服务器并显示在右侧
        std::wstring ws = DetectWebServer();
        HWND hWs = GetDlgItem(hw, 107);
        if (hWs) SetWindowTextW(hWs, ws.empty() ? L"未检测到 Web 服务器" : ws.c_str());
    } else if (msg == WM_NOTIFY) {
        NMHDR* pnm = (NMHDR*)lp;
        if (pnm->idFrom == 100 && pnm->code == NM_DBLCLK) {
            // 双击列表项 = 详情
            ShowDetailDialog(hw);
        } else if (pnm->idFrom == 100 && pnm->code == LVN_ITEMCHANGED) {
            NMLISTVIEW* pnmv = (NMLISTVIEW*)lp;
            if (pnmv->uChanged & LVIF_STATE) {
                BOOL newCheck = ListView_GetCheckState(pnmv->hdr.hwndFrom, pnmv->iItem);
                wchar_t domain[256] = {};
                ListView_GetItemText(pnmv->hdr.hwndFrom, pnmv->iItem, 0, domain, 256);
                std::vector<RenewalRecord> records; LoadRenewalRecords(records);
                int ri = FindRenewalByDomain(records, std::wstring(domain));
                if (ri >= 0) {
                    bool wasAuto = records[ri].autoRenew;
                    records[ri].autoRenew = (newCheck == TRUE);
                    SaveRenewalRecords(records);
                    wchar_t arText[16]; wcscpy_s(arText, records[ri].autoRenew ? L"已开启" : L"未开启");
                    ListView_SetItemText(pnmv->hdr.hwndFrom, pnmv->iItem, 3, arText);
                    if (records[ri].autoRenew && !wasAuto && !IsRenewalBackgroundRunning()) {
                        StartRenewalBackgroundThread();
                        MessageBoxW(hw, L"已启动后台续签检查（每 6 小时自动检查）\n无需 Windows 计划任务", L"自动续签", MB_OK);
                    }
                    if (!records[ri].autoRenew && wasAuto) {
                        bool anyAuto = false;
                        for (auto& r : records) if (r.autoRenew) { anyAuto = true; break; }
                        if (!anyAuto) StopRenewalBackgroundThread();
                    }
                }
            }
        }
    } else if (msg == WM_DESTROY) {
        HWND hLv = GetDlgItem(hw, 100);
        if (hLv) {
            for (int i = 0; i < 5; i++) {
                int w = ListView_GetColumnWidth(hLv, i);
                wchar_t key[8], val[16];
                swprintf_s(key, L"Col%d", i);
                swprintf_s(val, L"%d", w);
                WritePrivateProfileStringW(L"RenewalList", key, val, g_IniPath.c_str());
            }
        }
        SetWindowLongPtrW(hw, GWLP_WNDPROC, (LONG_PTR)g_OrigRenewProc);
        g_RenewWnd = NULL;
    }
    return CallWindowProcW(g_OrigRenewProc, hw, msg, wp, lp);
}

// UI 控件句柄
HWND g_hWnd = NULL;
HWND g_hDomain = NULL;
HWND g_hEmail = NULL;
HWND g_hBtnApply = NULL;
HWND g_hLog = NULL;
HWND g_hStatus = NULL;
HWND g_hSaveDirEdit = NULL;
HWND g_hBtnBrowse = NULL;
HWND g_hBtnOpen = NULL;
HWND g_hDaysEdit = NULL;
HWND g_hServer = NULL;
HWND g_hIP = NULL;
HWND g_hVerifyMode = NULL;
LRESULT CALLBACK NoWheelComboProc(HWND hw, UINT msg, WPARAM w, LPARAM l) {
    if (msg == WM_MOUSEWHEEL) return 0;
    WNDPROC oldProc = (WNDPROC)GetWindowLongPtrW(hw, GWLP_USERDATA);
    return CallWindowProcW(oldProc, hw, msg, w, l);
}
HWND g_hWebRoot = NULL;
HWND g_hBtnWebRootBrowse = NULL;
HWND g_hBtnWebRootOpen = NULL;
HWND g_hCA = NULL;       // CA 名称文本
HWND g_hCAEnv = NULL;    // CA 环境选择(生产/测试)
int g_CAEnvIndex = 0;    // 0=生产 1=测试
HWND g_hCAInd = NULL;    // CA 连接指示灯
HWND g_hCAStatus = NULL; // CA 状态文字
HWND g_hWildcard = NULL; // 通配符复选框
HWND g_hBtnDnsConfig = NULL; // DNS API 配置按钮

// CA 指示灯状态: 0=检测中(灰) 1=可连接(绿) 2=不可连接(红)
int g_caStatus = 0;

// IP 轮播
std::vector<std::wstring> g_ipList;
int g_ipIndex = 0;
#define IP_TIMER_ID 1001

// 全局状态
std::wstring g_SaveDir;
std::wstring g_IniPath;

// 验证步骤提示(避免 main.cpp 与 ssl_ui.cpp 重复)
void ShowVerifySteps(int vm) {
    if (vm == 0) {
        LogUI(L"HTTP-01 验证步骤:");
        LogUI(L"1. 填写域名");
        LogUI(L"2. 填写邮箱(可选填,用于接收到期提醒)");
        LogUI(L"3. 点击\"申请证书\"");
        LogUI(L"4. 若本机80端口空闲,自动启动临时验证服务器");
        LogUI(L"5. 若80端口被占用(Web服务器运行中),需填写网站目录(即 index.html 所在文件夹)");
        LogUI(L"6. CA 完成验证后自动签发证书");
        LogUI(L"");
        LogUI(L"说明: 验证时域名 A 记录需指向本机");
    } else {
        LogUI(L"DNS-01 验证步骤:");
        LogUI(L"");
        LogUI(L"【方式一】DNS API 自动化（推荐）:");
        LogUI(L"1. 填写域名和邮箱");
        LogUI(L"2. 点击「DNS API 配置」按钮");
        LogUI(L"3. 选择 DNS 提供商（阿里云/腾讯云/Cloudflare）");
        LogUI(L"4. 填入 API 密钥并验证（点击教程查看获取方法）");
        LogUI(L"5. 点击「申请证书」，工具自动添加 TXT 记录并验证");
        LogUI(L"");
        LogUI(L"【方式二】手动添加 TXT 记录:");
        LogUI(L"1. 填写域名和邮箱");
        LogUI(L"2. 点击「申请证书」，日志栏显示 TXT 记录值");
        LogUI(L"3. 登录域名 DNS 管理后台");
        LogUI(L"4. 添加 DNS TXT 记录:");
        LogUI(L"   主机记录: _acme-challenge");
        LogUI(L"   记录类型: TXT");
        LogUI(L"   记录值:  日志栏显示的值(区分大小写)");
        LogUI(L"5. 等待 DNS 记录生效(通常需数分钟)");
        LogUI(L"6. 点击「继续验证」按钮");
        LogUI(L"");
        LogUI(L"说明: DNS API 自动化支持通配符证书(*.域名)和自动续签");
        LogUI(L"      手动模式不支持自动续签，证书到期需手动重新申请");
    }
}

// 日志输出(同时写文件)
void LogToFile(const wchar_t* msg) {
    extern std::wstring g_LogFilePath;
    if (g_LogFilePath.empty()) return;
    HANDLE h = CreateFileW(g_LogFilePath.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    if (GetFileSize(h, NULL) == 0) {
        static const BYTE bom[2] = { 0xFF, 0xFE };
        WriteFile(h, bom, 2, &written, NULL);
    }
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t prefix[64]; swprintf_s(prefix, L"[%04d-%02d-%02d %02d:%02d:%02d] ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    WriteFile(h, prefix, (DWORD)wcslen(prefix) * sizeof(wchar_t), &written, NULL);
    WriteFile(h, msg, (DWORD)wcslen(msg) * sizeof(wchar_t), &written, NULL);
    const wchar_t* crlf = L"\r\n";
    WriteFile(h, crlf, 4, &written, NULL);
    CloseHandle(h);
}

void Log(const wchar_t* fmt, ...) {
    wchar_t buf[4096]; va_list va; va_start(va, fmt);
    _vsnwprintf_s(buf, sizeof(buf) / sizeof(wchar_t), fmt, va); va_end(va);
    LogToFile(buf);
    if (!g_hLog || !IsWindow(g_hLog)) return;
    if (GetCurrentThreadId() != GetWindowThreadProcessId(g_hLog, NULL)) {
        std::wstring* pMsg = new std::wstring(buf);
        PostMessageW(g_hWnd, WM_LOG_MSG, 0, (LPARAM)pMsg);
        return;
    }
    InitLogCs();
    EnterCriticalSection(&g_LogCs);
    int len = GetWindowTextLengthW(g_hLog);
    if (len > 200000) {
        SetWindowTextW(g_hLog, L"...(日志过长，已截断)\r\n");
        len = 0;
    }
    if (len > 0) {
        SendMessageW(g_hLog, EM_SETSEL, len, len);
        std::wstring msg = buf; msg += L"\r\n";
        SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)msg.c_str());
    } else {
        std::wstring msg = buf; msg += L"\r\n";
        SetWindowTextW(g_hLog, msg.c_str());
        SendMessageW(g_hLog, EM_SETSEL, msg.size(), msg.size());
    }
    if (g_AutoScroll) SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
    LeaveCriticalSection(&g_LogCs);
}

// 仅显示到UI不写日志文件
void LogUI(const wchar_t* fmt, ...) {
    wchar_t buf[4096]; va_list va; va_start(va, fmt);
    _vsnwprintf_s(buf, sizeof(buf) / sizeof(wchar_t), fmt, va); va_end(va);
    if (!g_hLog || !IsWindow(g_hLog)) return;
    if (GetCurrentThreadId() != GetWindowThreadProcessId(g_hLog, NULL)) {
        std::wstring* pMsg = new std::wstring(buf);
        PostMessageW(g_hWnd, WM_LOG_MSG, 0, (LPARAM)pMsg);
        return;
    }
    InitLogCs();
    EnterCriticalSection(&g_LogCs);
    int len = GetWindowTextLengthW(g_hLog);
    if (len > 200000) {
        SetWindowTextW(g_hLog, L"...(日志过长，已截断)\r\n");
        len = 0;
    }
    if (len > 0) {
        SendMessageW(g_hLog, EM_SETSEL, len, len);
        std::wstring msg = buf; msg += L"\r\n";
        SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)msg.c_str());
    } else {
        std::wstring msg = buf; msg += L"\r\n";
        SetWindowTextW(g_hLog, msg.c_str());
        SendMessageW(g_hLog, EM_SETSEL, msg.size(), msg.size());
    }
    if (g_AutoScroll) SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
    LeaveCriticalSection(&g_LogCs);
}

// 设置状态栏
void SetStatus(const wchar_t* t) { SetWindowTextW(g_hStatus, t); }

void SafeSetStatus(const wchar_t* t) {
    if (!g_hWnd) return;
    if (GetCurrentThreadId() == GetWindowThreadProcessId(g_hWnd, NULL)) {
        SetWindowTextW(g_hStatus, t);
        return;
    }
    std::wstring* p = new std::wstring(t);
    PostMessageW(g_hWnd, WM_SAFE_SETSTATUS, 0, (LPARAM)p);
}

void SafeEnableWindow(HWND h, BOOL enable) {
    if (!h || !g_hWnd) return;
    if (GetCurrentThreadId() == GetWindowThreadProcessId(g_hWnd, NULL)) {
        EnableWindow(h, enable);
        return;
    }
    PostMessageW(g_hWnd, WM_SAFE_ENABLE, (WPARAM)h, enable ? 1 : 0);
}

void SafeSetWindowText(HWND h, const wchar_t* t) {
    if (!h || !g_hWnd) return;
    if (GetCurrentThreadId() == GetWindowThreadProcessId(g_hWnd, NULL)) {
        SetWindowTextW(h, t);
        return;
    }
    std::wstring* p = new std::wstring(t);
    PostMessageW(g_hWnd, WM_SAFE_SETTEXT, (WPARAM)h, (LPARAM)p);
}

void SafeInvalidateRect(HWND h) {
    if (!h || !g_hWnd) return;
    if (GetCurrentThreadId() == GetWindowThreadProcessId(g_hWnd, NULL)) {
        InvalidateRect(h, NULL, TRUE);
        return;
    }
    PostMessageW(g_hWnd, WM_SAFE_INVALIDATE, (WPARAM)h, 0);
}

// 根据验证模式显示/隐藏网站根目录行及通配符选项
void SyncWebRootVis() {
    int vm = (int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0);
    int show = (vm == 0) ? SW_SHOW : SW_HIDE;
    ShowWindow(GetDlgItem(g_hWnd, 28), show);
    ShowWindow(g_hWebRoot, show);
    ShowWindow(g_hBtnWebRootBrowse, show);
    ShowWindow(g_hBtnWebRootOpen, show);
    // 通配符复选框和DNS API配置按钮仅在 DNS-01 时显示
    int showWild = (vm == 1) ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hWildcard, showWild);
    ShowWindow(g_hBtnDnsConfig, showWild);
    if (vm != 1 && g_hWildcard)
        SendMessageW(g_hWildcard, BM_SETCHECK, BST_UNCHECKED, 0);
}

// IFileDialog 事件回调,首次居中
class DlgCenterEvents : public IFileDialogEvents {
    HWND m_owner;
    DWORD m_cookie;
    IFileDialog* m_pfd;
    bool m_done;
public:
    DlgCenterEvents(HWND owner, IFileDialog* pfd)
        : m_owner(owner), m_cookie(0), m_pfd(pfd), m_done(false) {}
    void Advise() { m_pfd->Advise(this, &m_cookie); }
    void Unadvise() { if (m_cookie) { m_pfd->Unadvise(m_cookie); m_cookie = 0; } }
    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_IFileDialogEvents) { *ppv = this; return S_OK; }
        *ppv = NULL; return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() { return 2; }
    STDMETHODIMP_(ULONG) Release() { return 1; }
    // IFileDialogEvents
    STDMETHODIMP OnFileOk(IFileDialog*) { return S_OK; }
    STDMETHODIMP OnFolderChanging(IFileDialog*, IShellItem*) { return S_OK; }
    STDMETHODIMP OnFolderChange(IFileDialog* pfd) {
        if (m_done) return S_OK;
        m_done = true;
        Unadvise();
        IOleWindow* pow = NULL;
        if (SUCCEEDED(pfd->QueryInterface(IID_PPV_ARGS(&pow)))) {
            HWND hDlg = NULL;
            if (SUCCEEDED(pow->GetWindow(&hDlg)) && hDlg) {
                RECT rd, ro; GetWindowRect(hDlg, &rd); GetWindowRect(m_owner, &ro);
                int x = ro.left + (ro.right - ro.left - (rd.right - rd.left)) / 2;
                int y = ro.top + (ro.bottom - ro.top - (rd.bottom - rd.top)) / 2;
                SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
            }
            pow->Release();
        }
        return S_OK;
    }
    STDMETHODIMP OnSelectionChange(IFileDialog*) { return S_OK; }
    STDMETHODIMP OnShareViolation(IFileDialog*, IShellItem*, FDE_SHAREVIOLATION_RESPONSE*) { return S_OK; }
    STDMETHODIMP OnTypeChange(IFileDialog*) { return S_OK; }
    STDMETHODIMP OnOverwrite(IFileDialog*, IShellItem*, FDE_OVERWRITE_RESPONSE*) { return S_OK; }
};

static bool PickFolder(HWND owner, const wchar_t* title, const std::wstring& defaultPath, std::wstring& outPath) {
    IFileDialog* pfd = NULL;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pfd)))) return false;
    pfd->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_DONTADDTORECENT);
    pfd->SetTitle(title);
    // 固定 GUID,用户拖小后系统记住尺寸和位置
    pfd->SetClientGuid({ 0xa1b2c3d4, 0xe5f6, 0x4a7b, { 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d } });
    if (!defaultPath.empty()) {
        IShellItem* psi = NULL;
        if (SUCCEEDED(SHCreateItemFromParsingName(defaultPath.c_str(), NULL, IID_PPV_ARGS(&psi)))) {
            pfd->SetDefaultFolder(psi);
            psi->Release();
        }
    }
    // 首次弹出居中:ini 中无标记则居中,之后由系统记住位置
    bool needCenter = (GetPrivateProfileIntW(L"SSLClaw", L"FolderDlgPos", 0, g_IniPath.c_str()) == 0);
    DlgCenterEvents* evt = NULL;
    if (needCenter) {
        evt = new DlgCenterEvents(owner, pfd);
        evt->Advise();
    }
    HRESULT hr = pfd->Show(owner);
    if (evt) { evt->Unadvise(); delete evt; }
    if (needCenter && SUCCEEDED(hr))
        WritePrivateProfileStringW(L"SSLClaw", L"FolderDlgPos", L"1", g_IniPath.c_str());
    if (FAILED(hr)) { pfd->Release(); return false; }
    IShellItem* psiResult = NULL;
    hr = pfd->GetResult(&psiResult);
    pfd->Release();
    if (FAILED(hr)) return false;
    LPWSTR pPath = NULL;
    hr = psiResult->GetDisplayName(SIGDN_FILESYSPATH, &pPath);
    psiResult->Release();
    if (FAILED(hr)) return false;
    outPath = pPath;
    CoTaskMemFree(pPath);
    return true;
}

void BrowseDir() {
    wchar_t dt[MAX_PATH];
            GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
    if (dt[0]) g_SaveDir = dt;
    std::wstring out;
    if (PickFolder(g_hWnd, L"选择证书保存目录", g_SaveDir, out)) {
        g_SaveDir = out;
        SetWindowTextW(g_hSaveDirEdit, out.c_str());
    }
}

// 窗口过程
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        HFONT f = CreateFontW(18, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, PROOF_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        HFONT fb = CreateFontW(20, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, PROOF_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

        CreateWindowW(L"STATIC", L"域名", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)20, 0, 0);
        SendMessageW(GetDlgItem(h, 20), WM_SETFONT, (WPARAM)f, 0);
        g_hDomain = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hDomain, WM_SETFONT, (WPARAM)f, 0);

        CreateWindowW(L"STATIC", L"邮箱", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)27, 0, 0);
        SendMessageW(GetDlgItem(h, 27), WM_SETFONT, (WPARAM)f, 0);
        g_hEmail = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hEmail, WM_SETFONT, (WPARAM)f, 0);

        CreateWindowW(L"STATIC", L"CA机构", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)29, 0, 0);
        SendMessageW(GetDlgItem(h, 29), WM_SETFONT, (WPARAM)f, 0);
        g_hCA = CreateWindowW(L"STATIC", L"Let's Encrypt", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hCA, WM_SETFONT, (WPARAM)f, 0);
        g_hCAEnv = CreateWindowW(L"STATIC", L"[正式环境]", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_NOTIFY, 0, 0, 0, 0, h, (HMENU)34, 0, 0);
        SendMessageW(g_hCAEnv, WM_SETFONT, (WPARAM)f, 0);
        g_hCAStatus = CreateWindowW(L"STATIC", L"检测中...", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)31, 0, 0);
        SendMessageW(g_hCAStatus, WM_SETFONT, (WPARAM)f, 0);
        g_hCAInd = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 0, 0, h, (HMENU)30, 0, 0);

        // 启动后台线程检测 CA 连接
        HANDLE hCheck = (HANDLE)_beginthreadex(0, 0, [](void*)->unsigned {
            DWORD status = 0;
            HttpJson(L"https://acme-staging-v02.api.letsencrypt.org/directory", L"GET", NULL, 0, NULL, NULL, &status);
            g_caStatus = (status == 200) ? 1 : 2;
            SafeSetWindowText(g_hCAStatus, g_caStatus == 1 ? L"已连接" : L"不可达");
            SafeInvalidateRect(g_hCAInd);
            return 0;
        }, 0, 0, 0);
        // CA 检测线程: lambda 已包含 return 0
        if (hCheck) CloseHandle(hCheck);

        CreateWindowW(L"STATIC", L"服务器", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)25, 0, 0);
        SendMessageW(GetDlgItem(h, 25), WM_SETFONT, (WPARAM)f, 0);
        g_hServer = CreateWindowW(L"COMBOBOX", 0, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hServer, WM_SETFONT, (WPARAM)f, 0);
        for (auto* s : { L"Apache",L"Nginx",L"IIS",L"通用" })
            SendMessageW(g_hServer, CB_ADDSTRING, 0, (LPARAM)s);
        SendMessageW(g_hServer, CB_SETCURSEL, 0, 0);
        SetWindowLongPtrW(g_hServer, GWLP_USERDATA, (LONG_PTR)SetWindowLongPtrW(g_hServer, GWLP_WNDPROC, (LONG_PTR)NoWheelComboProc));

        CreateWindowW(L"STATIC", L"验证方式", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)26, 0, 0);
        SendMessageW(GetDlgItem(h, 26), WM_SETFONT, (WPARAM)f, 0);
        g_hVerifyMode = CreateWindowW(L"COMBOBOX", 0, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hVerifyMode, WM_SETFONT, (WPARAM)f, 0);
        SendMessageW(g_hVerifyMode, CB_ADDSTRING, 0, (LPARAM)L"HTTP-01");
        SendMessageW(g_hVerifyMode, CB_ADDSTRING, 0, (LPARAM)L"DNS-01");
        SendMessageW(g_hVerifyMode, CB_SETCURSEL, 0, 0);
        SetWindowLongPtrW(g_hVerifyMode, GWLP_USERDATA, (LONG_PTR)SetWindowLongPtrW(g_hVerifyMode, GWLP_WNDPROC, (LONG_PTR)NoWheelComboProc));

        CreateWindowW(L"STATIC", L"保存目录", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)21, 0, 0);
        SendMessageW(GetDlgItem(h, 21), WM_SETFONT, (WPARAM)f, 0);
        g_hSaveDirEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hSaveDirEdit, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnBrowse = CreateWindowW(L"BUTTON", L"选择", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)2, 0, 0);
        SendMessageW(g_hBtnBrowse, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnOpen = CreateWindowW(L"BUTTON", L"打开", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)4, 0, 0);
        SendMessageW(g_hBtnOpen, WM_SETFONT, (WPARAM)f, 0);

        CreateWindowW(L"STATIC", L"网站目录", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)28, 0, 0);
        SendMessageW(GetDlgItem(h, 28), WM_SETFONT, (WPARAM)f, 0);
        g_hWebRoot = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hWebRoot, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnWebRootBrowse = CreateWindowW(L"BUTTON", L"选择", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)6, 0, 0);
        SendMessageW(g_hBtnWebRootBrowse, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnWebRootOpen = CreateWindowW(L"BUTTON", L"打开", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)7, 0, 0);
        SendMessageW(g_hBtnWebRootOpen, WM_SETFONT, (WPARAM)f, 0);

        // 通配符复选框(DNS-01 时显示)
        g_hWildcard = CreateWindowW(L"BUTTON", L"通配符证书(*.域名)", WS_CHILD | BS_AUTOCHECKBOX, 0, 0, 0, 0, h, (HMENU)32, 0, 0);
        SendMessageW(g_hWildcard, WM_SETFONT, (WPARAM)f, 0);

        // DNS API 配置按钮(DNS-01 时显示)
        g_hBtnDnsConfig = CreateWindowW(L"BUTTON", L"DNS API 配置", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)33, 0, 0);
        SendMessageW(g_hBtnDnsConfig, WM_SETFONT, (WPARAM)f, 0);

        g_hBtnApply = CreateWindowW(L"BUTTON", L"申请证书", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)1, 0, 0);
        SendMessageW(g_hBtnApply, WM_SETFONT, (WPARAM)fb, 0);
        g_hDaysEdit = CreateWindowW(L"BUTTON", L"证书续签", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)5, 0, 0);
        SendMessageW(g_hDaysEdit, WM_SETFONT, (WPARAM)fb, 0);

        CreateWindowW(L"STATIC", 0, WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ, 0, 0, 0, 0, h, (HMENU)13, 0, 0);
        g_hLog = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hLog, WM_SETFONT, (WPARAM)f, 0);
        g_hStatus = CreateWindowW(L"STATIC", L"就绪", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)f, 0);
        g_hIP = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE | SS_NOTIFY, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hIP, WM_SETFONT, (WPARAM)f, 0);

        // 获取本机所有IP(遍历网卡,跳过回环和虚拟网卡)
        {
            ULONG sz = 0;
            GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, NULL, &sz);
            std::vector<BYTE> buf(sz);
            PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)buf.data();
            if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &sz) == 0) {
                g_ipList.clear();
                for (auto a = aa; a; a = a->Next) {
                    if (a->OperStatus != IfOperStatusUp) continue;
                    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
                    for (auto ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                        if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                        auto sa = (sockaddr_in*)ua->Address.lpSockaddr;
                        DWORD ip = sa->sin_addr.S_un.S_addr;
                        if ((ip & 0xFF) == 127 || (ip & 0xFF) == 0) continue;
                        if ((ip & 0xFFFF) == htons(0xFEA9)) continue;
                        wchar_t ipStr[64];
                        swprintf_s(ipStr, L"%d.%d.%d.%d",
                            sa->sin_addr.S_un.S_un_b.s_b1, sa->sin_addr.S_un.S_un_b.s_b2,
                            sa->sin_addr.S_un.S_un_b.s_b3, sa->sin_addr.S_un.S_un_b.s_b4);
                        g_ipList.push_back(ipStr);
                    }
                }
                if (!g_ipList.empty()) {
                    g_ipIndex = 0;
                    wchar_t display[128];
                    swprintf_s(display, L"本机IP: %s", g_ipList[0].c_str());
                    SafeSetWindowText(g_hIP, display);
                    if (g_ipList.size() > 1)
                        SetTimer(h, IP_TIMER_ID, 5000, NULL);
                } else {
                    SafeSetWindowText(g_hIP, L"本机IP: --");
                }
            }
        }
        SetPropW(h, L"F", (HANDLE)f); SetPropW(h, L"FB", (HANDLE)fb);
        SyncWebRootVis();
        SetTimer(h, 2001, 10000, NULL);
        SetTimer(h, 2002, 24 * 60 * 60 * 1000, NULL);
        break;
    }
    case WM_SIZE: {
        int W = LOWORD(l), H = HIWORD(l);
        int LM = 35, RM = 35, LW = 52, G = 8, RH = 28, RG = 8;
        int IX = LM + LW + G, IW = W - IX - RM;
        if (IW < 100) IW = 100;  // 防御性保护
        int y = 12;
        // CA机构行(标签 + 文本 + 环境标签 + 状态文字 + 指示灯)- 第一行
        SetWindowPos(GetDlgItem(h, 29), 0, LM + 10, y, LW, RH, 4);
        int caTextW = 100;
        SetWindowPos(g_hCA, 0, IX + 10, y, caTextW, RH, 4);
        SetWindowPos(g_hCAEnv, 0, IX + 5 + caTextW, y, 60, RH, 4);
        SetWindowPos(g_hCAStatus, 0, IX + IW - 70, y, 48, RH, 4);
        SetWindowPos(g_hCAInd, 0, IX + IW - 20, y + 5, 16, 16, 4);
        y += RH + RG;
        SetWindowPos(GetDlgItem(h, 20), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hDomain, 0, IX, y, IW, RH, 4);
        y += RH + RG;
        SetWindowPos(GetDlgItem(h, 27), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hEmail, 0, IX, y, IW, RH, 4);
        y += RH + RG;
        // 服务器 | 验证方式
        SetWindowPos(GetDlgItem(h, 25), 0, LM, y, LW, RH, 4);
        int half = (IW - LW - G) / 2;
        if (half < 60) half = 60;
        SetWindowPos(g_hServer, 0, IX, y, half, RH, 4);
        SetWindowPos(GetDlgItem(h, 26), 0, IX + half + G, y, LW, RH, 4);
        SetWindowPos(g_hVerifyMode, 0, IX + half + G + LW + G, y, IW - half - LW - 2 * G, RH, 4);
        y += RH + RG;
        // 右侧按钮左边缘与验证方式选择框左边缘对齐
        int btnX = IX + half + G + LW + G;
        int bw = 60, bg = 8;
        int rw = W - RM - btnX; // 右侧按钮到右边距的宽度
        int btnW = 100; // 申请证书和证书续签按钮宽度
        int btnH = 32;  // 申请证书和证书续签按钮高度(稍高更突出)
        int inputW = btnX - IX - 8; // 输入框宽度(到"选择"按钮前留8px间隙)
        if (inputW < 40) inputW = 40;
        SetWindowPos(GetDlgItem(h, 21), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hSaveDirEdit, 0, IX, y, inputW, RH, 4);
        SetWindowPos(g_hBtnBrowse, 0, btnX, y, bw, RH, 4);
        SetWindowPos(g_hBtnOpen, 0, btnX + bw + bg, y, bw, RH, 4);
        y += RH + RG;
        // 网站目录宽度与保存目录输入框一致
        SetWindowPos(GetDlgItem(h, 28), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hWebRoot, 0, IX, y, inputW, RH, 4);
        SetWindowPos(g_hBtnWebRootBrowse, 0, btnX, y, bw, RH, 4);
        SetWindowPos(g_hBtnWebRootOpen, 0, btnX + bw + bg, y, bw, RH, 4);
        // 通配符复选框与网站目录同行(互相隐藏)
        SetWindowPos(g_hWildcard, 0, IX, y, 160, RH, 4);
        SetWindowPos(g_hBtnDnsConfig, 0, btnX, y, rw, RH, 4);
        y += RH + 12;
        // 按钮行: 居中，两个按钮拉开距离
        int gap = 80, bx = (W - LM - RM - 2 * btnW - gap) / 2 + LM;
        SetWindowPos(g_hBtnApply, 0, bx, y, btnW, btnH, 4);
        SetWindowPos(g_hDaysEdit, 0, bx + btnW + gap, y, btnW, btnH, 4);
        y += 40;
        SetWindowPos(GetDlgItem(h, 13), 0, LM, y, W - LM - RM, 2, 4);
        y += 6;
        // 日志区域:从 y 到底部,最小 60px
        int sh = 26;
        int bottomY = y + 60 + sh + 4;  // 至少需要 log(60) + status(22) + gap(4)
        if (H < bottomY) H = bottomY;    // 确保空间够放日志+状态栏
        int lh = H - y - sh - 4; if (lh < 60) lh = 60;
        SetWindowPos(g_hLog, 0, LM, y, W - LM - RM, lh, 4);
        // 状态栏和 IP 紧跟日志下方,不依赖窗口总高度倒推
        int statusY = y + lh + 4;
        SetWindowPos(g_hStatus, 0, LM, statusY, 150, sh, 4);
        int ipW = 200;
        SetWindowPos(g_hIP, 0, W - RM - ipW, statusY, ipW, sh, 4);
        break;
    }
    case WM_GETMINMAXINFO: {
        // 限制最小窗口尺寸,防止远程桌面/DPI变化压烂布局
        MINMAXINFO* mm = (MINMAXINFO*)l;
        mm->ptMinTrackSize.x = 480;
        mm->ptMinTrackSize.y = 560;
        return 0;
    }
    case WM_COMMAND: {
        // 托盘菜单命令
        if (LOWORD(w) == IDM_SHOW) {
            ShowWindow(h, SW_SHOW); SetForegroundWindow(h); return 0;
        } else if (LOWORD(w) == IDM_EXIT) {
            SetPropW(h, L"ReallyClose", (HANDLE)1); PostMessageW(h, WM_CLOSE, 0, 0); return 0;
        }
        if (LOWORD(w) == 1) {
            // DNS-01 等待中:触发继续验证
            if (g_hDnsReady) { SetEvent(g_hDnsReady); EnableWindow(g_hBtnApply, FALSE); break; }
            if (!IsWindowEnabled(g_hBtnApply)) break;
            EnableWindow(g_hBtnApply, FALSE);
            // 同步 UI 输入到全局变量,避免重启才生效
            wchar_t dt[MAX_PATH];
            GetWindowTextW(g_hWebRoot, dt, MAX_PATH);
            if (dt[0]) g_WebRoot = dt;
            GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
            if (dt[0]) g_SaveDir = dt; if (g_SaveDir.empty()) { BrowseDir(); if (g_SaveDir.empty()) { EnableWindow(g_hBtnApply, TRUE); break; } }
            SetWindowTextW(g_hLog, L"");
            Log(L"开始申请...");
            g_AutoScroll = true;
            HANDLE hh = (HANDLE)_beginthreadex(0, 0, ApplyThread, 0, 0, 0); if (hh) CloseHandle(hh);
        }
        else if (LOWORD(w) == 2) BrowseDir();
        else if (LOWORD(w) == 6) {
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hWebRoot, dt, MAX_PATH);
            if (dt[0]) g_WebRoot = dt;
            std::wstring out;
            if (PickFolder(g_hWnd, L"选择网站目录", g_WebRoot, out)) {
                g_WebRoot = out;
                SetWindowTextW(g_hWebRoot, out.c_str());
            }
        }
        else if (LOWORD(w) == 7) {
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hWebRoot, dt, MAX_PATH);
            if (dt[0]) ShellExecuteW(0, L"open", dt, 0, 0, SW_SHOWNORMAL);
        }
        else if (LOWORD(w) == 4) {
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
            if (dt[0]) ShellExecuteW(0, L"open", dt, 0, 0, SW_SHOWNORMAL);
        }
        else if (LOWORD(w) == 33) {
            ShowDnsConfigDialog(h);
        }
        else if (LOWORD(w) == 34) {
            static DWORD lastEnvTick = 0;
            DWORD now = GetTickCount();
            if (now - lastEnvTick < 500) break;
            lastEnvTick = now;
            g_CAEnvIndex = 1 - g_CAEnvIndex;
            SetWindowTextW(g_hCAEnv, g_CAEnvIndex == 1 ? L"[测试环境]" : L"[正式环境]");
        }
        else if (LOWORD(w) == 5) {
            // 打开证书续签窗口
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
            if (dt[0]) g_SaveDir = dt;
            // 保存目录为空时不阻止打开窗口，而是在窗口内提示用户选择

            // 注册续签窗口类（只注册一次）
            static bool regRenewClass = false;
            if (!regRenewClass) {
                WNDCLASSEXW rwc = { sizeof(rwc) };
                rwc.style = CS_HREDRAW | CS_VREDRAW;
                rwc.lpfnWndProc = DefWindowProcW;
                rwc.hInstance = (HINSTANCE)GetWindowLongPtrW(h, GWLP_HINSTANCE);
                rwc.hCursor = LoadCursor(0, IDC_ARROW);
                rwc.hbrBackground = CreateSolidBrush(RGB(245, 245, 245));
                rwc.lpszClassName = L"SSLClawRenew";
                RegisterClassExW(&rwc);
                regRenewClass = true;
            }

            if (g_RenewWnd && IsWindow(g_RenewWnd)) { SetForegroundWindow(g_RenewWnd); break; }

            int rsw = 480, rsh = 300;
            int scrw = GetSystemMetrics(SM_CXSCREEN), scrh = GetSystemMetrics(SM_CYSCREEN);
            g_RenewWnd = CreateWindowExW(0, L"SSLClawRenew", L"证书续签",
                WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_MINIMIZEBOX & ~WS_THICKFRAME,
                (scrw - rsw) / 2, (scrh - rsh) / 2, rsw, rsh, h, 0, 0, 0);

            // 获取客户区实际宽高，动态布局
            RECT crc; GetClientRect(g_RenewWnd, &crc);
            int cw = crc.right, ch = crc.bottom;
            int padX = 10, padY = 10;

            // 统一字体 18px Microsoft YaHei UI
            HFONT rf = CreateFontW(18, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, PROOF_QUALITY,
                DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
            SetPropW(g_RenewWnd, L"F", (HANDLE)rf);

            // ListView - 占满宽度，从顶部到按钮区上方
            int btnH = 28, statusH = 26;
            int lvH = ch - padY - 6 - btnH - 8 - statusH - padY;
            HWND hList = CreateWindowExW(0, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_BORDER | WS_HSCROLL,
                padX, padY, cw - padX*2, lvH, g_RenewWnd, (HMENU)100, 0, 0);
            SendMessageW(hList, WM_SETFONT, (WPARAM)rf, 0);
            ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES | LVS_EX_GRIDLINES);

            LVCOLUMNW col = {}; col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; col.fmt = LVCFMT_LEFT;
            RECT lvRc; GetClientRect(hList, &lvRc);
            int lvW = lvRc.right - GetSystemMetrics(SM_CXVSCROLL);
            int defDomain = lvW * 35 / 100;
            int defOther = (lvW - defDomain) / 4;
            int defW[5] = { defDomain, defOther, defOther, defOther, defOther };
            wchar_t cwBuf[32];
            int colW[5];
            for (int i = 0; i < 5; i++) {
                wchar_t key[8]; swprintf_s(key, L"Col%d", i);
                GetPrivateProfileStringW(L"RenewalList", key, L"", cwBuf, 32, g_IniPath.c_str());
                colW[i] = cwBuf[0] ? _wtoi(cwBuf) : defW[i];
                if (colW[i] < 30) colW[i] = defW[i];
            }
            wchar_t col0[] = L"域名"; col.pszText = col0; col.cx = colW[0]; ListView_InsertColumn(hList, 0, &col);
            wchar_t col1[] = L"过期"; col.pszText = col1; col.cx = colW[1]; ListView_InsertColumn(hList, 1, &col);
            wchar_t col2[] = L"天数"; col.pszText = col2; col.cx = colW[2]; ListView_InsertColumn(hList, 2, &col);
            wchar_t col3[] = L"续签"; col.pszText = col3; col.cx = colW[3]; ListView_InsertColumn(hList, 3, &col);
            wchar_t col4[] = L"DNS"; col.pszText = col4; col.cx = colW[4]; ListView_InsertColumn(hList, 4, &col);

            // 按钮行 - 只保留3个核心按钮，双击列表=详情，吊销在详情里
            int btnY = padY + lvH + 6;
            int bw = 70, bg = 10;
            int totalBtnW = 4 * bw + 3 * bg;
            int bx = (cw - totalBtnW) / 2;
            CreateWindowW(L"BUTTON", L"刷新",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, bx, btnY, bw, btnH, g_RenewWnd, (HMENU)102, 0, 0);
            SendMessageW(GetDlgItem(g_RenewWnd, 102), WM_SETFONT, (WPARAM)rf, 0);
            bx += bw + bg;
            CreateWindowW(L"BUTTON", L"续签",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, bx, btnY, bw, btnH, g_RenewWnd, (HMENU)101, 0, 0);
            SendMessageW(GetDlgItem(g_RenewWnd, 101), WM_SETFONT, (WPARAM)rf, 0);
            bx += bw + bg;
            CreateWindowW(L"BUTTON", L"API配置",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, bx, btnY, bw, btnH, g_RenewWnd, (HMENU)104, 0, 0);
            SendMessageW(GetDlgItem(g_RenewWnd, 104), WM_SETFONT, (WPARAM)rf, 0);
            bx += bw + bg;
            CreateWindowW(L"BUTTON", L"自动续签",
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, bx, btnY, bw, btnH, g_RenewWnd, (HMENU)103, 0, 0);
            SendMessageW(GetDlgItem(g_RenewWnd, 103), WM_SETFONT, (WPARAM)rf, 0);

            // 状态栏 - 紧贴底部，左边记录数，右边 Web 服务器检测
            int stY = btnY + btnH + 8;
            int stTotalW = cw - padX*2;
            int leftW = 150;  // 左边“共 N 个续签记录”
            CreateWindowW(L"STATIC", L"",
                WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
                padX, stY, leftW, statusH, g_RenewWnd, (HMENU)106, 0, 0);
            SendMessageW(GetDlgItem(g_RenewWnd, 106), WM_SETFONT, (WPARAM)rf, 0);
            CreateWindowW(L"STATIC", L"",
                WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE,
                padX + leftW, stY, stTotalW - leftW, statusH, g_RenewWnd, (HMENU)107, 0, 0);
            SendMessageW(GetDlgItem(g_RenewWnd, 107), WM_SETFONT, (WPARAM)rf, 0);

            // 子类化窗口过程（不能用 lambda，MSVC 不支持 lambda 转 WNDPROC）
            g_OrigRenewProc = (WNDPROC)SetWindowLongPtrW(g_RenewWnd, GWLP_WNDPROC,
                (LONG_PTR)RenewWndProc);

            ShowWindow(g_RenewWnd, SW_SHOW);
            // 初始加载
            SendMessageW(g_RenewWnd, WM_USER+1, 0, 0);
        }
        else if (HIWORD(w) == CBN_SELCHANGE && (HWND)l == g_hVerifyMode) {
            static DWORD lastSwitchTick = 0;
            DWORD now = GetTickCount();
            if (now - lastSwitchTick < 300) break;
            lastSwitchTick = now;
            SyncWebRootVis();
            g_AutoScroll = false;
            SetWindowTextW(g_hLog, L"");
            ShowVerifySteps((int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0));
            SendMessageW(g_hLog, EM_SETSEL, 0, 0);
            SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
        }
        else if ((HWND)l == g_hIP && HIWORD(w) == 0) {
            // 点击复制当前显示的IP(不含"本机IP: "前缀)
            if (g_ipIndex < (int)g_ipList.size()) {
                const std::wstring& ip = g_ipList[g_ipIndex];
                OpenClipboard(NULL); EmptyClipboard();
                HGLOBAL hm = GlobalAlloc(GMEM_MOVEABLE, (ip.size() + 1) * sizeof(wchar_t));
                memcpy(GlobalLock(hm), ip.c_str(), (ip.size() + 1) * sizeof(wchar_t));
                GlobalUnlock(hm); SetClipboardData(CF_UNICODETEXT, hm);
                CloseClipboard(); SetStatus(L"IP 已复制");
            }
        }
        break;
    }
    case WM_SYSCOMMAND: {
        if ((w & 0xFFF0) == SC_CONTEXTHELP) {
            auto cb = [](HWND hw, UINT nm, WPARAM wp, LPARAM lp, LONG_PTR ref) -> HRESULT {
                if (nm == TDN_HYPERLINK_CLICKED)
                    ShellExecuteW((HWND)hw, L"open", (LPCWSTR)lp, NULL, NULL, SW_SHOWNORMAL);
                return S_OK;
            };
            TASKDIALOGCONFIG tc = {0};
            tc.cbSize = sizeof(tc);
            tc.hwndParent = h;
            tc.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_ENABLE_HYPERLINKS;
            tc.pszWindowTitle = L"关于 SSLClaw";
            tc.pszMainIcon = TD_INFORMATION_ICON;
            tc.pszMainInstruction = L"SSLClaw v1.3";
            tc.pszContent = L"Windows SSL 证书管理工具\n基于 ACME 协议自动申请和续签 Let's Encrypt 证书\n\n作者:DiskClaw\n<a href=\"https://github.com/DiskClaw/SSLClaw\">https://github.com/DiskClaw/SSLClaw</a>";
            tc.pfCallback = cb;
            TaskDialogIndirect(&tc, NULL, NULL, NULL);
            return 0;
        }
        return DefWindowProcW(h, m, w, l);
    }
    case WM_TIMER: {
        if (w == IP_TIMER_ID && g_ipList.size() > 1) {
            g_ipIndex = (g_ipIndex + 1) % (int)g_ipList.size();
            wchar_t display[128];
            swprintf_s(display, L"本机IP: %s", g_ipList[g_ipIndex].c_str());
            SetWindowTextW(g_hIP, display);
        }
        if (w == 2001) {
            KillTimer(h, 2001);
            HANDLE ht = (HANDLE)_beginthreadex(0, 0, [](void*)->unsigned {
                RunRenewalMode();
                return 0;
            }, 0, 0, 0);
            if (ht) CloseHandle(ht);
        }
        if (w == 2002) {
            HANDLE ht = (HANDLE)_beginthreadex(0, 0, [](void*)->unsigned {
                RunRenewalMode();
                return 0;
            }, 0, 0, 0);
            if (ht) CloseHandle(ht);
        }
        break;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)l;
        if (dis->CtlID == 30) { // CA 指示灯
            COLORREF clr;
            switch (g_caStatus) {
                case 1:  clr = RGB(0, 200, 80);  break; // 绿色
                case 2:  clr = RGB(220, 50, 50); break; // 红色
                default: clr = RGB(180, 180, 180); break; // 灰色
            }
            RECT rc = dis->rcItem;
            int cx = rc.left + (rc.right - rc.left) / 2;
            int cy = rc.top + (rc.bottom - rc.top) / 2;
            int r = min(rc.right - rc.left, rc.bottom - rc.top) / 2 - 1;
            if (r < 2) r = 2;
            HBRUSH br = CreateSolidBrush(clr);
            HPEN pen = CreatePen(PS_SOLID, 1, clr);
            HBRUSH oldBr = (HBRUSH)SelectObject(dis->hDC, br);
            HPEN oldPen = (HPEN)SelectObject(dis->hDC, pen);
            Ellipse(dis->hDC, cx - r, cy - r, cx + r, cy + r);
            // 高光效果(每通道 +60,独立 clamp 到 255)
            BYTE hlR = (GetRValue(clr) > 195) ? 255 : GetRValue(clr) + 60;
            BYTE hlG = (GetGValue(clr) > 195) ? 255 : GetGValue(clr) + 60;
            BYTE hlB = (GetBValue(clr) > 195) ? 255 : GetBValue(clr) + 60;
            COLORREF hlClr = RGB(hlR, hlG, hlB);
            HBRUSH brHL = CreateSolidBrush(hlClr);
            SelectObject(dis->hDC, brHL);
            int hr = max(r / 3, 1);
            Ellipse(dis->hDC, cx - hr, cy - r + 1, cx + hr, cy - r + 1 + hr * 2);
            SelectObject(dis->hDC, oldBr);
            SelectObject(dis->hDC, oldPen);
            DeleteObject(br); DeleteObject(pen); DeleteObject(brHL);
            return TRUE;
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)w;
        SetBkColor(dc, RGB(245, 245, 245));
        HWND ctrl = (HWND)l;
        if (ctrl == g_hCAStatus) {
            if (g_caStatus == 1) SetTextColor(dc, RGB(0, 150, 60));
            else if (g_caStatus == 2) SetTextColor(dc, RGB(200, 40, 40));
            else SetTextColor(dc, RGB(120, 120, 120));
        } else if (ctrl == g_hCAEnv) {
            SetTextColor(dc, g_CAEnvIndex == 1 ? RGB(220, 120, 0) : RGB(100, 100, 100));
        } else {
            SetTextColor(dc, RGB(0, 0, 0));
        }
        return (LRESULT)GetClassLongPtrW(h, GCLP_HBRBACKGROUND);
    }
    case WM_CLOSE: {
        // 有关闭标志才真退出，否则最小化到托盘
        if (GetPropW(h, L"ReallyClose")) {
            RemovePropW(h, L"ReallyClose");
            DestroyWindow(h);
        } else {
            // 最小化到托盘
            if (!g_TrayVisible) {
                ZeroMemory(&g_TrayNid, sizeof(g_TrayNid));
                g_TrayNid.cbSize = sizeof(g_TrayNid);
                g_TrayNid.hWnd = h;
                g_TrayNid.uID = TRAY_ID;
                g_TrayNid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
                g_TrayNid.uCallbackMessage = WM_TRAY;
                g_TrayNid.hIcon = LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(1));
                if (!g_TrayNid.hIcon) g_TrayNid.hIcon = LoadIconW(NULL, IDI_APPLICATION);
                wcscpy_s(g_TrayNid.szTip, L"SSLClaw - 后台续签运行中");
                Shell_NotifyIconW(NIM_ADD, &g_TrayNid);
                g_TrayVisible = true;
            }
            ShowWindow(h, SW_HIDE);
        }
        return 0;
    }
    case WM_LOG_MSG: {
        std::wstring* pMsg = (std::wstring*)l;
        if (pMsg && g_hLog && IsWindow(g_hLog)) {
            InitLogCs();
            EnterCriticalSection(&g_LogCs);
            int len = GetWindowTextLengthW(g_hLog);
            if (len > 200000) {
                SetWindowTextW(g_hLog, L"...(日志过长，已截断)\r\n");
                len = 0;
            }
            if (len > 0) {
                SendMessageW(g_hLog, EM_SETSEL, len, len);
                std::wstring msg = *pMsg + L"\r\n";
                SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)msg.c_str());
            } else {
                std::wstring msg = *pMsg + L"\r\n";
                SetWindowTextW(g_hLog, msg.c_str());
                SendMessageW(g_hLog, EM_SETSEL, msg.size(), msg.size());
            }
            if (g_AutoScroll) SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
            LeaveCriticalSection(&g_LogCs);
        }
        delete pMsg;
        return 0;
    }
    case WM_SAFE_SETSTATUS: {
        std::wstring* p = (std::wstring*)l;
        if (p && g_hStatus && IsWindow(g_hStatus))
            SetWindowTextW(g_hStatus, p->c_str());
        delete p;
        return 0;
    }
    case WM_SAFE_ENABLE: {
        HWND hCtrl = (HWND)w;
        if (hCtrl && IsWindow(hCtrl))
            EnableWindow(hCtrl, l ? TRUE : FALSE);
        return 0;
    }
    case WM_SAFE_SETTEXT: {
        HWND hCtrl = (HWND)w;
        std::wstring* p = (std::wstring*)l;
        if (hCtrl && IsWindow(hCtrl) && p)
            SetWindowTextW(hCtrl, p->c_str());
        delete p;
        return 0;
    }
    case WM_SAFE_INVALIDATE: {
        HWND hCtrl = (HWND)w;
        if (hCtrl && IsWindow(hCtrl))
            InvalidateRect(hCtrl, NULL, TRUE);
        return 0;
    }
    case WM_TRAY: {
        if (LOWORD(l) == WM_LBUTTONDBLCLK) {
            // 双击托盘图标显示主窗口
            ShowWindow(h, SW_SHOW);
            SetForegroundWindow(h);
        } else if (LOWORD(l) == WM_RBUTTONUP) {
            // 右键菜单
            POINT pt; GetCursorPos(&pt);
            HMENU hMenu = CreatePopupMenu();
            AppendMenuW(hMenu, MF_STRING, IDM_SHOW, L"显示主界面");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(hMenu, MF_STRING, IDM_EXIT, L"退出程序");
            SetForegroundWindow(h);
            int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, h, NULL);
            DestroyMenu(hMenu);
            if (cmd == IDM_SHOW) {
                ShowWindow(h, SW_SHOW);
                SetForegroundWindow(h);
            } else if (cmd == IDM_EXIT) {
                SetPropW(h, L"ReallyClose", (HANDLE)1);
                PostMessageW(h, WM_CLOSE, 0, 0);
            }
        }
        return 0;
    }
    // ── 以下是原有 WM_DESTROY ──
    case WM_DESTROY: {
        // 清理托盘图标
        if (g_TrayVisible) { Shell_NotifyIconW(NIM_DELETE, &g_TrayNid); g_TrayVisible = false; }
        KillTimer(h, IP_TIMER_ID);
        KillTimer(h, 2001);
        KillTimer(h, 2002);
        wchar_t buf[512];
        if (GetWindowTextW(g_hDomain, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"Domain", buf, g_IniPath.c_str());
        if (GetWindowTextW(g_hEmail, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"Email", buf, g_IniPath.c_str());
        int si = (int)SendMessageW(g_hServer, CB_GETCURSEL, 0, 0);
        swprintf_s(buf, L"%d", si);
        WritePrivateProfileStringW(L"SSLClaw", L"ServerType", buf, g_IniPath.c_str());
        if (GetWindowTextW(g_hSaveDirEdit, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"SaveDir", buf, g_IniPath.c_str());
        int vm = (int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0);
        swprintf_s(buf, L"%d", vm);
        WritePrivateProfileStringW(L"SSLClaw", L"VerifyMode", buf, g_IniPath.c_str());
        if (GetWindowTextW(g_hWebRoot, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"WebRoot", buf, g_IniPath.c_str());
        // 保存通配符复选框状态
        int wc = (int)SendMessageW(g_hWildcard, BM_GETCHECK, 0, 0);
        WritePrivateProfileStringW(L"SSLClaw", L"Wildcard", wc ? L"1" : L"0", g_IniPath.c_str());
        // CA 固定 Let's Encrypt，环境不持久化(每次启动默认生产)
        DeleteObject((HFONT)GetPropW(h, L"F")); DeleteObject((HFONT)GetPropW(h, L"FB"));
        if (g_LogCsInit) DeleteCriticalSection(&g_LogCs);
        PostQuitMessage(0); break;
    }
    default: {
        // 处理任务栏重建消息（Explorer 崩溃后恢复托盘图标）
        if (WM_TASKBARCREATED && m == WM_TASKBARCREATED && g_TrayVisible) {
            Shell_NotifyIconW(NIM_ADD, &g_TrayNid);
            return 0;
        }
        return DefWindowProcW(h, m, w, l);
    }
    }
    return 0;
}
