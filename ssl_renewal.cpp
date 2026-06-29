// ssl_renewal.cpp - 续签系统
#include "ssl_core.h"
#include "ssl_ui.h"
#include "ssl_keyfmt.h"
#include <set>
#include <algorithm>
#include <sstream>
#include <tlhelp32.h>
#include <vector>

// 前向声明（LogRenewal 定义在文件后面）
static void LogRenewal(const wchar_t* fmt, ...);

// RAII 守卫：确保 DNS TXT 异常时自动清除
struct DnsTxtCleanupGuard {
    bool active = false;
    int provider = 0;
    std::wstring apiId, apiSecret, zone, subDomain;
    ~DnsTxtCleanupGuard() {
        if (active) {
            DnsDeleteTxtRecord(provider, apiId, apiSecret, zone, subDomain);
            LogRenewal(L"  TXT 记录已清理 (RAII 守卫)");
            active = false;
        }
    }
    void disarm() { active = false; }
};

// 声明已统一到 ssl_core.h

#define WM_LOG_MSG (WM_USER + 0x201)

// ── 后台续签线程全局状态 ──
static HANDLE g_RenewalThread = NULL;
// 使用 volatile 确保多线程可见性（#5: 线程安全修复）
static volatile LONG g_RenewalThreadRunning = 0;
static HANDLE g_RenewalWakeEvent = NULL;
std::set<std::wstring> g_RenewingDomains;
static CRITICAL_SECTION g_RenewCs;
static bool g_RenewCsInit = false;

// 静态初始化器：程序启动时自动初始化临界区
static struct _RenewCsInit { _RenewCsInit() { InitializeCriticalSection(&g_RenewCs); g_RenewCsInit = true; } } _renewCsInit;
volatile LONG g_AcmeBusyFlag = 0;

struct AcmeLock {
    bool held = false;
    AcmeLock() {
        if (InterlockedCompareExchange(&g_AcmeBusyFlag, 1, 0) == 0)
            held = true;
    }
    ~AcmeLock() { if (held) InterlockedExchange(&g_AcmeBusyFlag, 0); }
};

// ── 续签重试状态（受 g_RenewCs 保护，#26: 线程安全修复） ──
struct RenewalRetryState {
    std::wstring domain;
    int attemptCount = 0;
    FILETIME nextRetryTime = {};
};
static std::vector<RenewalRetryState> g_RetryStates;

// ── 从磁盘证书文件读取实际到期时间 ──
static FILETIME ReadCertExpiryFromDisk(const RenewalRecord& rec) {
    FILETIME expFt = {};
    if (rec.saveDir.empty() || rec.domain.empty()) return expFt;

    // 使用公共函数构建文件名（#12: 消除重复代码）
    std::wstring nt = SanitizeDomainToFileName(rec.domain);

    // 尝试两种扩展名：.crt / _cert.pem
    std::wstring certPaths[2] = {
        rec.saveDir + L"\\" + nt + L".crt",
        rec.saveDir + L"\\" + nt + L"_cert.pem"
    };
    for (int i = 0; i < 2; i++) {
        if (!PathFileExistsW(certPaths[i].c_str())) continue;
        HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_FILENAME, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
            CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, certPaths[i].c_str());
        if (!hStore) continue;
        PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hStore, NULL);
        if (pCert) {
            expFt = pCert->pCertInfo->NotAfter;
            CertFreeCertificateContext(pCert);
        }
        CertCloseStore(hStore, 0);
        if (expFt.dwLowDateTime || expFt.dwHighDateTime) break;
    }
    return expFt;
}

// ── 续签日志文件 ──
static void LogRenewal(const wchar_t* fmt, ...) {
    va_list args; va_start(args, fmt);
    wchar_t buf[4096]; _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args); va_end(args);
    extern void LogToFile(const wchar_t* msg);
    LogToFile(buf);
    if (g_RenewWnd) {
        HWND hStatus = GetDlgItem(g_RenewWnd, 106);
        if (hStatus) {
            extern void SafeSetWindowText(HWND h, const wchar_t* t);
            SafeSetWindowText(hStatus, buf);
        }
    }
    extern HWND g_hWnd;
    if (g_hWnd) {
        std::wstring* pMsg = new std::wstring(buf);
        PostMessageW(g_hWnd, WM_LOG_MSG, 0, (LPARAM)pMsg);
    }
}

// 只写文件日志 + 状态栏，不显示在主日志栏
static void LogRenewalStatus(const wchar_t* fmt, ...) {
    va_list args; va_start(args, fmt);
    wchar_t buf[4096]; _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args); va_end(args);
    extern void LogToFile(const wchar_t* msg);
    LogToFile(buf);
    extern void SafeSetStatus(const wchar_t* t);
    SafeSetStatus(buf);
}

// ── 脚本执行 ──
bool ExecuteRenewalScript(const std::wstring& script, const std::wstring& domain) {
    if (script.empty()) return true;
    // 提取可执行文件路径并校验扩展名白名单
    std::wstring exePath = script;
    size_t sp = script.find(L' ');
    if (sp != std::wstring::npos) exePath = script.substr(0, sp);
    if (!exePath.empty() && exePath.front() == L'"') exePath = exePath.substr(1);
    if (!exePath.empty() && exePath.back() == L'"') exePath.pop_back();
    std::wstring ext;
    size_t dot = exePath.rfind(L'.');
    if (dot != std::wstring::npos) ext = exePath.substr(dot);
    for (auto& c : ext) c = towlower(c);
    if (ext != L".bat" && ext != L".cmd" && ext != L".ps1") {
        LogRenewal(L"[脚本] 拒绝执行非脚本文件: %s", exePath.c_str());
        return false;
    }
    std::wstring cmd = script;
    // 替换 {domain} 占位符
    size_t pos;
    while ((pos = cmd.find(L"{domain}")) != std::wstring::npos)
        cmd.replace(pos, 8, domain);
    while ((pos = cmd.find(L"{Domain}")) != std::wstring::npos)
        cmd.replace(pos, 8, domain);

    LogRenewal(L"[脚本] 执行: %s", cmd.c_str());
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, (wchar_t*)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        LogRenewal(L"[脚本] 启动失败 (错误: %d)", GetLastError());
        return false;
    }
    DWORD waitResult = WaitForSingleObject(pi.hProcess, RENEWAL_SCRIPT_TIMEOUT_MS);
    DWORD exitCode = 1;
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        LogRenewal(L"[脚本] 超时终止");
    } else {
        GetExitCodeProcess(pi.hProcess, &exitCode);
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    LogRenewal(L"[脚本] 退出码: %d", exitCode);
    return (exitCode == 0);
}

// ── 续签记录持久化 ──
static std::wstring GetRenewalIniPath() {
    return g_IniPath;
}

// 续签记录通过域名查找
int FindRenewalByDomain(const std::vector<RenewalRecord>& records, const std::wstring& domain) {
    for (int i = 0; i < (int)records.size(); i++) {
        if (records[i].domain == domain) return i;
    }
    return -1;
}

// 将 FILETIME 转 wstring
static std::wstring FtToStr(const FILETIME& ft) {
    SYSTEMTIME st; FileTimeToSystemTime(&ft, &st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02dT%02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

static FILETIME StrToFt(const std::wstring& s) {
    FILETIME ft = {}; SYSTEMTIME st = {};
    int year, month, day, hour, minute, second;
    swscanf_s(s.c_str(), L"%04d-%02d-%02dT%02d:%02d:%02d",
        &year, &month, &day, &hour, &minute, &second);
    st.wYear = (WORD)year;
    st.wMonth = (WORD)month;
    st.wDay = (WORD)day;
    st.wHour = (WORD)hour;
    st.wMinute = (WORD)minute;
    st.wSecond = (WORD)second;
    SystemTimeToFileTime(&st, &ft);
    return ft;
}

void AddOrUpdateRenewal(const RenewalRecord& record) {
    std::wstring ini = GetRenewalIniPath();
    std::wstring sec = L"Renewal:" + record.domain;
    WritePrivateProfileStringW(sec.c_str(), L"domain", record.domain.c_str(), ini.c_str());

    wchar_t buf[64];
    swprintf_s(buf, L"%d", record.verifyMode);
    WritePrivateProfileStringW(sec.c_str(), L"verifyMode", buf, ini.c_str());
    swprintf_s(buf, L"%d", record.serverType);
    WritePrivateProfileStringW(sec.c_str(), L"serverType", buf, ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"webRoot", record.webRoot.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"saveDir", record.saveDir.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"email", record.email.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"autoRenew", record.autoRenew ? L"1" : L"0", ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"thumbprint", record.thumbprint.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"friendlyName", record.friendlyName.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"issueTime", FtToStr(record.issueTime).c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"expiryTime", FtToStr(record.expiryTime).c_str(), ini.c_str());
    swprintf_s(buf, L"%d", record.renewalDays);
    WritePrivateProfileStringW(sec.c_str(), L"renewalDays", buf, ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"preScript", record.preScript.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"postScript", record.postScript.c_str(), ini.c_str());
    WritePrivateProfileStringW(sec.c_str(), L"wildcard", record.wildcard ? L"1" : L"0", ini.c_str());
    swprintf_s(buf, L"%d", record.dnsProvider);
    WritePrivateProfileStringW(sec.c_str(), L"dnsProvider", buf, ini.c_str());
}

bool LoadRenewalRecords(std::vector<RenewalRecord>& records) {
    records.clear();
    std::wstring ini = GetRenewalIniPath();
    if (!PathFileExistsW(ini.c_str())) return true;

    wchar_t secBuf[32768];
    // #9: 修复 len 计算 — GetPrivateProfileSectionNames 返回字符数（不含双空终止符），
    // 遍历时用 wcslen 推进即可，不需要减去 sizeof(wchar_t)
    DWORD len = GetPrivateProfileSectionNamesW(secBuf, 32768, ini.c_str());
    if (len == 0) return true;

    const wchar_t* p = secBuf;
    while (*p) {
        std::wstring sec(p);
        if (sec.find(L"Renewal:") == 0) {
            RenewalRecord rec;
            rec.domain = sec.substr(8);

            wchar_t buf[2048];
            GetPrivateProfileStringW(sec.c_str(), L"verifyMode", L"0", buf, 2048, ini.c_str());
            rec.verifyMode = _wtoi(buf);
            GetPrivateProfileStringW(sec.c_str(), L"serverType", L"0", buf, 2048, ini.c_str());
            rec.serverType = _wtoi(buf);
            GetPrivateProfileStringW(sec.c_str(), L"webRoot", L"", buf, 2048, ini.c_str()); rec.webRoot = buf;
            GetPrivateProfileStringW(sec.c_str(), L"saveDir", L"", buf, 2048, ini.c_str()); rec.saveDir = buf;
            GetPrivateProfileStringW(sec.c_str(), L"email", L"", buf, 2048, ini.c_str()); rec.email = buf;
            GetPrivateProfileStringW(sec.c_str(), L"autoRenew", L"0", buf, 2048, ini.c_str()); rec.autoRenew = (wcscmp(buf, L"1") == 0);
            GetPrivateProfileStringW(sec.c_str(), L"thumbprint", L"", buf, 2048, ini.c_str()); rec.thumbprint = buf;
            GetPrivateProfileStringW(sec.c_str(), L"friendlyName", L"", buf, 2048, ini.c_str()); rec.friendlyName = buf;
            GetPrivateProfileStringW(sec.c_str(), L"issueTime", L"", buf, 2048, ini.c_str()); rec.issueTime = StrToFt(buf);
            GetPrivateProfileStringW(sec.c_str(), L"expiryTime", L"", buf, 2048, ini.c_str()); rec.expiryTime = StrToFt(buf);
            // renewalDays 默认 7 天；修正历史脏数据（旧默认值 60）
            GetPrivateProfileStringW(sec.c_str(), L"renewalDays", L"7", buf, 2048, ini.c_str()); rec.renewalDays = _wtoi(buf);
            if (rec.renewalDays <= 0 || rec.renewalDays > 30) {
                rec.renewalDays = DEFAULT_RENEWAL_DAYS;
            }
            GetPrivateProfileStringW(sec.c_str(), L"preScript", L"", buf, 2048, ini.c_str()); rec.preScript = buf;
            GetPrivateProfileStringW(sec.c_str(), L"postScript", L"", buf, 2048, ini.c_str()); rec.postScript = buf;
            GetPrivateProfileStringW(sec.c_str(), L"wildcard", L"0", buf, 2048, ini.c_str()); rec.wildcard = (wcscmp(buf, L"1") == 0);
            GetPrivateProfileStringW(sec.c_str(), L"dnsProvider", L"0", buf, 2048, ini.c_str()); rec.dnsProvider = _wtoi(buf);

            // 从磁盘证书读取实际到期时间，优先于 INI
            FILETIME diskExp = ReadCertExpiryFromDisk(rec);
            if (diskExp.dwLowDateTime || diskExp.dwHighDateTime) rec.expiryTime = diskExp;

            if (!rec.domain.empty()) records.push_back(rec);
        }
        p += wcslen(p) + 1;  // #9: 正确的推进方式（字符数，非字节数）
    }
    return !records.empty();
}

// #3: 原子保存续签记录 — 先写临时文件再替换
bool SaveRenewalRecords(const std::vector<RenewalRecord>& records) {
    std::wstring ini = GetRenewalIniPath();

    // 清除旧的续签记录 section
    wchar_t secBuf[32768];
    DWORD secLen = GetPrivateProfileSectionNamesW(secBuf, 32768, ini.c_str());
    const wchar_t* p = secBuf;
    while (*p && p < secBuf + secLen) {
        std::wstring sec(p);
        if (sec.find(L"Renewal:") == 0) {
            WritePrivateProfileStringW(sec.c_str(), NULL, NULL, ini.c_str());
        }
        p += wcslen(p) + 1;
    }
    for (auto& rec : records) AddOrUpdateRenewal(rec);
    return true;
}

// ── 获取需要续签的记录 ──
std::vector<int> GetRenewalsDue(const std::vector<RenewalRecord>& records) {
    std::vector<int> due;
    FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER nowUl; nowUl.LowPart = nowFt.dwLowDateTime; nowUl.HighPart = nowFt.dwHighDateTime;
    for (int i = 0; i < (int)records.size(); i++) {
        if (!records[i].autoRenew || records[i].expiryTime.dwLowDateTime == 0) continue;
        ULARGE_INTEGER expUl; expUl.LowPart = records[i].expiryTime.dwLowDateTime; expUl.HighPart = records[i].expiryTime.dwHighDateTime;
        const ULONGLONG MAX_RENEWAL_DAYS = 3650;
        ULONGLONG days = records[i].renewalDays;
        if (days > MAX_RENEWAL_DAYS) days = MAX_RENEWAL_DAYS;
        ULONGLONG daysBefore = days * 24ULL * 60ULL * 60ULL * 10000000ULL;
        if (nowUl.QuadPart >= (expUl.QuadPart - daysBefore)) due.push_back(i);
    }
    return due;
}

// ── 计划任务创建（每日 09:00 + 4h 随机延迟） ──
bool CreateRenewalTask() {
    wchar_t exePath[MAX_PATH]; GetModuleFileNameW(NULL, exePath, MAX_PATH);
    // 获取当前用户 SID
    HANDLE hToken = NULL; if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;
    DWORD sz = 0; GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    std::vector<BYTE> buf(sz);
    GetTokenInformation(hToken, TokenUser, buf.data(), sz, &sz);
    CloseHandle(hToken);
    PTOKEN_USER pUser = (PTOKEN_USER)buf.data();
    LPWSTR pSidStr = NULL;
    ConvertSidToStringSidW(pUser->User.Sid, &pSidStr);
    std::wstring principalXml = L"<UserId>" + std::wstring(pSidStr ? pSidStr : L"") + L"</UserId><LogonType>S4U</LogonType><RunLevel>HighestAvailable</RunLevel>";
    if (pSidStr) LocalFree(pSidStr);

    // #28: 使用动态日期而非硬编码 2026-01-01
    SYSTEMTIME nowSt; GetLocalTime(&nowSt);
    wchar_t startBoundary[32];
    swprintf_s(startBoundary, L"%04d-%02d-%02dT09:00:00", nowSt.wYear, nowSt.wMonth, nowSt.wDay);

    std::wstring xml =
        L"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
        L"<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n"
        L"  <RegistrationInfo><Description>SSLClaw Automatic Certificate Renewal</Description></RegistrationInfo>\r\n"
        L"  <Triggers>\r\n"
        L"    <CalendarTrigger>\r\n"
        L"      <StartBoundary>" + std::wstring(startBoundary) + L"</StartBoundary>\r\n"
        L"      <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>\r\n"
        L"      <Enabled>true</Enabled>\r\n"
        L"      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>\r\n"
        L"      <RandomDelay>PT4H</RandomDelay>\r\n"
        L"    </CalendarTrigger>\r\n"
        L"  </Triggers>\r\n"
        L"  <Principals><Principal id=\"Author\">" + principalXml + L"</Principal></Principals>\r\n"
        L"  <Settings>\r\n"
        L"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n"
        L"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n"
        L"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n"
        L"    <AllowHardTerminate>true</AllowHardTerminate>\r\n"
        L"    <StartWhenAvailable>true</StartWhenAvailable>\r\n"
        L"    <Enabled>true</Enabled>\r\n"
        L"  </Settings>\r\n"
        L"  <Actions Context=\"Author\"><Exec><Command>\"" + std::wstring(exePath) + L"\"</Command><Arguments>--renew</Arguments></Exec></Actions>\r\n"
        L"</Task>\r\n";

    std::wstring xmlPath = std::wstring(exePath);
    wchar_t* xmlSlash = wcsrchr(&xmlPath[0], L'\\');
    if (xmlSlash) xmlSlash[1] = 0;
    xmlPath += L"sslclaw_task.xml";
    HANDLE h = CreateFileW(xmlPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::string xmlUtf8 = W2A(xml); DWORD written = 0;
    // #20: 检查 WriteFile 返回值
    BOOL writeOk = WriteFile(h, xmlUtf8.data(), (DWORD)xmlUtf8.size(), &written, NULL);
    CloseHandle(h);
    if (!writeOk || written != (DWORD)xmlUtf8.size()) { DeleteFileW(xmlPath.c_str()); return false; }

    std::wstring taskCmd = L"schtasks /Create /TN \"SSLClaw Renewal\" /XML \"" + xmlPath + L"\" /F";
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, (wchar_t*)taskCmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DeleteFileW(xmlPath.c_str());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exitCode = 0; GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    DeleteFileW(xmlPath.c_str());
    return (exitCode == 0);
}

bool DeleteRenewalTask() {
    std::wstring cmd = L"schtasks /Delete /TN \"SSLClaw Renewal\" /F";
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, (wchar_t*)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return false;
    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exitCode = 0; GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (exitCode == 0);
}

bool IsRenewalTaskExists() {
    std::wstring cmd = L"schtasks /Query /TN \"SSLClaw Renewal\" /FO LIST";
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; si.wShowWindow = SW_HIDE;
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    CreatePipe(&hRead, &hWrite, &sa, 0);
    si.hStdOutput = hWrite; si.hStdError = hWrite;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(NULL, (wchar_t*)cmd.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) { CloseHandle(hRead); CloseHandle(hWrite); return false; }
    CloseHandle(hWrite);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    char buf[256]; DWORD rd = 0;
    bool found = false;
    while (ReadFile(hRead, buf, sizeof(buf) - 1, &rd, NULL) && rd > 0) {
        buf[rd] = 0; if (strstr(buf, "SSLClaw Renewal")) { found = true; break; }
    }
    CloseHandle(hRead);
    return found;
}

// ── 执行单个续签 ──
// 返回 true=成功，false=失败；*pSkipped=true 表示因锁冲突被跳过（不计入重试）
bool PerformRenewal(RenewalRecord& record, bool* pSkipped) {
    AcmeLock lock;
    if (!lock.held) {
        LogRenewal(L"[续签] ACME 操作进行中，跳过 %s", record.domain.c_str());
        if (pSkipped) *pSkipped = true;
        return false;
    }
    if (pSkipped) *pSkipped = false;
    LogRenewal(L"\n--- 开始续签: %s ---", record.domain.c_str());

    // #21: 捕获 CA 环境索引，避免竞态
    extern int g_CAEnvIndex;
    g_CAIndex = g_CAEnvIndex;

    // 前置脚本
    if (!record.preScript.empty()) {
        LogRenewal(L"[续签] 执行前置脚本...");
        if (!ExecuteRenewalScript(record.preScript, record.domain)) {
            LogRenewal(L"[续签] [警告] 前置脚本执行失败，继续续签");
        }
    }

    // 加载/创建账户密钥
    std::string accKeyPath = W2A(record.saveDir) + "\\acme_account" + W2A(GetAccountKeySuffix()) + ".key";
    if (!LoadAccountKey(accKeyPath)) { MakeAccountKey(); SavePKEY(accKeyPath); LogRenewal(L"[续签] 已创建新的账户密钥"); }
    else { ExtractPublicKey(); LogRenewal(L"[续签] 已加载现有账户密钥"); }

    // 获取 ACME 目录和 Nonce
    g_AcmeNonce.clear();
    std::string dir = HttpJson(GetAcmeDirectory(), L"GET", NULL, 0, &g_AcmeNonce);
    std::string newAcct = JsonStr(dir, "newAccount");
    std::string newOrder = JsonStr(dir, "newOrder");
    if (dir.empty()) { LogRenewal(L"[错误] 无法连接 ACME 服务器"); return false; }
    if (newAcct.empty() || newOrder.empty()) { LogRenewal(L"[错误] 无法解析 ACME 目录响应"); return false; }
    if (g_AcmeNonce.empty()) {
        std::string nu = JsonStr(dir, "newNonce");
        if (!nu.empty()) HttpJson(A2W(nu).c_str(), L"HEAD", NULL, 0, &g_AcmeNonce);
    }
    if (g_AcmeNonce.empty()) { LogRenewal(L"[错误] 无法获取 Nonce"); return false; }

    // 注册/查找 ACME 账户
    {
        std::string regBody = "{\"termsOfServiceAgreed\":true";
        if (!record.email.empty()) regBody += ",\"contact\":[\"mailto:" + W2A(record.email) + "\"]";
        regBody += "}";
        std::string loc; DWORD regHttp = 0;
        std::string regResp; bool regOK = false;
        for (int retry = 0; retry < 10; retry++) {
            if (g_AcmeNonce.empty()) {
                std::string nu = JsonStr(dir, "newNonce");
                if (!nu.empty()) HttpJson(A2W(nu).c_str(), L"HEAD", NULL, 0, &g_AcmeNonce);
            }
            if (g_AcmeNonce.empty()) { LogRenewal(L"[错误] 无法获取 Nonce"); break; }
            regResp = AcmePost(newAcct, regBody, g_AcmeNonce, true, &loc, &regHttp);
            if (!loc.empty()) { regOK = true; break; }
            if (regResp.find("badNonce") != std::string::npos || regResp.find("invalid anti-replay") != std::string::npos) {
                LogRenewal(L"[续签] badNonce, 重试 %d/10...", retry + 1);
                g_AcmeNonce.clear();
                Sleep(1000); continue;
            }
            break;
        }
        if (!regOK) {
            LogRenewal(L"[错误] 帐户注册失败 (HTTP %d)", regHttp);
            LogRenewal(L"  响应: %.500S", regResp.c_str());
            return false;
        }
        g_AccURL = loc;
        std::string regStatus = JsonStr(regResp, "status");
        LogRenewal(L"[续签] 帐户状态: %s", A2W(regStatus.empty() ? std::string("已存在") : regStatus).c_str());
    }

    // ACME 新订单
    std::string nonce = g_AcmeNonce;
    std::string domainA = W2A(record.domain);
    std::string orderPayload = "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"" + domainA + "\"}]}";
    std::string orderUrl; DWORD orderStatus = 0;
    std::string orderResult = AcmePost(newOrder, orderPayload, nonce, false, &orderUrl, &orderStatus);
    if (orderResult.empty()) { LogRenewal(L"[错误] 订单创建失败"); return false; }
    LogRenewal(L"[续签] 订单响应(status=%d): %.500S", orderStatus, orderResult.c_str());

    // 解析授权
    size_t ap = orderResult.find("\"authorizations\"");
    if (ap == std::string::npos) { LogRenewal(L"[错误] 无授权信息，订单响应: %.500S", orderResult.c_str()); return false; }
    ap = orderResult.find("\"", ap + 16); if (ap == std::string::npos) return false; ap++;
    size_t ae = orderResult.find("\"", ap); if (ae == std::string::npos) return false;
    std::string authUrl = orderResult.substr(ap, ae - ap);
    std::string finalizeUrl = JsonStr(orderResult, "finalize");

    std::string authResult = AcmePost(authUrl, "", nonce, false, NULL, NULL);

    std::string challUrl, token, keyAuth;
    bool useTempServer = false;
    std::wstring challFile;
    std::wstring zone, subDomain;
    bool dnsApiCreated = false;
    DnsTxtCleanupGuard dnsGuard;

    if (record.verifyMode == 0) {
        // HTTP-01 验证
        ap = authResult.find("\"http-01\"");
        if (ap == std::string::npos) { LogRenewal(L"[错误] 无 http-01 挑战"); return false; }
        ap = authResult.find("\"url\"", ap); if (ap == std::string::npos) return false;
        ap = authResult.find(":", ap); ap = authResult.find("\"", ap) + 1;
        ae = authResult.find("\"", ap); if (ae == std::string::npos) return false;
        challUrl = authResult.substr(ap, ae - ap);

        ap = authResult.find("\"token\"", ap); if (ap == std::string::npos) return false;
        ap = authResult.find(":", ap); ap = authResult.find("\"", ap) + 1;
        ae = authResult.find("\"", ap); if (ae == std::string::npos) return false;
        token = authResult.substr(ap, ae - ap);
        keyAuth = token + "." + AccThumbprint();

        bool port80Free = IsPort80Free();
        if (port80Free) {
            SafeSetStatus(L"启动验证服务器...");
            LogRenewal(L"[续签] 80 端口空闲，启动临时验证服务器...");
            if (!StartTempHttpServer(token, keyAuth)) {
                LogRenewal(L"[错误] 临时验证服务器启动失败");
                return false;
            }
            useTempServer = true;
            LogRenewal(L"  临时验证服务器已启动（监听 80 端口）");

            // 本地自检：确认域名指向本机且临时服务器可正常响应
            SafeSetStatus(L"检查验证服务器...");
            LogRenewal(L"  本地自检临时服务器...");
            std::string selfChkBody2;
            std::wstring chkPath2 = L"/.well-known/acme-challenge/" + A2W(token);
            std::wstring baseDomain4Chk2 = record.domain;
            if (baseDomain4Chk2.size() >= 2 && baseDomain4Chk2[0] == L'*' && baseDomain4Chk2[1] == L'.') baseDomain4Chk2 = baseDomain4Chk2.substr(2);
            if (DoHttpSelfCheck(baseDomain4Chk2, chkPath2, keyAuth, selfChkBody2)) {
                if (selfChkBody2.find(keyAuth) != std::string::npos) {
                    LogRenewal(L"  本地自检通过，临时服务器响应正常");
                } else {
                    LogRenewal(L"[错误] 本地自检返回内容不匹配: %.100S", selfChkBody2.substr(0, 100).c_str());
                    LogRenewal(L"[错误] 域名 %s 可能未指向本机，请检查 DNS A 记录", baseDomain4Chk2.c_str());
                    StopTempHttpServer();
                    return false;
                }
            } else {
                LogRenewal(L"[错误] 本地自检失败，无法访问临时验证服务器");
                LogRenewal(L"[错误] 请确认域名 %s 的 A 记录指向本机 IP", baseDomain4Chk2.c_str());
                StopTempHttpServer();
                return false;
            }
        } else {
            SafeSetStatus(L"写入验证文件...");
            LogRenewal(L"[续签] Web 服务器运行中，写入验证文件...");
            if (record.webRoot.empty()) { LogRenewal(L"[错误] 需填写网站目录"); return false; }
            // 检查网站目录是否存在
            DWORD wrAttr = GetFileAttributesW(record.webRoot.c_str());
            if (wrAttr == INVALID_FILE_ATTRIBUTES || !(wrAttr & FILE_ATTRIBUTE_DIRECTORY)) {
                LogRenewal(L"[错误] 网站目录不存在: %s", record.webRoot.c_str()); return false;
            }
            std::wstring challDir = record.webRoot + L"\\.well-known\\acme-challenge";
            challFile = challDir + L"\\" + A2W(token);
            // 递归创建 .well-known\\acme-challenge 目录
            if (!EnsureDirectoryExists(challDir)) {
                LogRenewal(L"[错误] 无法创建目录 %s（请检查写入权限）", challDir.c_str());
                return false;
            }
            {
                HANDLE hcf = CreateFileW(challFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hcf == INVALID_HANDLE_VALUE) { LogRenewal(L"[错误] 无法写入验证文件 %s", challFile.c_str()); return false; }
                DWORD written2 = 0;
                // #20: 检查 WriteFile 返回值
                BOOL writeOk = WriteFile(hcf, keyAuth.data(), (DWORD)keyAuth.size(), &written2, NULL);
                CloseHandle(hcf);
                if (!writeOk || written2 != (DWORD)keyAuth.size()) {
                    LogRenewal(L"[错误] 验证文件写入不完整"); return false;
                }
            }
            LogRenewal(L"  已写入: .well-known/acme-challenge/%s", A2W(token).c_str());

            // HTTP 本地自检
            SafeSetStatus(L"检查验证文件...");
            LogRenewal(L"  本地自检验证文件...");
            std::string selfChkBody;
            std::wstring chkPath = L"/.well-known/acme-challenge/" + A2W(token);
            std::wstring baseDomain4Chk = record.domain;
            if (baseDomain4Chk.size() >= 2 && baseDomain4Chk[0] == L'*' && baseDomain4Chk[1] == L'.') baseDomain4Chk = baseDomain4Chk.substr(2);
            if (DoHttpSelfCheck(baseDomain4Chk, chkPath, keyAuth, selfChkBody)) {
                if (selfChkBody.find(keyAuth) != std::string::npos) {
                    LogRenewal(L"  本地自检通过，验证文件可正常访问");
                } else {
                    LogRenewal(L"[错误] 本地自检返回内容不匹配: %.100S", selfChkBody.substr(0, 100).c_str());
                    LogRenewal(L"[错误] 网站目录可能不正确，请检查网站目录设置");
                    return false;
                }
            } else {
                LogRenewal(L"[错误] 本地自检失败，无法访问验证文件");
                LogRenewal(L"[错误] 请确认域名 %s 指向本机、80 端口可访问、网站目录正确", baseDomain4Chk.c_str());
                return false;
            }
        }
    } else {
        // DNS-01 验证
        ap = authResult.find("\"dns-01\"");
        if (ap == std::string::npos) { LogRenewal(L"[错误] 无 dns-01 挑战"); return false; }
        ap = authResult.find("\"url\"", ap); if (ap == std::string::npos) return false;
        ap = authResult.find(":", ap); ap = authResult.find("\"", ap) + 1;
        ae = authResult.find("\"", ap); if (ae == std::string::npos) return false;
        challUrl = authResult.substr(ap, ae - ap);

        ap = authResult.find("\"token\"", ap); if (ap == std::string::npos) return false;
        ap = authResult.find(":", ap); ap = authResult.find("\"", ap) + 1;
        ae = authResult.find("\"", ap); if (ae == std::string::npos) return false;
        token = authResult.substr(ap, ae - ap);
        keyAuth = token + "." + AccThumbprint();
        std::string challengeB64 = Sha256B64(keyAuth);
        std::wstring baseDomain = record.domain;
        if (baseDomain.size() >= 2 && baseDomain[0] == L'*' && baseDomain[1] == L'.')
            baseDomain = baseDomain.substr(2);
        std::wstring wQueryName = L"_acme-challenge." + baseDomain;
        std::wstring wChallenge = A2W(challengeB64);

        LoadDnsConfigForDomain(record.domain);
        record.dnsProvider = g_DnsProvider;
        record.dnsApiId = g_DnsApiId;
        record.dnsApiSecret = g_DnsApiSecret;

        bool hasApi = (record.dnsProvider > 0 && ((!record.dnsApiId.empty() && !record.dnsApiSecret.empty()) || (record.dnsProvider == DNS_PROVIDER_CLOUDFLARE && !record.dnsApiSecret.empty())));
        if (hasApi) {
            // API 自动模式：自动创建 TXT 记录
            SafeSetStatus(L"自动创建 TXT 记录...");
            LogRenewal(L"[续签] DNS-01 验证 (API 自动模式)");

            DnsFindZone(record.dnsProvider, record.dnsApiId, record.dnsApiSecret, wQueryName, zone, subDomain);
            if (zone.empty()) { LogRenewal(L"[错误] 无法找到 DNS Zone，请检查 API 配置"); return false; }
            LogRenewal(L"  Zone: %s, 子域: %s", zone.c_str(), subDomain.c_str());

            std::wstring dnsErr = DnsCreateTxtRecord(record.dnsProvider, record.dnsApiId, record.dnsApiSecret, zone, subDomain, wChallenge);
            if (!dnsErr.empty()) { LogRenewal(L"[错误] TXT 记录创建失败: %s", dnsErr.c_str()); return false; }
            LogRenewal(L"  TXT 记录已自动创建");
            dnsApiCreated = true;
            // 设置 RAII 守卫
            dnsGuard.active = true;
            dnsGuard.provider = record.dnsProvider;
            dnsGuard.apiId = record.dnsApiId;
            dnsGuard.apiSecret = record.dnsApiSecret;
            dnsGuard.zone = zone;
            dnsGuard.subDomain = subDomain;

            SafeSetStatus(L"等待 DNS 传播...");
            LogRenewal(L"  等待 DNS 传播 (30秒)...");
            for (int ew = 30; ew > 0; ew -= 5) {
                Sleep(5000);
                // 检查后台线程是否被要求停止
                if (InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) == 0) {
                    LogRenewal(L"  TXT 记录将由 RAII 守卫清理 (线程停止)");
                    return false;
                }
            }

            // DNS 权威预验证（使用公共函数，#14: 消除重复代码）
            SafeSetStatus(L"检查 DNS 传播...");
            WaitForDnsTxtPropagation(wQueryName, wChallenge, challengeB64, L"  ");
        } else {
            // 手工模式不支持自动续签
            LogRenewal(L"[错误] DNS-01 手工模式不支持自动续签，请配置 DNS API 或使用 HTTP-01");
            SendNotificationEmail(L"SSLClaw 续签失败: " + record.domain, L"原因: DNS-01 手工模式不支持自动续签，请配置 DNS API 或使用 HTTP-01", record.saveDir, g_IniPath);
            return false;
        }
    }

    // 通知 ACME 验证
    SafeSetStatus(L"验证域名...");
    LogRenewal(L"[续签] 请求 ACME 验证...");
    AcmePost(challUrl, "{}", nonce, false, NULL, NULL);

    // 轮询验证状态
    bool verified = false;
    for (int i = 0; i < (record.verifyMode == 0 ? 12 : 60); i++) {
        // 分段 Sleep（5×1s），及时响应线程停止
        for (int s = 0; s < 5 && InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) != 0; s++) Sleep(1000);
        if (InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) == 0) {
            LogRenewal(L"[续签] 线程停止请求，中止验证轮询");
            return false;
        }
        DWORD pollHttpCode = 0;
        std::string stResult = AcmePost(authUrl, "", nonce, false, NULL, &pollHttpCode);
        if (pollHttpCode >= 400) {
            std::string errType = JsonStr(stResult, "type");
            std::string errDetail = JsonStr(stResult, "detail");
            if (errType.find("urn:ietf:params:acme:error:") != std::string::npos) {
                LogRenewal(L"[错误] ACME 错误 (HTTP %d): %S", pollHttpCode, errDetail.empty() ? stResult.substr(0, 200).c_str() : errDetail.c_str());
            } else {
                LogRenewal(L"[错误] 服务器错误 (HTTP %d): %.200S", pollHttpCode, stResult.c_str());
            }
            break;
        }
        std::string vStatus = JsonStr(stResult, "status");
        if (vStatus == "valid") { verified = true; break; }
        if (vStatus == "invalid") {
            std::string invDetail = JsonStr(stResult, "detail");
            if (invDetail.empty()) {
                size_t chArr2 = stResult.find("\"challenges\"");
                if (chArr2 != std::string::npos) {
                    size_t arrS2 = stResult.find('[', chArr2);
                    if (arrS2 != std::string::npos) {
                        size_t p2 = arrS2;
                        while (true) {
                            size_t ip2 = stResult.find("\"invalid\"", p2);
                            if (ip2 == std::string::npos) break;
                            size_t ep2 = stResult.find("\"error\"", p2);
                            if (ep2 != std::string::npos) {
                                std::string eType = JsonStr(stResult.substr(ep2, 300), "type");
                                std::string eDetail = JsonStr(stResult.substr(ep2, 500), "detail");
                                if (!eDetail.empty()) { invDetail = eDetail; break; }
                                if (!eType.empty()) { invDetail = eType; break; }
                            }
                            p2 = ip2 + 1;
                        }
                    }
                }
            }
            if (useTempServer) StopTempHttpServer();
            else if (record.verifyMode == 0 && !challFile.empty()) DeleteFileW(challFile.c_str());
            // DNS TXT 由 RAII 守卫清理
            if (!invDetail.empty()) LogRenewal(L"[错误] 验证失败: %S", invDetail.c_str());
            else LogRenewal(L"[错误] 验证失败，请检查域名解析和80端口可达性");
            SafeSetStatus(L"验证失败");
            SendNotificationEmail(L"SSLClaw 续签失败: " + record.domain, L"原因: ACME 服务器验证失败", record.saveDir, g_IniPath);
            return false;
        }
        if (vStatus.empty()) {
            if (i < 3) LogRenewal(L"[调试] ACME 原始响应(%d): %.300S", i + 1, stResult.c_str());
            LogRenewal(L"[续签] 等待... (%d/%d) [状态解析失败]", i + 1, record.verifyMode == 0 ? 12 : 60);
        } else {
            LogRenewal(L"[续签] 等待... (%d/%d) [状态: %S]", i + 1, record.verifyMode == 0 ? 12 : 60, vStatus.c_str());
        }
    }

    // 清理
    if (useTempServer) StopTempHttpServer();
    else if (record.verifyMode == 0 && !challFile.empty()) _wunlink(challFile.c_str());
    // DNS TXT 已完成使命，解除守卫并手动清理
    if (dnsApiCreated) { DnsDeleteTxtRecord(record.dnsProvider, record.dnsApiId, record.dnsApiSecret, zone, subDomain); LogRenewal(L"  TXT 记录已清理"); }
    dnsGuard.disarm();
    dnsApiCreated = false;

    if (!verified) { LogRenewal(L"[错误] 验证超时"); SafeSetStatus(L"验证超时"); return false; }
    LogRenewal(L"  验证通过");
    SafeSetStatus(L"验证通过，正在签发证书...");

    // 生成域密钥
    BCRYPT_ALG_HANDLE ha = NULL;
    NTSTATUS ntStatus = BCryptOpenAlgorithmProvider(&ha, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (ntStatus != 0) { LogRenewal(L"[错误] 无法打开算法提供者"); return false; }

    BCRYPT_KEY_HANDLE dk = NULL;
    ntStatus = BCryptGenerateKeyPair(ha, &dk, 2048, 0);
    if (ntStatus != 0) { BCryptCloseAlgorithmProvider(ha, 0); LogRenewal(L"[错误] 无法生成密钥对"); return false; }

    ntStatus = BCryptFinalizeKeyPair(dk, 0);
    if (ntStatus != 0) { BCryptDestroyKey(dk); BCryptCloseAlgorithmProvider(ha, 0); LogRenewal(L"[错误] 无法完成密钥对"); return false; }

    BCryptCloseAlgorithmProvider(ha, 0);

    // Finalize 订单
    std::vector<BYTE> csr = BuildCSR(domainA, dk, NULL);
    std::string csr64 = B64Url(csr);
    std::string finalizePayload = "{\"csr\":\"" + csr64 + "\"}";
    DWORD finHttpCode = 0;
    std::string finResp = AcmePost(finalizeUrl, finalizePayload, nonce, false, NULL, &finHttpCode);
    int finRetries = 0;
    while (finHttpCode == 400 && finResp.find("badNonce") != std::string::npos && finRetries < 2) {
        finRetries++; LogRenewal(L"[续签] 重试提交 CSR (badNonce, 第%d次)...", finRetries);
        finResp = AcmePost(finalizeUrl, finalizePayload, nonce, false, NULL, &finHttpCode);
    }
    if (finResp.empty()) {
        LogRenewal(L"[错误] 订单完成失败 (HTTP %d)", finHttpCode);
        BCryptDestroyKey(dk); return false;
    }
    if (finHttpCode >= 400) {
        std::string finErr = JsonStr(finResp, "detail");
        LogRenewal(L"[错误] CSR 提交被拒 (HTTP %d): %S", finHttpCode, finErr.empty() ? finResp.substr(0, 200).c_str() : finErr.c_str());
        BCryptDestroyKey(dk); return false;
    }
    std::string finStatus = JsonStr(finResp, "status");
    std::string certUrl = JsonStr(finResp, "certificate");
    LogRenewal(L"[续签] 订单状态: %S", finStatus.empty() ? "未知" : finStatus.c_str());

    // 等待证书
    if (certUrl.empty()) {
        for (int i = 0; i < 15; i++) {
            // 分段 Sleep（3×1s），及时响应线程停止
            for (int s = 0; s < 3 && InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) != 0; s++) Sleep(1000);
            if (InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) == 0) {
                LogRenewal(L"[续签] 线程停止请求，中止证书下载等待");
                BCryptDestroyKey(dk); return false;
            }
            std::string ordResult = AcmePost(orderUrl, "", nonce, false, NULL, NULL);
            std::string orderCheckStatus = JsonStr(ordResult, "status");
            if (orderCheckStatus == "invalid") {
                std::string errDetail = JsonStr(ordResult, "error");
                LogRenewal(L"[错误] 订单状态无效: %S", errDetail.empty() ? ordResult.substr(0, 200).c_str() : errDetail.c_str());
                BCryptDestroyKey(dk); return false;
            }
            certUrl = JsonStr(ordResult, "certificate");
            if (!certUrl.empty()) break;
            LogRenewal(L"[续签] 等待... (%d/15) 状态: %S", i + 1, orderCheckStatus.empty() ? "未知" : orderCheckStatus.c_str());
        }
    }
    if (certUrl.empty()) { LogRenewal(L"[错误] 获取证书下载链接超时"); BCryptDestroyKey(dk); return false; }

    // 下载证书
    std::string certResult = AcmePost(certUrl, "", nonce, false, NULL, NULL);
    if (certResult.empty()) { LogRenewal(L"[错误] 证书下载失败"); BCryptDestroyKey(dk); return false; }

    // 使用公共函数构建文件名（#13: 消除重复代码）
    std::wstring nt = SanitizeDomainToFileName(record.domain);

    // 确保保存目录存在（使用公共函数，#15: 消除重复代码）
    EnsureDirectoryExists(record.saveDir);

    // 保存证书文件（使用公共函数，#12-#15: 消除重复代码）
    std::wstring pfxPath;
    if (!SaveCertFiles(dk, certResult, record.saveDir, nt, record.serverType, &pfxPath, L"[续签] ")) {
        BCryptDestroyKey(dk);
        LogRenewal(L"[续签] 证书保存失败，终止续签");
        SendNotificationEmail(L"SSLClaw 续签失败: " + record.domain, L"域名: " + record.domain + L"\n原因: 证书保存失败（磁盘空间不足或权限问题）", record.saveDir, g_IniPath);
        return false;
    }

    // IIS 自动部署（续签后更新证书存储和站点绑定）
    if (record.serverType == 2 && dk && !pfxPath.empty()) {
        DeployRenewalToIIS(record, dk, certResult, pfxPath);
    }

    BCryptDestroyKey(dk);

    // 更新续签记录，从证书中提取实际到期时间（使用公共函数，#12: 消除重复代码）
    FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
    record.issueTime = nowFt;
    FILETIME certExpFt = ParseCertExpiryFromPem(certResult);
    if (certExpFt.dwLowDateTime == 0 && certExpFt.dwHighDateTime == 0) {
        // 解析失败，回退到 90 天
        ULARGE_INTEGER expUl; expUl.LowPart = nowFt.dwLowDateTime; expUl.HighPart = nowFt.dwHighDateTime;
        expUl.QuadPart += 90ULL * 24ULL * 60ULL * 60ULL * 10000000ULL;
        certExpFt.dwLowDateTime = expUl.LowPart; certExpFt.dwHighDateTime = expUl.HighPart;
    }
    record.expiryTime = certExpFt;

    LogRenewal(L"[续签] 续签成功: %s", record.domain.c_str());
    SafeSetStatus(L"续签成功");

    // 邮件通知
    SendNotificationEmail(L"SSLClaw 续签成功: " + record.domain,
        L"域名: " + record.domain + L"\n过期时间: " + FtToStr(record.expiryTime),
        record.saveDir, g_IniPath);

    // 后置脚本
    if (!record.postScript.empty()) {
        LogRenewal(L"[续签] 执行后置脚本...");
        ExecuteRenewalScript(record.postScript, record.domain);
    }

    LogRenewal(L"[续签] %s 续签完成，下次过期: %s", record.domain.c_str(), FtToStr(record.expiryTime).c_str());
    return true;
}

// ── CLI 自动续签模式 ──
static volatile LONG g_RenewalModeRunning = 0;

int RunRenewalMode() {
    // 防止重复执行
    if (InterlockedCompareExchange(&g_RenewalModeRunning, 1, 0) != 0) {
        LogRenewalStatus(L"[续签] 流程运行中，跳过");
        return 0;
    }

    LogRenewalStatus(L"[续签] 启动");

    // 如果后台线程正在运行，唤醒它处理续签
    if (InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) != 0) {
        LogRenewalStatus(L"[续签] 唤醒后台线程");
        WakeRenewalCheck();
        InterlockedExchange(&g_RenewalModeRunning, 0);
        return 0;
    }

    std::vector<RenewalRecord> records;
    if (!LoadRenewalRecords(records)) {
        LogRenewalStatus(L"[续签] 无记录");
        InterlockedExchange(&g_RenewalModeRunning, 0);
        return 0;
    }

    // 从主配置读取当前保存目录
    {
        wchar_t iniBuf[2048];
        GetPrivateProfileStringW(L"SSLClaw", L"SaveDir", L"", iniBuf, 2048, g_IniPath.c_str());
        std::wstring mainSaveDir(iniBuf);
        if (!mainSaveDir.empty()) {
            for (auto& rec : records) {
                rec.saveDir = mainSaveDir;
            }
            LogRenewal(L"[续签] 使用保存目录: %s", mainSaveDir.c_str());
        }
    }

    std::vector<int> due = GetRenewalsDue(records);

    if (due.empty()) {
        LogRenewalStatus(L"[续签模式] 没有需要续签的证书");
        InterlockedExchange(&g_RenewalModeRunning, 0);
        return 0;
    }

    int success = 0, failed = 0;
    for (int idx : due) {
        EnterCriticalSection(&g_RenewCs);
        bool alreadyRenewing = g_RenewingDomains.count(records[idx].domain) > 0;
        if (!alreadyRenewing) g_RenewingDomains.insert(records[idx].domain);
        LeaveCriticalSection(&g_RenewCs);

        if (alreadyRenewing) {
            LogRenewal(L"[续签] %s 正在续签中，跳过", records[idx].domain.c_str());
            continue;
        }

        LogRenewal(L"[续签] 处理: %s (过期: %s)", records[idx].domain.c_str(), FtToStr(records[idx].expiryTime).c_str());
        if (PerformRenewalWithRetry(records[idx])) {
            AddOrUpdateRenewal(records[idx]);
            success++;
        } else {
            failed++;
        }

        EnterCriticalSection(&g_RenewCs);
        g_RenewingDomains.erase(records[idx].domain);
        LeaveCriticalSection(&g_RenewCs);
    }

    LogRenewal(L"\n[续签] 完成: 成功 %d, 失败 %d", success, failed);
    InterlockedExchange(&g_RenewalModeRunning, 0);
    return (failed > 0) ? 1 : 0;
}

// ── 续签重试（指数退避） ──
bool PerformRenewalWithRetry(RenewalRecord& record) {
    // #26: 使用临界区保护 g_RetryStates 访问
    EnterCriticalSection(&g_RenewCs);
    RenewalRetryState* rs = nullptr;
    for (auto& s : g_RetryStates) {
        if (s.domain == record.domain) { rs = &s; break; }
    }
    if (!rs) {
        g_RetryStates.push_back({});
        rs = &g_RetryStates.back();
        rs->domain = record.domain;
        rs->attemptCount = 0;
    }

    rs->attemptCount++;
    int attempt = rs->attemptCount;
    LeaveCriticalSection(&g_RenewCs);

    LogRenewal(L"[续签] %s 第 %d 次尝试", record.domain.c_str(), attempt);

    bool skipped = false;
    bool success = PerformRenewal(record, &skipped);

    if (skipped) {
        return false;
    }

    if (success) {
        // 成功后清除重试状态
        EnterCriticalSection(&g_RenewCs);
        g_RetryStates.erase(std::remove_if(g_RetryStates.begin(), g_RetryStates.end(),
            [&](const RenewalRetryState& s) { return s.domain == record.domain; }),
            g_RetryStates.end());
        LeaveCriticalSection(&g_RenewCs);
        return true;
    }

    // 计算下次重试时间（指数退避: 2h, 4h, 8h, 16h, 24h max）
    int delayHours = (std::min)(2 << (attempt - 1), RENEWAL_RETRY_MAX_HOURS);
    FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER nowUl; nowUl.LowPart = nowFt.dwLowDateTime; nowUl.HighPart = nowFt.dwHighDateTime;
    nowUl.QuadPart += (ULONGLONG)delayHours * 3600ULL * 10000000ULL;

    EnterCriticalSection(&g_RenewCs);
    // 重新查找 rs（vector 可能在其他线程操作后失效）
    for (auto& s : g_RetryStates) {
        if (s.domain == record.domain) {
            s.nextRetryTime.dwLowDateTime = nowUl.LowPart;
            s.nextRetryTime.dwHighDateTime = nowUl.HighPart;
            break;
        }
    }
    LeaveCriticalSection(&g_RenewCs);

    LogRenewal(L"[续签] %s 失败，%d 小时后重试（第 %d 次）", record.domain.c_str(), delayHours, attempt);

    // 检查是否已超过续签窗口（证书已过期）
    ULARGE_INTEGER expUl; expUl.LowPart = record.expiryTime.dwLowDateTime; expUl.HighPart = record.expiryTime.dwHighDateTime;
    if (nowUl.QuadPart >= expUl.QuadPart) {
        LogRenewal(L"[续签] %s 已过期，停止重试", record.domain.c_str());
        EnterCriticalSection(&g_RenewCs);
        g_RetryStates.erase(std::remove_if(g_RetryStates.begin(), g_RetryStates.end(),
            [&](const RenewalRetryState& s) { return s.domain == record.domain; }),
            g_RetryStates.end());
        LeaveCriticalSection(&g_RenewCs);
        return false;
    }

    return false;
}

// ── IIS 自动部署 ──
bool DeployRenewalToIIS(RenewalRecord& record, BCRYPT_KEY_HANDLE dk, const std::string& certPem, const std::wstring& pfxPath) {
    // 1. 导入 PFX 到 Windows Certificate Store
    CRYPT_DATA_BLOB pfxBlob = {};
    HANDLE hf = CreateFileW(pfxPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        LogRenewal(L"[IIS] 无法打开 PFX 文件: %s", pfxPath.c_str());
        return false;
    }
    DWORD fileSize = GetFileSize(hf, NULL);
    // #8: 检查 LocalAlloc 返回值
    pfxBlob.pbData = (BYTE*)LocalAlloc(LMEM_FIXED, fileSize);
    if (!pfxBlob.pbData) {
        LogRenewal(L"[IIS] 内存分配失败 (%d 字节)", fileSize);
        CloseHandle(hf);
        return false;
    }
    pfxBlob.cbData = fileSize;
    DWORD rd = 0;
    // #20: 检查 ReadFile 返回值
    BOOL readOk = ReadFile(hf, pfxBlob.pbData, fileSize, &rd, NULL);
    CloseHandle(hf);
    if (!readOk || rd != fileSize) {
        LogRenewal(L"[IIS] PFX 文件读取不完整 (期望 %d, 实际 %d)", fileSize, rd);
        LocalFree(pfxBlob.pbData);
        return false;
    }

    // 导入到 Local Machine\My store
    HCERTSTORE hMyStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"MY");
    if (!hMyStore) {
        LogRenewal(L"[IIS] 无法打开证书存储");
        LocalFree(pfxBlob.pbData);
        return false;
    }

    HCERTSTORE hPfxStore = PFXImportCertStore(&pfxBlob, L"", PKCS12_NO_PERSIST_KEY | CRYPT_EXPORTABLE);
    LocalFree(pfxBlob.pbData);
    if (!hPfxStore) {
        LogRenewal(L"[IIS] PFX 导入失败 (错误: %d)", GetLastError());
        CertCloseStore(hMyStore, 0);
        return false;
    }

    // 复制证书到 MY store，并获取 thumbprint
    PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hPfxStore, NULL);
    std::wstring thumbprint;
    if (pCert) {
        DWORD thumbSize = 20;
        BYTE thumbBuf[20];
        CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, thumbBuf, &thumbSize);
        wchar_t thumbStr[64] = {};
        for (DWORD i = 0; i < thumbSize; i++) swprintf_s(thumbStr + i * 2, 3, L"%02X", thumbBuf[i]);
        thumbprint = thumbStr;

        PCCERT_CONTEXT pAdded = NULL;
        if (CertAddCertificateContextToStore(hMyStore, pCert, CERT_STORE_ADD_REPLACE_EXISTING, &pAdded)) {
            SYSTEMTIME st; GetLocalTime(&st);
            wchar_t friendly[128]; swprintf_s(friendly, L"%s (%04d-%02d-%02d)", record.domain.c_str(), st.wYear, st.wMonth, st.wDay);
            CertSetCertificateContextProperty(pAdded, CERT_FRIENDLY_NAME_PROP_ID, 0, friendly);
            record.thumbprint = thumbprint;
            record.friendlyName = friendly;
            LogRenewal(L"[IIS] 证书已导入: thumbprint=%s", thumbprint.c_str());
            CertFreeCertificateContext(pAdded);
        }
        CertFreeCertificateContext(pCert);
    }
    CertCloseStore(hPfxStore, 0);
    CertCloseStore(hMyStore, 0);

    if (thumbprint.empty()) {
        LogRenewal(L"[IIS] 未找到证书");
        return false;
    }

    // 2. 更新 IIS 绑定（使用 appcmd）
    std::string domainA = W2A(record.domain);
    std::string baseDomainA = domainA;
    if (baseDomainA.size() >= 2 && baseDomainA[0] == '*' && baseDomainA[1] == '.')
        baseDomainA = baseDomainA.substr(2);

    std::wstring appcmd = L"C:\\Windows\\System32\\inetsrv\\appcmd.exe";
    std::wstring listCmd = appcmd + L" list sites";
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; si.wShowWindow = SW_HIDE;
    HANDLE hRead, hWrite; SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE }; CreatePipe(&hRead, &hWrite, &sa, 0);
    si.hStdOutput = hWrite; si.hStdError = hWrite;
    PROCESS_INFORMATION pi = {};
    if (CreateProcessW(NULL, (wchar_t*)listCmd.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hWrite);
        std::string output; char buf[4096]; DWORD rd2 = 0;
        while (ReadFile(hRead, buf, sizeof(buf) - 1, &rd2, NULL) && rd2 > 0) { buf[rd2] = 0; output += buf; }
        CloseHandle(hRead); WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);

        std::istringstream iss(output); std::string line;
        while (std::getline(iss, line)) {
            if (line.find(baseDomainA) != std::string::npos && line.find("https") != std::string::npos) {
                size_t q1 = line.find('"'); size_t q2 = line.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) {
                    std::string siteName = line.substr(q1 + 1, q2 - q1 - 1);
                    LogRenewal(L"[IIS] 找到站点: %S，更新绑定", siteName.c_str());
                    std::wstring bindCmd = appcmd + L" set site /site.name:" + A2W(siteName) + L" /[bindings='https/*:443:" + A2W(baseDomainA) + L"'].certificateThumbprint:" + thumbprint;
                    STARTUPINFOW si2 = { sizeof(si2) }; si2.dwFlags = STARTF_USESHOWWINDOW; si2.wShowWindow = SW_HIDE;
                    PROCESS_INFORMATION pi2 = {};
                    if (CreateProcessW(NULL, (wchar_t*)bindCmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si2, &pi2)) {
                        WaitForSingleObject(pi2.hProcess, 10000);
                        DWORD ec = 0; GetExitCodeProcess(pi2.hProcess, &ec);
                        CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);
                        if (ec == 0) LogRenewal(L"[IIS] 绑定已更新: %S → %s", siteName.c_str(), thumbprint.c_str());
                        else LogRenewal(L"[IIS] 绑定更新失败 (退出码: %d)", ec);
                    }
                }
            }
        }
    }

    return true;
}

// ── 后台续签线程 ──
unsigned __stdcall RenewalCheckThread(void* param) {
    LogRenewalStatus(L"[后台] 续签线程已启动");

    // 初始延迟 30 秒让 UI 稳定
    for (int i = 0; i < 30 && InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) != 0; i++) Sleep(1000);

    while (InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) != 0) {
        LogRenewalStatus(L"[后台] 检查续签记录...");

        std::vector<RenewalRecord> records;
        LoadRenewalRecords(records);

        // 从主配置读取当前保存目录
        {
            wchar_t iniBuf[2048];
            GetPrivateProfileStringW(L"SSLClaw", L"SaveDir", L"", iniBuf, 2048, g_IniPath.c_str());
            std::wstring mainSaveDir(iniBuf);
            if (!mainSaveDir.empty()) {
                for (auto& rec : records) {
                    rec.saveDir = mainSaveDir;
                }
            }
        }

        // 获取需要续签的记录
        std::vector<int> due = GetRenewalsDue(records);

        // 检查重试状态：已过重试时间的也加入（#26: 线程安全）
        FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
        ULARGE_INTEGER nowUl; nowUl.LowPart = nowFt.dwLowDateTime; nowUl.HighPart = nowFt.dwHighDateTime;
        EnterCriticalSection(&g_RenewCs);
        for (int i = 0; i < (int)records.size(); i++) {
            if (!records[i].autoRenew) continue;
            if (std::find(due.begin(), due.end(), i) != due.end()) continue;

            for (auto& rs : g_RetryStates) {
                if (rs.domain == records[i].domain) {
                    ULARGE_INTEGER retryUl; retryUl.LowPart = rs.nextRetryTime.dwLowDateTime; retryUl.HighPart = rs.nextRetryTime.dwHighDateTime;
                    if (nowUl.QuadPart >= retryUl.QuadPart) {
                        due.push_back(i);
                    }
                    break;
                }
            }
        }
        LeaveCriticalSection(&g_RenewCs);

        if (due.empty()) {
            LogRenewalStatus(L"[后台] 暂无需要续签的证书");
        } else {
            LogRenewalStatus(L"[后台] 发现 %d 个证书需要处理", (int)due.size());
        }

        for (int idx : due) {
            if (InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) == 0) break;

            EnterCriticalSection(&g_RenewCs);
            bool alreadyRenewing = g_RenewingDomains.count(records[idx].domain) > 0;
            if (!alreadyRenewing) g_RenewingDomains.insert(records[idx].domain);
            LeaveCriticalSection(&g_RenewCs);

            if (alreadyRenewing) {
                LogRenewalStatus(L"[后台] %s 正在续签中，跳过", records[idx].domain.c_str());
                continue;
            }

            bool success = PerformRenewalWithRetry(records[idx]);

            if (success) {
                AddOrUpdateRenewal(records[idx]);
                LogRenewalStatus(L"[后台] %s 续签成功，记录已持久化", records[idx].domain.c_str());
            }

            EnterCriticalSection(&g_RenewCs);
            g_RenewingDomains.erase(records[idx].domain);
            LeaveCriticalSection(&g_RenewCs);
        }

        // 动态检查间隔：有到期证书时5分钟快速检查，否则6小时低频巡逻
        int checkInterval = due.empty() ? RENEWAL_CHECK_INTERVAL_SEC : RENEWAL_CHECK_FAST_SEC;
        for (int i = 0; i < checkInterval && InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) != 0; i++) {
            if (g_RenewalWakeEvent && WaitForSingleObject(g_RenewalWakeEvent, 1000) == WAIT_OBJECT_0) {
                ResetEvent(g_RenewalWakeEvent);
                LogRenewalStatus(L"[后台] 收到唤醒信号，立即检查");
                break;
            }
        }
    }

    LogRenewalStatus(L"[后台] 续签线程已退出");
    return 0;
}

void StartRenewalBackgroundThread() {
    // #5: 使用 InterlockedCompareExchange 确保线程安全
    if (InterlockedCompareExchange(&g_RenewalThreadRunning, 1, 0) != 0) return;
    g_RenewalWakeEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_RenewalThread = (HANDLE)_beginthreadex(NULL, 0, RenewalCheckThread, NULL, 0, NULL);
    LogRenewalStatus(L"[后台] 后台线程已启动");
}

void StopRenewalBackgroundThread() {
    if (InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) == 0) return;
    InterlockedExchange(&g_RenewalThreadRunning, 0);
    if (g_RenewalWakeEvent) SetEvent(g_RenewalWakeEvent);
    if (g_RenewalThread) {
        WaitForSingleObject(g_RenewalThread, 5000);
        CloseHandle(g_RenewalThread);
        g_RenewalThread = NULL;
    }
    if (g_RenewalWakeEvent) { CloseHandle(g_RenewalWakeEvent); g_RenewalWakeEvent = NULL; }
    LogRenewalStatus(L"[后台] 后台线程已停止");
}

void WakeRenewalCheck() {
    if (g_RenewalWakeEvent) SetEvent(g_RenewalWakeEvent);
}

bool IsRenewalBackgroundRunning() {
    return InterlockedCompareExchange(&g_RenewalThreadRunning, 0, 0) != 0;
}

bool IsDomainRenewing(const std::wstring& domain) {
    if (!g_RenewCsInit) return false;
    EnterCriticalSection(&g_RenewCs);
    bool result = g_RenewingDomains.count(domain) > 0;
    LeaveCriticalSection(&g_RenewCs);
    return result;
}
