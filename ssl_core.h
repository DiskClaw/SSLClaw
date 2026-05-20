// ssl_core.h - SSL 证书核心功能
#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <wincrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include <process.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <windns.h>

// 链接库指令放在 ssl_core.cpp 中，避免头文件污染其他编译单元

#ifndef BCRYPT_PKCS8_PRIVATE_KEY_BLOB
#define BCRYPT_PKCS8_PRIVATE_KEY_BLOB L"PKCS8_PRIVATEKEY"
#endif
#ifndef szOID_RSA_RSA
#define szOID_RSA_RSA "1.2.840.113549.1.1.1"
#endif
#ifndef szOID_SUBJECT_ALT_NAME2
#define szOID_SUBJECT_ALT_NAME2 "2.5.29.17"
#endif
#ifndef szOID_PKCS_9_EXTENSION_REQUEST
#define szOID_PKCS_9_EXTENSION_REQUEST "1.2.840.113549.1.9.14"
#endif

// CA 机构
enum CAIndex { CA_LE = 0, CA_LE_STAGING = 1 };
const wchar_t* GetAcmeDirectory();
const wchar_t* GetAcmeStagingDirectory();
const wchar_t* GetAccountKeySuffix();
extern int g_CAIndex;

// 续签后台线程配置
#define RENEWAL_CHECK_INTERVAL_SEC (6 * 60 * 60)  // 6小时检查一次
#define RENEWAL_RETRY_MAX_HOURS 24                 // 最大重试间隔24小时
#define RENEWAL_SCRIPT_TIMEOUT_MS 120000           // 脚本执行超时2分钟

// 工具函数
std::string W2A(const std::wstring& w);
std::wstring A2W(const std::string& a);
std::string B64Url(const std::vector<BYTE>& d);
std::string B64UrlS(const std::string& s);
std::string B64Pem(const std::vector<BYTE>& d);
std::string Sha256B64(const std::string& data);
std::string JsonStr(const std::string& json, const char* key);

// HTTP 请求
std::string HttpJson(const wchar_t* url, const wchar_t* method, const char* body, int bodyLen,
                     std::string* outNonce = NULL, std::string* outLocation = NULL,
                     DWORD* outStatusCode = NULL);

// ACME 功能
bool MakeAccountKey();
bool LoadAccountKey(const std::string& path);
bool ExtractPublicKey();
std::string MakeJWK();
std::string AccThumbprint();
void SavePKEY(const std::string& path);
std::string SignJWS(const std::string& payload, const std::string& nonce, const std::string& url, bool useJWK);
std::string AcmePost(const std::string& urlStr, const std::string& payload,
                     std::string& nonce, bool useJWK = false,
                     std::string* outLocation = NULL, DWORD* outStatus = NULL);

// CSR 生成（支持多域名 SAN）
std::vector<BYTE> BuildCSR(const std::string& domain, BCRYPT_KEY_HANDLE key,
                            const std::vector<std::string>* extraSans = NULL);

// GUID 生成（用于 NCrypt 密钥容器名，避免冲突）
std::wstring NewGuid();

// 证书链处理：确保 PEM 包含完整链（叶子+中间证书）
std::string EnsureCertChain(const std::string& certPem);

// 证书吊销
bool RevokeCertificate(const std::string& domain, const std::string& certPem, const std::string& reason = "");

// 全局状态
extern BCRYPT_KEY_HANDLE g_AccKey;
extern std::string g_AccPubB64;
extern std::string g_AccExpB64;
extern std::string g_AccURL;
extern std::wstring g_AccURLPath;  // 账户 URL 持久化路径
extern std::wstring g_IniPath;     // 统一配置文件路径

// 日志文件
extern std::wstring g_LogFilePath;
void LogToFile(const wchar_t* msg);

// 证书申请线程
extern bool g_Running;
extern bool g_AutoScroll;
extern HANDLE g_hDnsReady;  // DNS-01 手动继续事件
extern std::wstring g_WebRoot;
extern CRITICAL_SECTION g_cs;
unsigned __stdcall ApplyThread(void* param);

// IIS 原生部署（Certificate Store + 自动绑定 IIS 站点）
bool DeployToIIS(BCRYPT_KEY_HANDLE dk, const std::string& certPem,
                 const std::string& domainA, const std::wstring& pfxPath,
                 std::wstring* outThumbprint = nullptr, std::wstring* outFriendlyName = nullptr);
bool BindCertToIIS(const std::string& domainA, const std::wstring& thumbprint);
std::wstring GeneratePassword(int len = 24);

// ========== 续签系统 ==========

// 续签记录
struct RenewalRecord {
    std::wstring domain;        // 域名
    bool wildcard = false;      // 通配符
    int serverType = 0;         // 服务器类型索引
    int verifyMode = 0;        // 验证方式 0=HTTP-01, 1=DNS-01
    std::wstring webRoot;      // 网站目录
    std::wstring saveDir;      // 保存目录
    std::wstring email;        // 邮箱
    bool autoRenew = false;    // 自动续签
    std::wstring thumbprint;   // 证书指纹
    std::wstring friendlyName; // 证书友好名称
    FILETIME issueTime = {};   // 签发时间
    FILETIME expiryTime = {};  // 过期时间
    int renewalDays = 60;      // 提前多少天续签
    std::wstring preScript;    // 前置脚本
    std::wstring postScript;   // 后置脚本
    // DNS-01 API 自动化（密钥不存续签记录，续签时从主配置读取）
    int dnsProvider = 0;       // DNS提供商 0=手动, 1=阿里云, 2=腾讯云, 3=Cloudflare
    std::wstring dnsApiId;     // [运行时] 从主配置填充，不持久化
    std::wstring dnsApiSecret; // [运行时] 从主配置填充，不持久化
};

// 续签记录持久化
std::wstring GetRenewalIniPath();
bool LoadRenewalRecords(std::vector<RenewalRecord>& records);
bool SaveRenewalRecords(const std::vector<RenewalRecord>& records);
int FindRenewalByDomain(const std::vector<RenewalRecord>& records, const std::wstring& domain);
void AddOrUpdateRenewal(const RenewalRecord& record);

// 续签检查（返回需要续签的记录索引列表）
std::vector<int> GetRenewalsDue(const std::vector<RenewalRecord>& records);

// 执行单个续签
bool PerformRenewal(RenewalRecord& record);

// Windows 计划任务管理（兼容保留，新代码用后台线程）
bool CreateRenewalTask();
bool DeleteRenewalTask();
bool IsRenewalTaskExists();

// CLI 模式：自动续签
int RunRenewalMode();

// 后台续签线程（替代计划任务）
void StartRenewalBackgroundThread();
void StopRenewalBackgroundThread();
void WakeRenewalCheck();
bool IsRenewalBackgroundRunning();
bool IsDomainRenewing(const std::wstring& domain);

// 续签重试（指数退避）
bool PerformRenewalWithRetry(RenewalRecord& record);

// 续签脚本执行
bool ExecuteRenewalScript(const std::wstring& script, const std::wstring& domain);

// 续签后 IIS 自动部署
bool DeployRenewalToIIS(RenewalRecord& record, BCRYPT_KEY_HANDLE dk, const std::string& certPem, const std::wstring& pfxPath);

// 旧计划任务迁移
void MigrateOldScheduledTask();

// 续签并发控制
extern std::set<std::wstring> g_RenewingDomains;

// 证书查询（同时扫描文件和 Certificate Store）
struct CertInfo {
    std::wstring subject;      // 主题
    std::wstring thumbprint;   // 指纹
    std::wstring friendlyName; // 友好名称
    int daysLeft = 0;          // 剩余天数
    FILETIME expiryTime = {};  // 过期时间
    std::wstring source;       // 来源（文件路径或 Store）
    bool inStore = false;      // 是否在 Certificate Store 中
};
std::vector<CertInfo> ScanAllCertificates(const std::wstring& saveDir);

// DNS-01 API 自动化接口
struct DnsProvider {
    std::wstring name;         // 提供商名称
    int id;                    // 标识符
};
std::vector<DnsProvider> GetAvailableDnsProviders();

// ========== DNS 提供商常量 ==========
#define DNS_PROVIDER_MANUAL       0
#define DNS_PROVIDER_ALIYUN       1
#define DNS_PROVIDER_TENCENT      2
#define DNS_PROVIDER_CLOUDFLARE   3

// DNS TXT 记录操作（返回空字符串=成功，非空=错误信息）
std::wstring DnsCreateTxtRecord(int provider, const std::wstring& apiId, const std::wstring& apiSecret,
    const std::wstring& domain, const std::wstring& subDomain, const std::wstring& value);
std::wstring DnsDeleteTxtRecord(int provider, const std::wstring& apiId, const std::wstring& apiSecret,
    const std::wstring& domain, const std::wstring& subDomain);
std::wstring DnsFindZone(int provider, const std::wstring& apiId, const std::wstring& apiSecret,
    const std::wstring& recordName, std::wstring& outZone, std::wstring& outSubDomain);
bool DnsVerifyApi(int provider, const std::wstring& apiId, const std::wstring& apiSecret);

// ========== 工具增强 ==========

// DPAPI 加密/解密字符串
std::string ProtectString(const std::string& clearText);
std::string UnprotectString(const std::string& protectedText);
void EnsureIniUtf16(const wchar_t* iniPath);
void WriteProtectedProfileStringW(const wchar_t* iniPath, const wchar_t* section, const wchar_t* key, const std::wstring& value);
std::wstring GetProtectedProfileStringW(const wchar_t* iniPath, const wchar_t* section, const wchar_t* key, const wchar_t* def);

// DNS 权威服务器预验证（递归查询 NS，直接向权威 DNS 查询 TXT）
bool DnsPreValidateAuthoritative(const std::wstring& queryName, const std::wstring& expectedValue, int maxRetries, int retryInterval);

// SMTP 邮件通知
void SendNotificationEmail(const std::wstring& subject, const std::wstring& body, const std::wstring& saveDir, const std::wstring& iniPath);
