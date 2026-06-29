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
#define RENEWAL_CHECK_INTERVAL_SEC (6 * 60 * 60)  // 默认 6h 巡逻
#define RENEWAL_CHECK_FAST_SEC (5 * 60)            // 有到期证书时 5min 快速检查
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
bool DoHttpSelfCheck(const std::wstring& host, const std::wstring& path, const std::string& expected, std::string& outBody);

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

// 证书链处理和吊销（预留，未实现）
// std::string EnsureCertChain(const std::string& certPem);
// bool RevokeCertificate(const std::string& domain, const std::string& certPem, const std::string& reason = "");

// 全局状态
extern BCRYPT_KEY_HANDLE g_AccKey;
extern std::string g_AccPubB64;
extern std::string g_AccExpB64;
extern std::string g_AccURL;
extern std::wstring g_IniPath;     // 统一配置文件路径
extern std::string g_AcmeNonce;   // ACME Nonce（受 g_AcmeBusyFlag 串行化保护）

// 日志文件
extern std::wstring g_LogFilePath;
void LogToFile(const wchar_t* msg);

// 证书申请线程
// volatile 确保等待循环中编译器不会缓存该值（线程间可见性）
extern volatile bool g_Running;
extern bool g_AutoScroll;
extern HANDLE g_hDnsReady;  // DNS-01 手动继续事件
extern std::wstring g_WebRoot;
extern CRITICAL_SECTION g_cs;
unsigned __stdcall ApplyThread(void* param);

// IIS 原生部署（预留，未实现，续签流程中使用 DeployRenewalToIIS）
// bool DeployToIIS(BCRYPT_KEY_HANDLE dk, const std::string& certPem,
//                  const std::string& domainA, const std::wstring& pfxPath,
//                  std::wstring* outThumbprint = nullptr, std::wstring* outFriendlyName = nullptr);
// bool BindCertToIIS(const std::string& domainA, const std::wstring& thumbprint);
std::wstring GeneratePassword(int len = 24);

// 续签系统

// 到期前 7 天触发续签
#define DEFAULT_RENEWAL_DAYS 7

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
    int renewalDays = DEFAULT_RENEWAL_DAYS; // 提前多少天续签
    std::wstring preScript;    // 前置脚本
    std::wstring postScript;   // 后置脚本
    // DNS-01 API 自动化（密钥不存续签记录，续签时从主配置读取）
    int dnsProvider = 0;       // DNS提供商 0=手动, 1=阿里云, 2=腾讯云, 3=Cloudflare
    std::wstring dnsApiId;     // [运行时] 从主配置填充，不持久化
    std::wstring dnsApiSecret; // [运行时] 从主配置填充，不持久化
};

// 续签记录持久化
bool LoadRenewalRecords(std::vector<RenewalRecord>& records);
bool SaveRenewalRecords(const std::vector<RenewalRecord>& records);
int FindRenewalByDomain(const std::vector<RenewalRecord>& records, const std::wstring& domain);
void AddOrUpdateRenewal(const RenewalRecord& record);

// 从磁盘证书文件读取实际到期时间
FILETIME ReadCertExpiryFromDisk(const RenewalRecord& rec);

// 续签检查（返回需要续签的记录索引列表）
std::vector<int> GetRenewalsDue(const std::vector<RenewalRecord>& records);

// 执行单个续签（pSkipped=true 表示因 ACME 锁冲突被跳过，不计入重试）
bool PerformRenewal(RenewalRecord& record, bool* pSkipped = nullptr);

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

// 续签并发控制
extern std::set<std::wstring> g_RenewingDomains;

// 证书查询（预留，未实现）
struct CertInfo {
    std::wstring subject;      // 主题
    std::wstring thumbprint;   // 指纹
    std::wstring friendlyName; // 友好名称
    int daysLeft = 0;          // 剩余天数
    FILETIME expiryTime = {};  // 过期时间
    std::wstring source;       // 来源（文件路径或 Store）
    bool inStore = false;      // 是否在 Certificate Store 中
};
// std::vector<CertInfo> ScanAllCertificates(const std::wstring& saveDir);

// DNS-01 API 自动化接口
struct DnsProvider {
    std::wstring name;         // 提供商名称
    int id;                    // 标识符
};
// std::vector<DnsProvider> GetAvailableDnsProviders();  // 预留，未实现

// DNS 提供商常量
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

// 工具增强

// DPAPI 加密/解密字符串
std::string ProtectString(const std::string& clearText);
std::string UnprotectString(const std::string& protectedText);
void EnsureIniUtf8(const wchar_t* iniPath);
void WriteProtectedProfileStringW(const wchar_t* iniPath, const wchar_t* section, const wchar_t* key, const std::wstring& value);
std::wstring GetProtectedProfileStringW(const wchar_t* iniPath, const wchar_t* section, const wchar_t* key, const wchar_t* def);

// DNS 权威服务器预验证（递归查询 NS，直接向权威 DNS 查询 TXT）
bool DnsPreValidateAuthoritative(const std::wstring& queryName, const std::wstring& expectedValue, int maxRetries, int retryInterval);

// SMTP 邮件通知
void SendNotificationEmail(const std::wstring& subject, const std::wstring& body, const std::wstring& saveDir, const std::wstring& iniPath);

// ── 跨模块共享函数声明（原先散落在 .cpp 中用 extern 引用） ──

// 文件原子写入（ssl_utils.cpp）
bool WriteFileAtomic(const std::string& path, const std::string& content);

// HTTP 临时验证服务器（ssl_http.cpp）
bool IsPort80Free();
bool StartTempHttpServer(const std::string& token, const std::string& keyAuth);
void StopTempHttpServer();
std::string DnsHttp(const std::string& url, const std::string& method,
    const std::string& contentType, const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& headers);

// PFX 导出（ssl_deploy.cpp）
bool SavePFX(BCRYPT_KEY_HANDLE dk, const std::string& certPem, const std::wstring& pfxPath);

// HMAC / Hash 辅助（ssl_utils.cpp）
std::vector<BYTE> HmacSha1(const std::string& key, const std::string& data);
std::vector<BYTE> HmacSha256Raw(const std::string& key, const std::string& data);
std::vector<BYTE> HmacSha256Raw(const std::vector<BYTE>& key, const std::string& data);
std::string Sha256Hex(const std::string& data);

// DNS TXT 查询（ssl_dnsapi.cpp）
bool DnsTxtExists(const std::wstring& queryName);

// ── 公共辅助函数（消除 ssl_core.cpp / ssl_renewal.cpp 间的重复代码） ──

// 从 PEM 证书内容解析到期时间（写临时文件 → CertOpenStore → 提取 NotAfter）
FILETIME ParseCertExpiryFromPem(const std::string& certPem);

// 导出私钥为 PEM 字符串（根据 serverType 选择 PKCS#1 或 PKCS#8）
// serverType: 0/1=PKCS#1, 2=PFX(不导出PEM), 3=PKCS#8
std::string ExportPrivateKeyPem(BCRYPT_KEY_HANDLE dk, int serverType);

// DNS TXT 传播检查（权威预验证 + 本地 DnsQuery 回退 + 额外等待）
// 返回 true 表示 DNS 已生效
bool WaitForDnsTxtPropagation(const std::wstring& queryName, const std::wstring& expectedValue,
    const std::string& challengeB64, const wchar_t* logPrefix);

// 将域名转换为安全的文件名（通配符前缀替换 + 非法字符替换 + 长度限制）
std::wstring SanitizeDomainToFileName(const std::wstring& domain);

// 递归创建目录（确保保存目录存在）
bool EnsureDirectoryExists(const std::wstring& path);

// 保存证书文件（私钥 + 证书 + PFX），返回是否全部成功
// outPfxPath: 若 serverType==2 则填充 PFX 路径
bool SaveCertFiles(BCRYPT_KEY_HANDLE dk, const std::string& certPem,
    const std::wstring& saveDir, const std::wstring& nt, int serverType,
    std::wstring* outPfxPath = nullptr, const wchar_t* logPrefix = nullptr);
