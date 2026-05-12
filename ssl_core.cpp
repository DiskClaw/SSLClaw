// ssl_core.cpp - SSL 证书核心功能实现
#include "ssl_core.h"
#include "ssl_keyfmt.h"

// 链接库（从头文件迁出，避免头文件污染）
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "dnsapi.lib")

// 前向声明（实现在 ssl_ui.cpp）
extern void Log(const wchar_t* fmt, ...);

// 全局状态
BCRYPT_KEY_HANDLE g_AccKey = NULL;
std::string g_AccPubB64, g_AccExpB64;
std::string g_AccURL;
bool g_Running = false;
HANDLE g_hDnsReady = NULL;  // DNS-01 手动继续事件
std::wstring g_WebRoot;
int g_CAIndex = 0;

// 线程同步
CRITICAL_SECTION g_cs;
struct _CsInit { _CsInit() { InitializeCriticalSection(&g_cs); } ~_CsInit() { DeleteCriticalSection(&g_cs); } } _cs_init;

// CA 机构目录 URL（固定 Let's Encrypt）
const wchar_t* GetAcmeDirectory() {
    return L"https://acme-v02.api.letsencrypt.org/directory";
}

// CA 账户密钥文件后缀
const wchar_t* GetAccountKeySuffix() {
    return L"_le";
}

// 若 SDK 未定义 TLS 1.3 标志，手动补充
#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

// 字符串转换
std::string W2A(const std::wstring& w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], len, NULL, NULL);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

std::wstring A2W(const std::string& a) {
    int len = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), -1, NULL, 0);
    std::wstring s(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, a.c_str(), -1, &s[0], len);
    if (!s.empty() && s.back() == L'\0') s.pop_back();
    return s;
}

// Base64 URL
std::string B64Url(const std::vector<BYTE>& d) {
    DWORD len = 0;
    CryptBinaryToStringA(d.data(), (DWORD)d.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
    std::string s(len, 0);
    CryptBinaryToStringA(d.data(), (DWORD)d.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &s[0], &len);
    while (!s.empty() && (s.back() == '\0' || s.back() == '\r' || s.back() == '\n')) s.pop_back();
    for (char& c : s) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    s.erase(std::remove(s.begin(), s.end(), '='), s.end());
    return s;
}

std::string B64UrlS(const std::string& s) {
    return B64Url(std::vector<BYTE>(s.begin(), s.end()));
}

std::string B64Pem(const std::vector<BYTE>& d) {
    DWORD len = 0;
    CryptBinaryToStringA(d.data(), (DWORD)d.size(), CRYPT_STRING_BASE64, NULL, &len);
    std::string s(len, 0);
    CryptBinaryToStringA(d.data(), (DWORD)d.size(), CRYPT_STRING_BASE64, &s[0], &len);
    // 去掉尾部的 \0, \r, \n
    while (!s.empty() && (s.back() == '\0' || s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s;
}

// SHA-256 摘要后 B64Url (DNS-01 TXT 记录值)
std::string Sha256B64(const std::string& data) {
    BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, 0, 0);
    BCRYPT_HASH_HANDLE hh = NULL; (void)BCryptCreateHash(ha, &hh, 0, 0, 0, 0, 0);
    (void)BCryptHashData(hh, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BYTE hash[32]; (void)BCryptFinishHash(hh, hash, 32, 0);
    (void)BCryptDestroyHash(hh); (void)BCryptCloseAlgorithmProvider(ha, 0);
    return B64Url(std::vector<BYTE>(hash, hash + 32));
}

// 本地 HTTP[S] GET 自检（先尝试 HTTP 80，失败则尝试 HTTPS 443）
static bool HttpSelfCheck(const std::wstring& host, const std::wstring& path, std::string& outBody) {
    auto tryCheck = [&](int port, bool secure) -> bool {
        HINTERNET hSess = WinHttpOpen(L"SSLClaw/1.0 ACME-Client", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (!hSess) return false;
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if (!WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
            protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
            WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
        }
        HINTERNET hConn = WinHttpConnect(hSess, host.c_str(), (INTERNET_PORT)port, 0);
        if (!hConn) { WinHttpCloseHandle(hSess); return false; }
        DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), NULL, NULL, NULL, flags);
        if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return false; }
        bool ok = false;
        if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hReq, NULL)) {
                DWORD read = 0; char buf[4096] = {}; outBody.clear();
                while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read > 0) {
                    outBody.append(buf, read); read = 0;
                }
                ok = true;
            }
        }
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return ok;
    };
    // 先试 HTTP 80
    if (tryCheck(80, false)) return true;
    // 再试 HTTPS 443
    return tryCheck(443, true);
}

// 检测本机80端口是否空闲
static bool IsPort80Free() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in a = {}; a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(80);
    bool ok = (bind(s, (sockaddr*)&a, sizeof(a)) == 0);
    closesocket(s); return ok;
}

// 临时HTTP验证服务器（无Web服务器时使用）
static volatile bool g_TempHttpRun = false;
static std::string g_TempHttpToken, g_TempHttpKA;

static unsigned __stdcall TempHttpServerThread(void*) {
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) return 0;
    sockaddr_in a = {}; a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(80);
    if (bind(ls, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) { closesocket(ls); return 0; }
    listen(ls, 5); g_TempHttpRun = true;
    DWORD tv = 1000; setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    while (g_TempHttpRun) {
        sockaddr_in ca = {}; int cl = sizeof(ca);
        SOCKET cs = accept(ls, (sockaddr*)&ca, &cl);
        if (cs == INVALID_SOCKET) continue;
        char buf[4096] = {}; recv(cs, buf, sizeof(buf) - 1, 0);
        std::string req(buf);
        std::string exp = "GET /.well-known/acme-challenge/" + g_TempHttpToken + " ";
        if (req.find(exp) == 0) {
            std::string r = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + std::to_string(g_TempHttpKA.size()) + "\r\nConnection: close\r\n\r\n" + g_TempHttpKA;
            send(cs, r.c_str(), (int)r.size(), 0);
        } else {
            const char* r = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(cs, r, (int)strlen(r), 0);
        }
        closesocket(cs);
    }
    closesocket(ls); return 0;
}

// HTTP 请求
std::string HttpJson(const wchar_t* url, const wchar_t* method, const char* body, int bodyLen,
                     std::string* outNonce, std::string* outLocation, DWORD* outStatusCode) {
    std::string result;
    HINTERNET hSess = WinHttpOpen(L"SSLClaw/1.0 ACME-Client", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSess) {
        Log(L"[HTTP] WinHttpOpen 失败: %lu", GetLastError());
        return result;
    }
    // 启用 TLS 1.2 + TLS 1.3（如系统支持）
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if (!WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
        // TLS 1.3 不支持则回退到仅 TLS 1.2
        protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    }

    URL_COMPONENTSW uc = { sizeof(uc) }; uc.dwSchemeLength = -1; uc.dwHostNameLength = -1;
    uc.dwUrlPathLength = -1; uc.dwExtraInfoLength = -1;
    WinHttpCrackUrl(url, 0, 0, &uc);

    std::wstring host(uc.lpszHostName ? uc.lpszHostName : L"", uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath ? uc.lpszUrlPath : L"", uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength > 0 && uc.lpszExtraInfo) path += std::wstring(uc.lpszExtraInfo, uc.dwExtraInfoLength);

    HINTERNET hConn = WinHttpConnect(hSess, host.c_str(), uc.nPort, 0);
    if (!hConn) {
        Log(L"[HTTP] WinHttpConnect(%s) 失败: %lu", host.c_str(), GetLastError());
        WinHttpCloseHandle(hSess); return result;
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, method, path.c_str(), NULL, NULL, NULL, flags);
    if (!hReq) {
        Log(L"[HTTP] WinHttpOpenRequest 失败: %lu", GetLastError());
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return result;
    }

    DWORD features = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS;
    WinHttpSetOption(hReq, WINHTTP_OPTION_DISABLE_FEATURE, &features, sizeof(features));
    BOOL isPost = (wcscmp(method, L"POST") == 0);
    LPCWSTR headers = isPost ? L"Content-Type: application/jose+json\r\n" : WINHTTP_NO_ADDITIONAL_HEADERS;
    if (!WinHttpSendRequest(hReq, headers, isPost ? -1 : 0, (LPVOID)body, bodyLen, bodyLen, 0)) {
        Log(L"[HTTP] WinHttpSendRequest 失败: %lu", GetLastError());
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        return result;
    }

    if (WinHttpReceiveResponse(hReq, NULL)) {
        if (outStatusCode) {
            DWORD scLen = sizeof(DWORD);
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                NULL, outStatusCode, &scLen, NULL);
        }
        // Nonce: 用 WINHTTP_QUERY_CUSTOM 精确获取
        if (outNonce) {
            DWORD nSz = 0;
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_CUSTOM,
                L"Replay-Nonce:", NULL, &nSz, NULL);
            if (nSz > 0) {
                std::vector<wchar_t> nBuf(nSz / sizeof(wchar_t) + 1);
                if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_CUSTOM,
                    L"Replay-Nonce:", nBuf.data(), &nSz, NULL)) {
                    *outNonce = W2A(nBuf.data());
                }
            }
        }
        // Location: 从 raw headers 提取
        if (outLocation) {
            DWORD rawLen = 0;
            WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, NULL, &rawLen, NULL);
            if (rawLen > 0) {
                std::vector<wchar_t> rawBuf(rawLen / sizeof(wchar_t) + 1);
                if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, rawBuf.data(), &rawLen, NULL)) {
                    std::wstring raw(rawBuf.data());
                    size_t p = raw.find(L"Location:");
                    if (p != std::wstring::npos) {
                        p += 9;
                        while (p < raw.size() && (raw[p] == L' ' || raw[p] == L'\r' || raw[p] == L'\n')) p++;
                        size_t e = raw.find_first_of(L"\r\n", p);
                        if (e == std::wstring::npos) e = raw.size();
                        *outLocation = W2A(raw.substr(p, e - p));
                    }
                }
            }
        }

        DWORD read = 0; char buf[4096] = {};
        while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read > 0) {
            result.append(buf, read); read = 0;
        }
    } else {
        Log(L"[HTTP] WinHttpReceiveResponse 失败: %lu", GetLastError());
    }

    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    return result;
}

// JSON 解析
std::string JsonStr(const std::string& json, const char* key) {
    std::string k = "\"" + std::string(key) + "\"";
    size_t pos = 0;
    while (true) {
        pos = json.find(k, pos);
        if (pos == std::string::npos) return "";
        // 快速检查：key 后面必须是 :，排除 "status" 匹配到 "status_url" 的情况
        if (pos + k.size() >= json.size() || json[pos + k.size()] != ':') {
            pos += k.size();
            continue;
        }
        // 检查 key 不在嵌套结构内部（跨过引号和花括号/方括号）
        int depth = 0; bool inStr = false;
        for (size_t i = 0; i < pos; i++) {
            if (inStr) {
                if (json[i] == '\\') i++;
                else if (json[i] == '"') inStr = false;
            } else if (json[i] == '"') inStr = true;
            else if (json[i] == '{' || json[i] == '[') depth++;
            else if (json[i] == '}' || json[i] == ']') depth--;
        }
        if (depth <= 1 && !inStr) break;
        pos += k.size();
    }
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos = json.find_first_not_of(" \t\r\n", pos + 1);
    if (pos == std::string::npos || json[pos] != '"') return "";
    pos++;
    std::string r;
    for (; pos < json.size(); pos++) {
        if (json[pos] == '\\' && pos + 1 < json.size()) { r += json[pos + 1]; pos++; }
        else if (json[pos] == '"') return r;
        else r += json[pos];
    }
    return "";
}

// 账户密钥
bool ExtractPublicKey() {
    if (!g_AccKey) return false;
    DWORD pl = 0;
    if (BCryptExportKey(g_AccKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, 0, &pl, 0)) return false;
    std::vector<BYTE> pb(pl);
    if (BCryptExportKey(g_AccKey, 0, BCRYPT_RSAPUBLIC_BLOB, pb.data(), pl, &pl, 0)) return false;
    BCRYPT_RSAKEY_BLOB* hd = (BCRYPT_RSAKEY_BLOB*)pb.data();
    BYTE* ep = pb.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    BYTE* md = ep + hd->cbPublicExp;
    g_AccPubB64 = B64Url(std::vector<BYTE>(md, md + hd->cbModulus));
    g_AccExpB64 = B64Url(std::vector<BYTE>(ep, ep + hd->cbPublicExp));
    return true;
}

bool MakeAccountKey() {
    if (g_AccKey) { (void)BCryptDestroyKey(g_AccKey); g_AccKey = NULL; }
    BCRYPT_ALG_HANDLE a = NULL; if (BCryptOpenAlgorithmProvider(&a, BCRYPT_RSA_ALGORITHM, 0, 0)) return false;
    BCRYPT_KEY_HANDLE k = NULL; if (BCryptGenerateKeyPair(a, &k, 2048, 0)) { (void)BCryptCloseAlgorithmProvider(a, 0); return false; }
    if (BCryptFinalizeKeyPair(k, 0)) { (void)BCryptDestroyKey(k); (void)BCryptCloseAlgorithmProvider(a, 0); return false; }
    (void)BCryptCloseAlgorithmProvider(a, 0);
    g_AccKey = k;
    return ExtractPublicKey();
}

bool LoadAccountKey(const std::string& path) {
    // 用宽字符路径打开，支持中文目录
    std::wstring wPath = A2W(path);
    HANDLE hf = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return false;
    DWORD fsz = GetFileSize(hf, NULL);
    std::string pem(fsz, '\0');
    DWORD rd = 0;
    (void)ReadFile(hf, &pem[0], fsz, &rd, NULL);
    CloseHandle(hf);
    pem.resize(rd);
    // 提取 Base64 内容
    size_t s = pem.find("-----BEGIN");
    size_t e = pem.find("-----END");
    if (s == std::string::npos || e == std::string::npos) return false;
    s = pem.find('\n', s); if (s == std::string::npos) s = pem.find('\r', s); if (s == std::string::npos) return false;
    s++;
    std::string b64 = pem.substr(s, e - s);
    DWORD cb = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, NULL, &cb, NULL, NULL)) return false;
    std::vector<BYTE> der(cb);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, der.data(), &cb, NULL, NULL)) return false;
    // NCrypt 导入 PKCS#8
    NCRYPT_PROV_HANDLE hProv = NULL;
    if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0)) return false;
    NCRYPT_KEY_HANDLE hNKey = NULL;
    SECURITY_STATUS ss = NCryptImportKey(hProv, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &hNKey, der.data(), (DWORD)der.size(), 0);
    NCryptFreeObject(hProv);
    if (ss) return false;
    // 导出为 BCRYPT 格式
    DWORD cbBlob = 0;
    SECURITY_STATUS ssExport = NCryptExportKey(hNKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &cbBlob, 0);
    if (ssExport != 0 || cbBlob == 0) {
        NCryptFreeObject(hNKey);
        return false;
    }
    std::vector<BYTE> blob(cbBlob);
    ssExport = NCryptExportKey(hNKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, blob.data(), cbBlob, &cbBlob, 0);
    NCryptFreeObject(hNKey);
    if (ssExport != 0) return false;
    // BCrypt 导入
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0)) { return false; }
    BCRYPT_KEY_HANDLE hBKey = NULL;
    NTSTATUS st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hBKey, blob.data(), (ULONG)blob.size(), 0);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st) return false;
    if (g_AccKey) (void)BCryptDestroyKey(g_AccKey);
    g_AccKey = hBKey;
    return true;
}

std::string MakeJWK() {
    return "{\"e\":\"" + g_AccExpB64 + "\",\"kty\":\"RSA\",\"n\":\"" + g_AccPubB64 + "\"}";
}

std::string AccThumbprint() {
    std::string jwk = MakeJWK();
    BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, 0, 0);
    BCRYPT_HASH_HANDLE hh = NULL; (void)BCryptCreateHash(ha, &hh, 0, 0, 0, 0, 0);
    (void)BCryptHashData(hh, (PUCHAR)jwk.data(), (ULONG)jwk.size(), 0);
    BYTE hash[32]; (void)BCryptFinishHash(hh, hash, 32, 0);
    (void)BCryptDestroyHash(hh); (void)BCryptCloseAlgorithmProvider(ha, 0);
    return B64Url(std::vector<BYTE>(hash, hash + 32));
}

// 原子写入文件：先写 .tmp 再 rename（路径转宽字符，支持中文目录）
static bool WriteFileAtomic(const std::string& path, const std::string& content) {
    std::wstring wPath = A2W(path);
    std::wstring wTmp  = wPath + L".tmp";
    {
        HANDLE h = CreateFileW(wTmp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        WriteFile(h, content.data(), (DWORD)content.size(), &written, NULL);
        CloseHandle(h);
        if (written != (DWORD)content.size()) { _wunlink(wTmp.c_str()); return false; }
    }
    // Windows: MoveFileExW 支持原子重命名（覆盖已有文件）
    if (!MoveFileExW(wTmp.c_str(), wPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        _wunlink(wTmp.c_str());
        return false;
    }
    return true;
}

void SavePKEY(const std::string& path) {
    DWORD pl = 0;
    if (BCryptExportKey(g_AccKey, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, 0, &pl, 0)) {
        Log(L"[错误] 导出账户密钥失败"); return;
    }
    std::vector<BYTE> pk(pl);
    if (BCryptExportKey(g_AccKey, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, pk.data(), pl, &pl, 0)) {
        Log(L"[错误] 导出账户密钥数据失败"); return;
    }
    std::string b = B64Pem(pk);
    std::string pem = "-----BEGIN PRIVATE KEY-----\r\n" + b + "\r\n-----END PRIVATE KEY-----\r\n";
    WriteFileAtomic(path, pem);
}

// PFX 导出（IIS 用）
bool SavePFX(BCRYPT_KEY_HANDLE dk, const std::string& certPem, const std::wstring& pfxPath) {
    auto delKey = [](NCRYPT_PROV_HANDLE hProv, const wchar_t* keyName) {
        if (hProv && keyName) {
            NCRYPT_KEY_HANDLE hDel = 0;
            if (NCryptOpenKey(hProv, &hDel, keyName, 0, 0) == 0) NCryptDeleteKey(hDel, 0);
        }
    };

    // 1. 证书 PEM → DER
    std::string b64;
    for (size_t i = 0; i < certPem.size(); i++) {
        char c = certPem[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')
            b64 += c;
    }
    DWORD derLen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, NULL, &derLen, NULL, NULL)) return false;
    std::vector<BYTE> certDer(derLen);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, certDer.data(), &derLen, NULL, NULL)) return false;

    // 2. 域私钥 → PKCS#8 DER
    DWORD pkLen = 0;
    if (BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, 0, &pkLen, 0)) return false;
    std::vector<BYTE> pkcs8Der(pkLen);
    if (BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkcs8Der.data(), pkLen, &pkLen, 0)) return false;

    // 3. 创建证书上下文
    PCCERT_CONTEXT pCert = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, certDer.data(), derLen);
    if (!pCert) return false;

    // 4. NCrypt 导入私钥并持久化
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS ss = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0);
    if (ss) { CertFreeCertificateContext(pCert); return false; }

    wchar_t keyName[64];
    SYSTEMTIME st; GetSystemTime(&st);
    swprintf_s(keyName, L"SSLClaw_%04d%02d%02d%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    NCryptBuffer ncBuf = {};
    ncBuf.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
    ncBuf.cbBuffer = (ULONG)(wcslen(keyName) + 1) * sizeof(wchar_t);
    ncBuf.pvBuffer = keyName;
    NCryptBufferDesc ncParam = {};
    ncParam.ulVersion = 0;
    ncParam.cBuffers = 1;
    ncParam.pBuffers = &ncBuf;

    NCRYPT_KEY_HANDLE hKey = 0;
    ss = NCryptImportKey(hProv, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &ncParam,
        &hKey, pkcs8Der.data(), (DWORD)pkcs8Der.size(), NCRYPT_OVERWRITE_KEY_FLAG);
    if (ss) { NCryptFreeObject(hProv); CertFreeCertificateContext(pCert); return false; }
    NCryptFreeObject(hKey);

    // 5. 关联私钥到证书
    CRYPT_KEY_PROV_INFO kpi = {};
    kpi.pwszContainerName = keyName;
    kpi.pwszProvName = const_cast<LPWSTR>(MS_KEY_STORAGE_PROVIDER);
    kpi.dwProvType = 0;
    kpi.dwFlags = 0;
    kpi.cProvParam = 0;
    kpi.rgProvParam = NULL;
    kpi.dwKeySpec = AT_KEYEXCHANGE;

    if (!CertSetCertificateContextProperty(pCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)) {
        delKey(hProv, keyName); NCryptFreeObject(hProv); CertFreeCertificateContext(pCert); return false;
    }

    // 6. 创建内存证书存储
    HCERTSTORE hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!hMemStore) { delKey(hProv, keyName); NCryptFreeObject(hProv); CertFreeCertificateContext(pCert); return false; }
    if (!CertAddCertificateContextToStore(hMemStore, pCert, CERT_STORE_ADD_ALWAYS, NULL)) {
        CertCloseStore(hMemStore, 0); delKey(hProv, keyName); NCryptFreeObject(hProv); CertFreeCertificateContext(pCert); return false;
    }

    // 7. PFX 导出
    CRYPT_DATA_BLOB pfxBlob = {};
    wchar_t pwd[] = L"";
    DWORD exportFlags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, pwd, NULL, exportFlags)) {
        CertCloseStore(hMemStore, 0); delKey(hProv, keyName); NCryptFreeObject(hProv); CertFreeCertificateContext(pCert); return false;
    }
    pfxBlob.pbData = (BYTE*)LocalAlloc(LMEM_FIXED, pfxBlob.cbData);
    if (!pfxBlob.pbData) { CertCloseStore(hMemStore, 0); delKey(hProv, keyName); NCryptFreeObject(hProv); CertFreeCertificateContext(pCert); return false; }
    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, pwd, NULL, exportFlags)) {
        LocalFree(pfxBlob.pbData); CertCloseStore(hMemStore, 0); delKey(hProv, keyName); NCryptFreeObject(hProv); CertFreeCertificateContext(pCert); return false;
    }

    // 8. 写入文件
    HANDLE hf = CreateFileW(pfxPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    bool ok = false;
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ok = (WriteFile(hf, pfxBlob.pbData, pfxBlob.cbData, &written, NULL) && written == pfxBlob.cbData);
        CloseHandle(hf);
    }

    // 9. 清理
    LocalFree(pfxBlob.pbData);
    CertCloseStore(hMemStore, 0);
    CertFreeCertificateContext(pCert);
    delKey(hProv, keyName);
    NCryptFreeObject(hProv);
    return ok;
}

// JWS 签名
std::string SignJWS(const std::string& payload, const std::string& nonce, const std::string& url, bool useJWK) {
    std::string prot = "{\"alg\":\"RS256\"";
    if (useJWK) {
        prot += ",\"jwk\":" + MakeJWK();
    }
    else {
        prot += ",\"kid\":\"" + g_AccURL + "\"";
    }
    if (!nonce.empty()) prot += ",\"nonce\":\"" + nonce + "\"";
    prot += ",\"url\":\"" + url + "\"}";

    std::string pb64 = B64UrlS(prot);
    std::string pay64 = B64UrlS(payload);
    std::string toSign = pb64 + "." + pay64;

    BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, 0, 0);
    BCRYPT_HASH_HANDLE hh = NULL;
    (void)BCryptCreateHash(ha, &hh, 0, 0, 0, 0, 0);
    (void)BCryptHashData(hh, (PUCHAR)toSign.data(), (ULONG)toSign.size(), 0);
    BYTE hash[32]; (void)BCryptFinishHash(hh, hash, 32, 0);
    (void)BCryptDestroyHash(hh);
    (void)BCryptCloseAlgorithmProvider(ha, 0);

    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    DWORD sl = 0; (void)BCryptSignHash(g_AccKey, &pi, hash, 32, 0, 0, &sl, BCRYPT_PAD_PKCS1);
    std::vector<BYTE> sig(sl); (void)BCryptSignHash(g_AccKey, &pi, hash, 32, sig.data(), sl, &sl, BCRYPT_PAD_PKCS1);
    std::string sig64 = B64Url(sig);

    return "{\"protected\":\"" + pb64 + "\",\"payload\":\"" + pay64 + "\",\"signature\":\"" + sig64 + "\"}";
}

std::string AcmePost(const std::string& urlStr, const std::string& payload,
                     std::string& nonce, bool useJWK,
                     std::string* outLocation, DWORD* outStatus) {
    std::wstring wurl = A2W(urlStr);
    std::string jws = SignJWS(payload, nonce, urlStr, useJWK);
    std::string newNonce, loc;
    DWORD statusCode = 0;
    std::string result = HttpJson(wurl.c_str(), L"POST", jws.c_str(), (int)jws.size(),
        &newNonce, outLocation ? &loc : NULL, &statusCode);
    if (!newNonce.empty()) nonce = newNonce;
    if (outLocation && !loc.empty()) *outLocation = loc;
    if (outStatus) *outStatus = statusCode;
    // 非 2xx 且非 3xx 响应视为失败
    if (statusCode >= 300 && statusCode < 400) {
        return result;
    }
    if (statusCode >= 400) {
        // 4xx/5xx 保留 body（含错误信息如 badNonce、rateLimited 等）
    }
    return result;
}

// DER 长度编码（ssl_keyfmt.cpp 用 DerLenEncode，此处用 DerLenAppend 区分）
static void DerLenAppend(std::vector<BYTE>& out, size_t len) {
    if (len < 128) out.push_back((BYTE)len);
    else if (len <= 0xFF) { out.push_back(0x81); out.push_back((BYTE)len); }
    else { out.push_back(0x82); out.push_back((BYTE)(len >> 8)); out.push_back((BYTE)(len & 0xFF)); }
}

// CSR 生成
std::vector<BYTE> BuildCSR(const std::string& domain, BCRYPT_KEY_HANDLE key) {
    DWORD pkLen = 0;
    (void)BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &pkLen, 0);
    std::vector<BYTE> pkBlob(pkLen);
    (void)BCryptExportKey(key, NULL, BCRYPT_RSAPUBLIC_BLOB, pkBlob.data(), pkLen, &pkLen, 0);
    BCRYPT_RSAKEY_BLOB* hd = (BCRYPT_RSAKEY_BLOB*)pkBlob.data();
    BYTE* ep = pkBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    BYTE* md = ep + hd->cbPublicExp;

    auto derInt = [](const BYTE* d, DWORD n) {
        std::vector<BYTE> r; r.push_back(0x02);
        bool needZero = (n > 0 && (d[0] & 0x80));
        DerLenAppend(r, (size_t)n + (needZero ? 1 : 0));
        if (needZero) r.push_back(0);
        r.insert(r.end(), d, d + n);
        return r;
    };
    std::vector<BYTE> nDer = derInt(md, hd->cbModulus);
    std::vector<BYTE> eDer = derInt(ep, hd->cbPublicExp);
    std::vector<BYTE> rsaInner; rsaInner.insert(rsaInner.end(), nDer.begin(), nDer.end());
    rsaInner.insert(rsaInner.end(), eDer.begin(), eDer.end());
    std::vector<BYTE> rsaPub; rsaPub.push_back(0x30); DerLenAppend(rsaPub, rsaInner.size());
    rsaPub.insert(rsaPub.end(), rsaInner.begin(), rsaInner.end());

    std::string subjStr = "CN=" + domain;
    CERT_NAME_BLOB subjBlob = { 0 };
    CertStrToNameW(X509_ASN_ENCODING, A2W(subjStr).c_str(), CERT_X500_NAME_STR, NULL, NULL, &subjBlob.cbData, NULL);
    std::vector<BYTE> subjData(subjBlob.cbData);
    CertStrToNameW(X509_ASN_ENCODING, A2W(subjStr).c_str(), CERT_X500_NAME_STR, NULL, subjData.data(), &subjBlob.cbData, NULL);
    subjBlob.pbData = subjData.data();

    CERT_REQUEST_INFO cri = { 0 };
    cri.dwVersion = 0;
    cri.Subject = subjBlob;
    cri.SubjectPublicKeyInfo.Algorithm.pszObjId = szOID_RSA_RSA;
    cri.SubjectPublicKeyInfo.Algorithm.Parameters.cbData = 0;
    cri.SubjectPublicKeyInfo.PublicKey.cbData = (DWORD)rsaPub.size();
    cri.SubjectPublicKeyInfo.PublicKey.pbData = rsaPub.data();
    cri.SubjectPublicKeyInfo.PublicKey.cUnusedBits = 0;

    // 添加 SAN 扩展 (subjectAltName) — 通过 extensionRequest 属性
    std::wstring wdomain = A2W(domain);
    CERT_ALT_NAME_ENTRY sanEntry = { 0 };
    sanEntry.dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    sanEntry.pwszDNSName = (LPWSTR)wdomain.c_str();

    CERT_ALT_NAME_INFO sanInfo = { 0 };
    sanInfo.cAltEntry = 1;
    sanInfo.rgAltEntry = &sanEntry;

    DWORD sanEncodedSize = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                             &sanInfo, 0, NULL, NULL, &sanEncodedSize)) {
        cri.cAttribute = 0;
    } else {
        std::vector<BYTE> sanEncoded(sanEncodedSize);
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                                 &sanInfo, 0, NULL, sanEncoded.data(), &sanEncodedSize)) {
            cri.cAttribute = 0;
        } else {
            // 构造 CERT_EXTENSIONS 结构
            CERT_EXTENSION ext = { 0 };
            ext.pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
            ext.fCritical = FALSE;
            ext.Value.cbData = sanEncodedSize;
            ext.Value.pbData = sanEncoded.data();

            CERT_EXTENSIONS exts = { 0 };
            exts.cExtension = 1;
            exts.rgExtension = &ext;

            // 编码扩展列表为 DER
            DWORD extsEncodedSize = 0;
            if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_EXTENSIONS,
                                     &exts, 0, NULL, NULL, &extsEncodedSize)) {
                cri.cAttribute = 0;
            } else {
                std::vector<BYTE> extsEncoded(extsEncodedSize);
                if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_EXTENSIONS,
                                         &exts, 0, NULL, extsEncoded.data(), &extsEncodedSize)) {
                    cri.cAttribute = 0;
                } else {
                    // 创建 extensionRequest 属性
                    cri.cAttribute = 1;
                    cri.rgAttribute = (decltype(cri.rgAttribute))LocalAlloc(LPTR, sizeof(*cri.rgAttribute));
                    if (cri.rgAttribute) {
                        cri.rgAttribute[0].pszObjId = (LPSTR)szOID_PKCS_9_EXTENSION_REQUEST;
                        cri.rgAttribute[0].cValue = 1;
                        cri.rgAttribute[0].rgValue = (decltype(cri.rgAttribute[0].rgValue))LocalAlloc(LPTR, sizeof(*cri.rgAttribute[0].rgValue));
                        if (cri.rgAttribute[0].rgValue) {
                            cri.rgAttribute[0].rgValue[0].cbData = extsEncodedSize;
                            cri.rgAttribute[0].rgValue[0].pbData = (BYTE*)LocalAlloc(LPTR, extsEncodedSize);
                            if (cri.rgAttribute[0].rgValue[0].pbData) {
                                memcpy(cri.rgAttribute[0].rgValue[0].pbData, extsEncoded.data(), extsEncodedSize);
                            } else {
                                LocalFree(cri.rgAttribute[0].rgValue);
                                LocalFree(cri.rgAttribute);
                                cri.cAttribute = 0;
                            }
                        } else {
                            LocalFree(cri.rgAttribute);
                            cri.cAttribute = 0;
                        }
                    } else {
                        cri.cAttribute = 0;
                    }
                }
            }
        }
    }

    DWORD tbsLen = 0;
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
        &cri, 0, NULL, NULL, &tbsLen);
    std::vector<BYTE> tbsBuf(tbsLen);
    CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
        &cri, 0, NULL, tbsBuf.data(), &tbsLen);

    BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, 0, 0);
    BCRYPT_HASH_HANDLE hh = NULL; (void)BCryptCreateHash(ha, &hh, 0, 0, 0, 0, 0);
    (void)BCryptHashData(hh, (PUCHAR)tbsBuf.data(), (ULONG)tbsLen, 0);
    BYTE hash[32]; (void)BCryptFinishHash(hh, hash, 32, 0);
    (void)BCryptDestroyHash(hh); (void)BCryptCloseAlgorithmProvider(ha, 0);

    BCRYPT_PKCS1_PADDING_INFO pad = { BCRYPT_SHA256_ALGORITHM };
    DWORD sl = 0; (void)BCryptSignHash(key, &pad, hash, 32, 0, 0, &sl, BCRYPT_PAD_PKCS1);
    std::vector<BYTE> sig(sl); (void)BCryptSignHash(key, &pad, hash, 32, sig.data(), sl, &sl, BCRYPT_PAD_PKCS1);

    BYTE algDer[] = { 0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b,0x05,0x00 };
    std::vector<BYTE> bitStr; bitStr.push_back(0x03); DerLenAppend(bitStr, (size_t)sl + 1); bitStr.push_back(0);
    bitStr.insert(bitStr.end(), sig.begin(), sig.end());

    std::vector<BYTE> outer;
    outer.insert(outer.end(), tbsBuf.begin(), tbsBuf.end());
    outer.insert(outer.end(), algDer, algDer + sizeof(algDer));
    outer.insert(outer.end(), bitStr.begin(), bitStr.end());

    std::vector<BYTE> csr; csr.push_back(0x30); DerLenAppend(csr, (size_t)outer.size());
    csr.insert(csr.end(), outer.begin(), outer.end());

    // 清理 SAN 扩展分配的内存
    if (cri.cAttribute > 0 && cri.rgAttribute) {
        for (DWORD i = 0; i < cri.cAttribute; i++) {
            if (cri.rgAttribute[i].rgValue) {
                for (DWORD j = 0; j < cri.rgAttribute[i].cValue; j++) {
                    if (cri.rgAttribute[i].rgValue[j].pbData) {
                        LocalFree(cri.rgAttribute[i].rgValue[j].pbData);
                    }
                }
                LocalFree(cri.rgAttribute[i].rgValue);
            }
        }
        LocalFree(cri.rgAttribute);
    }

    return csr;
}

// ApplyThread 需要外部提供的回调函数
extern void SetStatus(const wchar_t* t);
extern HWND g_hWnd;
extern HWND g_hDomain, g_hEmail, g_hSaveDirEdit, g_hServer, g_hBtnApply, g_hVerifyMode, g_hDaysEdit;
extern HWND g_hWildcard;  // 通配符复选框
extern std::wstring g_SaveDir;
extern std::wstring g_WebRoot;

// 证书申请线程主体
static unsigned ApplyThreadInner() {
    wchar_t td[256]; GetWindowTextW(g_hDomain, td, 256);
    wchar_t* p = td; while (*p == L' ') p++; std::wstring wd = p;
    while (!wd.empty() && wd.back() == L' ') wd.pop_back();
    if (wd.empty()) { SetStatus(L"域名不能为空"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }

    // 获取验证方式（0=HTTP-01, 1=DNS-01）
    int verifyMode = (int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0);

    // 通配符模式：自动在域名前加 *.（若用户未手动加）
    bool isWild = g_hWildcard && (SendMessageW(g_hWildcard, BM_GETCHECK, 0, 0) == BST_CHECKED);
    if (isWild) {
        if (verifyMode == 0) {
            // HTTP-01 不支持通配符证书
            Log(L"[错误] 通配符证书仅支持 DNS-01 验证方式");
            SetStatus(L"通配符需 DNS-01");
            EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        if (wd.size() < 2 || wd[0] != L'*')
            wd = L"*." + wd;
    }

    wchar_t em[256]; GetWindowTextW(g_hEmail, em, 256);
    std::wstring email;
    p = em; while (*p == L' ') p++; email = p;
    while (!email.empty() && email.back() == L' ') email.pop_back();

    wchar_t dtx[MAX_PATH]; GetWindowTextW(g_hSaveDirEdit, dtx, MAX_PATH);
    if (dtx[0]) g_SaveDir = dtx;
    if (g_SaveDir.empty()) { SetStatus(L"保存目录不能为空"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }

    std::wstring nt = wd;
    // 通配符域名文件名：*.example.com → wildcard.example.com
    if (nt.size() >= 2 && nt[0] == L'*' && nt[1] == L'.') nt = L"wildcard." + nt.substr(2);
    for (wchar_t& c : nt) if (c == L'/' || c == L'\\' || c == L':' || c == L'*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|') c = '_';

    int si = (int)SendMessageW(g_hServer, CB_GETCURSEL, 0, 0);
    std::wstring srv; const wchar_t* sn[] = { L"Apache",L"Nginx",L"IIS",L"HAProxy",L"Tomcat",L"Caddy",L"通用" };
    srv = sn[si < 7 ? si : 6];

    std::wstring verifyName = verifyMode == 0 ? L"HTTP-01" : L"DNS-01";

    // CA 机构（仅 Let's Encrypt，索引固定 0）
    g_CAIndex = 0;
    const wchar_t* caName = L"Let's Encrypt";
    EnableWindow(g_hBtnApply, FALSE);
    EnableWindow(g_hDaysEdit, FALSE);
    SetStatus(L"正在申请证书...");
    Log(L"========================================");
    Log(L"  域名: %s", wd.c_str());
    if (!email.empty()) Log(L"  邮箱: %s", email.c_str());
    Log(L"  CA: %s", caName);
    Log(L"  服务器: %s", srv.c_str());
    Log(L"  验证: %s", verifyName.c_str());
    Log(L"  目录: %s", g_SaveDir.c_str());
    Log(L"  文件: %s", nt.c_str());
    Log(L"========================================");

    // Step 1: 加载现有账户密钥或生成新密钥
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
    std::string nonce;
    std::string dir = HttpJson(GetAcmeDirectory(), L"GET", NULL, 0, &nonce);
    std::string newAcct = JsonStr(dir, "newAccount");
    std::string newOrder = JsonStr(dir, "newOrder");
    if (dir.empty()) {
        Log(L"[错误] 无法连接 ACME 服务器"); SetStatus(L"失败");
        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
    }
    if (newAcct.empty() || newOrder.empty()) {
        Log(L"[错误] 无法解析 ACME 目录响应"); SetStatus(L"失败");
        Log(L"  原始响应: %s", A2W(dir.substr(0, 300)).c_str());
        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
    }
    auto getNonce = [&]() {
        nonce.clear();
        std::string nu = JsonStr(dir, "newNonce");
        if (nu.empty()) return 0;
        std::wstring wnu = A2W(nu);
        HttpJson(wnu.c_str(), L"HEAD", NULL, 0, &nonce);
        Log(L"  获取 Nonce: %s", A2W(nonce.substr(0, 32)).c_str());
        return 0;
    };
    getNonce();

    // Step 3: 注册 ACME 账户
    SetStatus(L"注册 ACME 帐户...");
    Log(L"Step 3: 注册帐户...");
    {
        std::string regBody = "{\"termsOfServiceAgreed\":true";
        if (!email.empty()) regBody += ",\"contact\":[\"mailto:" + W2A(email) + "\"]";
        regBody += "}";
        std::string loc;
        DWORD regHttp = 0;
        std::string regResp;
        bool regOK = false;
        for (int retry = 0; retry < 10; retry++) {
            if (nonce.empty()) getNonce();
            if (nonce.empty()) { Log(L"[错误] 无法获取 Nonce"); break; }
            regResp = AcmePost(newAcct, regBody, nonce, true, &loc, &regHttp);
            if (!loc.empty()) { regOK = true; break; }
            if (regResp.find("badNonce") != std::string::npos ||
                regResp.find("invalid anti-replay") != std::string::npos) {
                Log(L"  badNonce, 重试 %d/10...", retry + 1);
                nonce.clear();
                getNonce(); // 直接获取新 nonce
                Sleep(1000);
                continue;
            }
            break;
        }
        if (!regOK) {
            Log(L"[错误] 帐户注册失败 (HTTP %d)", regHttp);
            Log(L"  响应: %s", A2W(regResp.substr(0, 500)).c_str()); SetStatus(L"失败");
            EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        g_AccURL = loc;
        std::string regStatus = JsonStr(regResp, "status");
        Log(L"  帐户状态: %s", A2W(regStatus.empty() ? std::string("已存在") : regStatus).c_str());
    }

    // Step 4: 创建订单
    SetStatus(L"创建订单...");
    Log(L"Step 4: 创建订单...");
    {
        std::string domainA = W2A(wd);
        std::string ordBody = "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"" + domainA + "\"}]}";
        std::string orderUrl;
        DWORD orderHttpCode = 0;
        std::string order = AcmePost(newOrder, ordBody, nonce, false, &orderUrl, &orderHttpCode);
        // badNonce 重试（最多2次）
        int retries = 0;
        while (orderHttpCode == 400 && order.find("badNonce") != std::string::npos && retries < 2) {
            retries++;
            Log(L"  重试订单请求 (badNonce, 第%d次)...", retries);
            orderUrl.clear();
            order = AcmePost(newOrder, ordBody, nonce, false, &orderUrl, &orderHttpCode);
        }
        if (order.empty()) {
            Log(L"[错误] 订单创建失败 (HTTP %d)", orderHttpCode);
            if (orderHttpCode == 429) Log(L"  速率限制: 每周最多签发 50 张证书"); SetStatus(L"失败");
            EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        if (orderUrl.empty()) {
            Log(L"[警告] 未收到订单 Location 头，尝试从订单 JSON 解析");
            orderUrl = JsonStr(order, "location");
        }
        if (orderUrl.empty()) {
            Log(L"[错误] 无法获取订单 URL (HTTP %d)", orderHttpCode);
            Log(L"  响应: %s", A2W(order.substr(0, 200)).c_str()); SetStatus(L"失败");
            EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }
        std::string orderStatus = JsonStr(order, "status");
        Log(L"  订单状态: %s", A2W(orderStatus).c_str());

        std::string authzUrl = "", finalizeUrl = JsonStr(order, "finalize");
        bool skipChallenge = false;

        if (orderStatus == "ready") {
            Log(L"  域名已验证，跳过挑战");
            skipChallenge = true;
        }
        else {
            size_t aPos = order.find("\"authorizations\"");
            if (aPos == std::string::npos || (aPos = order.find("[", aPos)) == std::string::npos ||
                (aPos = order.find("\"", aPos)) == std::string::npos) {
                Log(L"[错误] 无法解析授权列表"); SetStatus(L"失败");
                EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            aPos++;
            size_t aEnd = order.find("\"", aPos);
            authzUrl = order.substr(aPos, aEnd - aPos);
        }

        bool verified = false;
        if (!skipChallenge) {
            // Step 5: 获取域名授权
            SetStatus(L"获取授权...");
            Log(L"Step 5: 获取域名授权...");
            std::string authz = AcmePost(authzUrl, "", nonce, false);
            if (authz.empty()) {
                Log(L"[错误] 授权获取失败"); SetStatus(L"失败");
                EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }

            std::string challUrl;
            std::string token;
            std::string keyAuth;
            std::wstring challFile;
            bool useTempServer = false;
            // DNS-01 用 baseDomain（通配符需去掉 *. 前缀）
            std::wstring baseDomain = wd;
            if (isWild && baseDomain.size() >= 2 && baseDomain[0] == L'*' && baseDomain[1] == L'.')
                baseDomain = baseDomain.substr(2);

            if (verifyMode == 0) {
                // HTTP-01 验证
                size_t cPos = authz.find("\"http-01\"");
                if (cPos == std::string::npos) {
                    Log(L"[错误] 未找到 HTTP-01 挑战"); SetStatus(L"失败");
                    EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                }
                cPos = authz.find("\"url\"", cPos);
                if (cPos == std::string::npos) { Log(L"[错误] 挑战无 url"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
                cPos = authz.find(":", cPos);
                cPos = authz.find("\"", cPos) + 1;
                size_t cEnd = authz.find("\"", cPos);
                challUrl = authz.substr(cPos, cEnd - cPos);
                // 从当前挑战对象中提取 token
                size_t tPos = authz.find("\"token\"", cPos);
                if (tPos == std::string::npos) {
                    Log(L"[错误] 挑战无 token"); SetStatus(L"失败");
                    EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                }
                tPos = authz.find(":", tPos);
                tPos = authz.find("\"", tPos) + 1;
                size_t tEnd = authz.find("\"", tPos);
                token = authz.substr(tPos, tEnd - tPos);
                keyAuth = token + "." + AccThumbprint();

                bool port80Free = IsPort80Free();
                if (port80Free) {
                    SetStatus(L"启动验证服务器...");
                    Log(L"Step 6: 80 端口空闲，启动临时验证服务器...");
                    g_TempHttpToken = token;
                    g_TempHttpKA = keyAuth;
                    g_TempHttpRun = false;
                    HANDLE hT = (HANDLE)_beginthreadex(0, 0, TempHttpServerThread, 0, 0, 0);
                    if (hT) CloseHandle(hT);
                    Sleep(200);
                    if (!g_TempHttpRun) {
                        Log(L"[错误] 临时验证服务器启动失败"); SetStatus(L"失败");
                        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                    }
                    useTempServer = true;
                    Log(L"  临时验证服务器已启动（监听80端口）");
                    Log(L"  域名 %s 的 A 记录需指向本机", wd.c_str());
                } else {
                    SetStatus(L"写入验证文件...");
                    Log(L"Step 6: Web 服务器运行中，写入验证文件...");
                    if (g_WebRoot.empty()) {
                        Log(L"[错误] 需填写网站目录"); SetStatus(L"失败");
                        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                    }
                    std::wstring challDir = g_WebRoot + L"\\.well-known\\acme-challenge";
                    challFile = challDir + L"\\" + A2W(token);
                    CreateDirectoryW((g_WebRoot + L"\\.well-known").c_str(), NULL);
                    if (!CreateDirectoryW(challDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                        Log(L"[错误] 无法创建目录 %s", challDir.c_str());
                        SetStatus(L"目录创建失败");
                        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                    }
                    {
                        HANDLE hcf = CreateFileW(challFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                                  FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hcf == INVALID_HANDLE_VALUE) {
                            Log(L"[错误] 无法写入验证文件 %s", challFile.c_str());
                            SetStatus(L"写入失败");
                            EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                        }
                        DWORD written2 = 0;
                        WriteFile(hcf, keyAuth.data(), (DWORD)keyAuth.size(), &written2, NULL);
                        CloseHandle(hcf);
                    }
                    Log(L"  已写入: .well-known/acme-challenge/%s", A2W(token).c_str());

                    // Step 6.5: 自检
                    SetStatus(L"自检验证文件...");
                    Log(L"Step 6.5: 自检...");
                    {
                        std::string body;
                        std::wstring chkPath = L"/.well-known/acme-challenge/" + A2W(token);
                        if (!HttpSelfCheck(wd, chkPath, body)) {
                            Log(L"[警告] 本地自检失败，Web 服务器可能无法访问验证文件");
                            Log(L"  检查: Web 服务器是否运行、.well-known 路径是否可访问");
                        }
                        else if (body != keyAuth) {
                            Log(L"[警告] 验证文件内容不匹配（期望 %s，实际 %s）",
                                A2W(keyAuth.substr(0, 32)).c_str(),
                                A2W(body.substr(0, 32)).c_str());
                            Log(L"  可能原因: Web 服务器返回了缓存或错误页面");
                        }
                        else {
                            Log(L"  本地自检通过");
                        }
                    }
                    Log(L"  域名 A 记录需指向本机");
                }
            }
            else {
                // DNS-01 验证
                size_t cPos = authz.find("\"dns-01\"");
                if (cPos == std::string::npos) {
                    Log(L"[错误] 未找到 DNS-01 挑战"); SetStatus(L"失败");
                    EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                }
                cPos = authz.find("\"url\"", cPos);
                if (cPos == std::string::npos) { Log(L"[错误] 挑战无 url"); SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0; }
                cPos = authz.find(":", cPos);
                cPos = authz.find("\"", cPos) + 1;
                size_t cEnd = authz.find("\"", cPos);
                challUrl = authz.substr(cPos, cEnd - cPos);
                // 从当前挑战对象中提取 token
                size_t tPos = authz.find("\"token\"", cPos);
                if (tPos == std::string::npos) {
                    Log(L"[错误] 挑战无 token"); SetStatus(L"失败");
                    EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
                }
                tPos = authz.find(":", tPos);
                tPos = authz.find("\"", tPos) + 1;
                size_t tEnd = authz.find("\"", tPos);
                token = authz.substr(tPos, tEnd - tPos);
                keyAuth = token + "." + AccThumbprint();

                // Step 6: DNS-01 验证
                SetStatus(L"请添加 TXT 记录...");
                Log(L"Step 6: DNS-01 验证");
                Log(L"");
                Log(L"========================================");
                Log(L"DNS-01 验证步骤：");
                Log(L"  1. 登录域名 DNS 管理后台");
                Log(L"  2. 添加以下 TXT 记录：");
                Log(L"");
                Log(L"     主机记录: _acme-challenge");
                Log(L"     记录类型: TXT");
                Log(L"     记录值: %s", A2W(Sha256B64(keyAuth)).c_str());
                if (isWild) {
                    Log(L"     完整名称: _acme-challenge.%s", baseDomain.c_str());
                }
                Log(L"");
                Log(L"  3. 等待 DNS 记录生效（通常需数分钟）");
                Log(L"  4. 点击「继续验证」按钮");
                Log(L"");
                if (isWild) {
                    Log(L"  通配符: TXT 记录添加在根域名 %s 下（非 *.%s）", baseDomain.c_str(), baseDomain.c_str());
                }
                Log(L"  记录值区分大小写，完整复制");
                Log(L"========================================");
                Log(L"");

                {
                    if (g_hDnsReady) CloseHandle(g_hDnsReady);
                    g_hDnsReady = CreateEventW(NULL, TRUE, FALSE, NULL);
                    EnableWindow(g_hBtnApply, TRUE);
                    SetWindowTextW(g_hBtnApply, L"继续验证");
                    SetStatus(L"请添加 TXT 记录后点击「继续验证」");
                    Log(L"  请添加 TXT 记录后点击「继续验证」按钮...");
                    // 等待用户点击或取消
                    while (WaitForSingleObject(g_hDnsReady, 500) != WAIT_OBJECT_0) {
                        if (!g_Running) {
                            CloseHandle(g_hDnsReady); g_hDnsReady = NULL;
                            EnableWindow(g_hBtnApply, TRUE);
                            SetWindowTextW(g_hBtnApply, L"申请证书");
                            return 0;
                        }
                    }
                    CloseHandle(g_hDnsReady); g_hDnsReady = NULL;
                    EnableWindow(g_hBtnApply, FALSE);
                    SetWindowTextW(g_hBtnApply, L"申请证书");

                    // DNS 传播自检
                    std::wstring queryName = L"_acme-challenge." + baseDomain;
                    std::string expectedValue = Sha256B64(keyAuth);
                    SetStatus(L"检查 DNS 传播...");
                    PDNS_RECORD dr = NULL;
                    DNS_STATUS ds = DnsQuery_W(queryName.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &dr, NULL);
                    bool dnsFound = false;
                    if (ds == 0 && dr) {
                        for (PDNS_RECORD p = dr; p; p = p->pNext) {
                            if (p->wType == DNS_TYPE_TEXT && p->Data.Txt.dwStringCount > 0) {
                                std::string txtVal = p->Data.Txt.pStringArray[0];
                                if (txtVal == expectedValue) {
                                    dnsFound = true;
                                    Log(L"  DNS 自检通过: TXT 记录已生效");
                                    break;
                                }
                            }
                        }
                        DnsRecordListFree(dr, DnsFreeRecordList);
                    }
                    if (!dnsFound) {
                        Log(L"  [警告] DNS 自检未通过，额外等待 30 秒...");
                        for (int ew = 30; ew > 0; ew -= 5) {
                            Sleep(5000);
                            if (!g_Running) return 0;
                        }
                    }
                }
            }

            // Step 7: 通知 ACME 服务器进行验证
            SetStatus(L"验证域名...");
            Log(L"Step 7: 请求 ACME 验证...");
            AcmePost(challUrl, "{}", nonce, false);
            Log(L"  已通知验证");

            // Step 8: 轮询验证结果
            Log(L"Step 8: 轮询验证结果...");
            std::string authStatus;
            for (int i = 0; i < (verifyMode == 0 ? 15 : 90); i++) {
                Sleep(2000);
                std::string check = AcmePost(authzUrl, "", nonce, false);
                authStatus = JsonStr(check, "status");
                if (authStatus == "valid") { verified = true; break; }
                if (authStatus == "invalid") break;
                Log(L"  等待... (%d/%d)", i + 1, verifyMode == 0 ? 15 : 90);
            }
            if (!verified) {
                // 清理
                if (useTempServer) {
                    g_TempHttpRun = false;
                    Log(L"  临时验证服务器已关闭");
                } else if (verifyMode == 0 && !challFile.empty()) {
                    DeleteFileW(challFile.c_str());
                    Log(L"  已删除验证文件");
                }
                Log(L"");
                if (verifyMode == 0) {
                    Log(L"[错误] 域名验证失败");
                    Log(L"  原因: %s 无法通过 HTTP-01 验证域名所有权", caName);
                    Log(L"  解决方法:");
                    Log(L"    1. 在域名 DNS 管理后台将 %s 的 A 记录指向本机公网 IP", wd.c_str());
                    Log(L"    2. 确认网站根目录的 .well-known/acme-challenge/ 可被公网访问");
                    Log(L"    3. 检查 Web 服务器（IIS/Nginx/Apache）配置是否有重写规则拦截了该路径");
                } else {
                    Log(L"[错误] DNS 验证失败");
                    Log(L"  可能原因:");
                    Log(L"    1. TXT 记录尚未生效（DNS 传播需要时间）");
                    Log(L"    2. 记录值填写错误");
                    Log(L"    3. 主机记录填写错误（应为 _acme-challenge）");
                    Log(L"  验证方法: 命令行执行 nslookup -type=TXT _acme-challenge.%s", baseDomain.c_str());
                }
                Log(L"  速率限制: 每小时最多验证失败 5 次，每周最多签发 50 张");
                SetStatus(L"验证失败");
                EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            Log(L"  验证通过");
            if (useTempServer) g_TempHttpRun = false;
            else if (verifyMode == 0 && !challFile.empty()) _wunlink(challFile.c_str());
        }
        else {
            verified = true;
        }

        // Step 9: 生成域密钥和 CSR
        SetStatus(L"生成域密钥和 CSR...");
        Log(L"Step 9: 生成域密钥和 CSR...");
        BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_RSA_ALGORITHM, 0, 0);
        BCRYPT_KEY_HANDLE dk = NULL; (void)BCryptGenerateKeyPair(ha, &dk, 2048, 0);
        (void)BCryptFinalizeKeyPair(dk, 0); (void)BCryptCloseAlgorithmProvider(ha, 0);

        std::vector<BYTE> csrDer = BuildCSR(domainA, dk);
        std::string csrB64 = B64Url(csrDer);
        Log(L"  CSR %d 字节", (int)csrDer.size());

        // Step 10: 提交 CSR 完成订单
        SetStatus(L"正在签发证书...");
        Log(L"Step 10: 提交 CSR 申请签发...");
        std::string finBody = "{\"csr\":\"" + csrB64 + "\"}";
        std::string finResp = AcmePost(finalizeUrl, finBody, nonce, false);
        if (finResp.empty()) {
            Log(L"[错误] 订单完成失败");
            Log(L"  ⚠ 速率限制: 同一域名每周最多签发 50 张证书，相同域名组合每周 5 张");
            (void)BCryptDestroyKey(dk);
            SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }

        // Step 11: 等待证书生成并获取下载链接
        SetStatus(L"正在下载证书...");
        Log(L"Step 11: 等待服务器打包证书...");
        std::string certUrl;
        for (int i = 0; i < 10; i++) {
            Sleep(2000);
            std::string check = AcmePost(orderUrl, "", nonce, false);
            std::string orderCheckStatus = JsonStr(check, "status");
            if (orderCheckStatus == "invalid") {
                Log(L"[错误] 订单状态无效，证书签发失败");
                Log(L"  ⚠ 速率限制: 同一域名每周最多签发 50 张证书，相同域名组合每周 5 张");
                (void)BCryptDestroyKey(dk);
                SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
            }
            certUrl = JsonStr(check, "certificate");
            if (!certUrl.empty()) break;
            Log(L"  等待... (%d/10)", i + 1);
        }
        if (certUrl.empty()) {
            Log(L"[错误] 获取证书下载链接超时"); (void)BCryptDestroyKey(dk);
            SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }

        // Step 12: 下载并保存证书+私钥
        Log(L"Step 12: 下载证书链...");
        std::string certPem = AcmePost(certUrl, "", nonce, false);
        if (certPem.empty()) {
            Log(L"[错误] 证书下载失败"); (void)BCryptDestroyKey(dk);
            SetStatus(L"失败"); EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE); g_Running = false; return 0;
        }

        // 保存域私钥和证书（下载成功后才写盘，避免残留文件）
        // 私钥格式：Apache/Nginx/IIS/Tomcat → PKCS#1（最兼容），HAProxy/Caddy/通用 → PKCS#8
        bool needPkcs1 = (si == 0 || si == 1 || si == 2 || si == 4);
        {
            std::string keyPath = W2A(g_SaveDir + L"\\" + nt + L".key");
            std::string pem;
            NTSTATUS status = 0;

            if (needPkcs1) {
                // PKCS#1 路径：优先 BCRYPT_RSAFULLPRIVATE_BLOB → CryptEncodeObjectEx 直接出 PKCS#1
                DWORD fl = 0;
                status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, 0, 0, &fl, 0);
                if (status == 0 && fl > 0) {
                    std::vector<BYTE> fb(fl);
                    status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, fb.data(), fl, &fl, 0);
                    if (status == 0) {
                        pem = RsaFullBlobToPkcs1Pem(fb);
                    }
                }
                // 备选：PKCS#8 导出后转换
                if (pem.empty()) {
                    DWORD pl = 0;
                    status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, 0, &pl, 0);
                    if (status == 0 && pl > 0) {
                        std::vector<BYTE> pkv(pl);
                        status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkv.data(), pl, &pl, 0);
                        if (status == 0) {
                            std::string bp = B64Pem(pkv);
                            std::string pkcs8 = "-----BEGIN PRIVATE KEY-----\r\n" + bp + "\r\n-----END PRIVATE KEY-----\r\n";
                            pem = Pkcs8PemToPkcs1Pem(pkcs8);
                        }
                    }
                }
            } else {
                // PKCS#8 路径：优先 BCrypt 原生导出，失败则 BCRYPT_RSAFULLPRIVATE_BLOB 手动构造
                DWORD pl = 0;
                status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, 0, &pl, 0);
                if (status == 0 && pl > 0) {
                    std::vector<BYTE> pkv(pl);
                    status = BCryptExportKey(dk, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkv.data(), pl, &pl, 0);
                    if (status == 0) {
                        std::string bp = B64Pem(pkv);
                        pem = "-----BEGIN PRIVATE KEY-----\r\n" + bp + "\r\n-----END PRIVATE KEY-----\r\n";
                    }
                }
                if (pem.empty()) {
                    DWORD fl = 0;
                    status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, 0, 0, &fl, 0);
                    if (status == 0 && fl > 0) {
                        std::vector<BYTE> fb(fl);
                        status = BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, fb.data(), fl, &fl, 0);
                        if (status == 0) {
                            pem = RsaFullBlobToPkcs8Pem(fb);
                        }
                    }
                }
            }

            if (pem.empty()) {
                Log(L"[错误] 私钥导出失败 (0x%08X)", status);
            } else if (WriteFileAtomic(keyPath, pem)) {
                const wchar_t* fmt = needPkcs1 ? L"  私钥已保存: %s.key (PKCS#1)" : L"  私钥已保存: %s.key (PKCS#8)";
                Log(fmt, nt.c_str());
            } else {
                Log(L"[警告] 私钥保存失败: %s.key", nt.c_str());
            }
        }
        {
            std::string certPath = W2A(g_SaveDir + L"\\" + nt + L".crt");
            if (WriteFileAtomic(certPath, certPem))
                Log(L"  公钥证书已保存: %s.crt", nt.c_str());
            else
                Log(L"[警告] 公钥证书保存失败: %s.crt", nt.c_str());
        }

        // IIS: 额外导出 .pfx 文件
        if (si == 2) {
            std::wstring pfxPath = g_SaveDir + L"\\" + nt + L".pfx";
            if (SavePFX(dk, certPem, pfxPath))
                Log(L"  IIS 证书已保存: %s.pfx", nt.c_str());
            else
                Log(L"[警告] PFX 导出失败，IIS 用户可手动转换");
        }

        if (si == 2) {
            Log(L"  提示: IIS 请导入 .pfx 文件到服务器证书，.key/.crt 为备用格式");
        } else {
            Log(L"  提示: .key 为私钥文件，.crt 为证书文件，配置 SSL 时两个文件均需使用");
        }
        if (g_TempHttpRun) {
            Log(L"  提示: 关闭本程序后再启动 Web 服务器（本程序占用 80 端口）");
        }

        (void)BCryptDestroyKey(dk);
    }

    SetStatus(L"完成 - 证书已获取");
    SetWindowTextW(g_hBtnApply, L"申请证书");
    EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE);
    g_Running = false;
    return 0;
}

// 证书申请线程（SEH 保护）
unsigned __stdcall ApplyThread(void*) {
    EnterCriticalSection(&g_cs);
    if (g_Running) { LeaveCriticalSection(&g_cs); return 0; }
    g_Running = true;
    LeaveCriticalSection(&g_cs);

    __try {
        ApplyThreadInner();
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        Log(L"[致命错误] 证书申请线程异常终止");
        SetStatus(L"失败 - 异常");
    }

    if (g_Running) {
        EnableWindow(g_hBtnApply, TRUE); EnableWindow(g_hDaysEdit, TRUE);
        SetWindowTextW(g_hBtnApply, L"申请证书");
        if (g_hDnsReady) { CloseHandle(g_hDnsReady); g_hDnsReady = NULL; }
        g_Running = false;
    }
    return 0;
}
