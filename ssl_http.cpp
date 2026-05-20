// ssl_http.cpp - HTTP 客户端（WinHTTP 封装、临时服务器、自检）
#include "ssl_core.h"

extern void Log(const wchar_t* fmt, ...);

#ifndef WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3
#define WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 0x00002000
#endif

// ── HTTP 请求 ──
std::string HttpJson(const wchar_t* url, const wchar_t* method, const char* body, int bodyLen,
                     std::string* outNonce, std::string* outLocation, DWORD* outStatusCode) {
    std::string result;
    HINTERNET hSess = WinHttpOpen(L"SSLClaw/1.1 ACME-Client", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSess) { Log(L"[HTTP] WinHttpOpen 失败: %lu", GetLastError()); return result; }
    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    if (!WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
        protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
    }
    URL_COMPONENTSW uc = { sizeof(uc) }; uc.dwSchemeLength = -1; uc.dwHostNameLength = -1;
    uc.dwUrlPathLength = -1; uc.dwExtraInfoLength = -1;
    if (!WinHttpCrackUrl(url, (DWORD)wcslen(url), 0, &uc)) {
        Log(L"[HTTP] WinHttpCrackUrl 失败: %lu", GetLastError());
        WinHttpCloseHandle(hSess);
        return result;
    }
    std::wstring host(uc.lpszHostName ? uc.lpszHostName : L"", uc.dwHostNameLength);
    std::wstring path(uc.lpszUrlPath ? uc.lpszUrlPath : L"", uc.dwUrlPathLength);
    if (uc.dwExtraInfoLength > 0 && uc.lpszExtraInfo) path += std::wstring(uc.lpszExtraInfo, uc.dwExtraInfoLength);
    if (host.empty()) {
        Log(L"[HTTP] 无效的 URL 主机");
        WinHttpCloseHandle(hSess);
        return result;
    }
    HINTERNET hConn = WinHttpConnect(hSess, host.c_str(), uc.nPort, 0);
    if (!hConn) { Log(L"[HTTP] WinHttpConnect(%s) 失败: %lu", host.c_str(), GetLastError()); WinHttpCloseHandle(hSess); return result; }
    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, method, path.c_str(), NULL, NULL, NULL, flags);
    if (!hReq) { Log(L"[HTTP] WinHttpOpenRequest 失败: %lu", GetLastError()); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return result; }
    DWORD features = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS;
    WinHttpSetOption(hReq, WINHTTP_OPTION_DISABLE_FEATURE, &features, sizeof(features));
    BOOL isPost = (wcscmp(method, L"POST") == 0);
    LPCWSTR headers = isPost ? L"Content-Type: application/jose+json\r\n" : WINHTTP_NO_ADDITIONAL_HEADERS;
    if (!WinHttpSendRequest(hReq, headers, isPost ? -1 : 0, (LPVOID)body, bodyLen, bodyLen, 0)) {
        Log(L"[HTTP] WinHttpSendRequest 失败: %lu", GetLastError()); WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return result;
    }
    if (WinHttpReceiveResponse(hReq, NULL)) {
        if (outStatusCode) { DWORD scLen = sizeof(DWORD); WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, outStatusCode, &scLen, NULL); }
        if (outNonce) {
            DWORD nSz = 0;
            if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_CUSTOM, L"Replay-Nonce:", NULL, &nSz, NULL) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                if (nSz > 0) {
                    std::vector<wchar_t> nBuf((nSz / sizeof(wchar_t)) + 2); // 额外空间以防变化
                    DWORD nSz2 = nSz;
                    if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_CUSTOM, L"Replay-Nonce:", nBuf.data(), &nSz2, NULL)) {
                        *outNonce = W2A(nBuf.data());
                    }
                }
            }
        }
        if (outLocation) {
            DWORD rawLen = 0;
            if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, NULL, &rawLen, NULL) || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                if (rawLen > 0) {
                    std::vector<wchar_t> rawBuf((rawLen / sizeof(wchar_t)) + 2); // 额外空间
                    DWORD rawLen2 = rawLen;
                    if (WinHttpQueryHeaders(hReq, WINHTTP_QUERY_RAW_HEADERS_CRLF, NULL, rawBuf.data(), &rawLen2, NULL)) {
                        std::wstring raw(rawBuf.data());
                        size_t p = raw.find(L"Location:");
                        if (p != std::wstring::npos) {
                            p += 9;
                            while (p < raw.size() && (raw[p] == L' ' || raw[p] == L'\r' || raw[p] == L'\n')) p++;
                            if (p < raw.size()) {
                                size_t e = raw.find_first_of(L"\r\n", p);
                                if (e == std::wstring::npos) e = raw.size();
                                *outLocation = W2A(raw.substr(p, e - p));
                            }
                        }
                    }
                }
            }
        }
        DWORD read = 0; char buf[4096] = {};
        while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read > 0) { result.append(buf, read); read = 0; }
    } else { Log(L"[HTTP] WinHttpReceiveResponse 失败: %lu", GetLastError()); }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
    return result;
}

// ── 通用 DNS HTTP 请求（DNS API 用） ──
std::string DnsHttp(const std::string& url, const std::string& method,
    const std::string& contentType, const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& headers) {
    std::wstring wurl = A2W(url);
    bool secure = (wurl.find(L"https://") == 0);
    std::wstring whost, wpathStr;
    int port = secure ? 443 : 80;
    size_t protoEnd = secure ? 8 : 7;
    size_t hostEnd = wurl.find(L"/", protoEnd);
    if (hostEnd == std::wstring::npos) {
        whost = wurl.substr(protoEnd); wpathStr = L"/";
    } else {
        whost = wurl.substr(protoEnd, hostEnd - protoEnd);
        wpathStr = wurl.substr(hostEnd);
    }
    size_t colonPos = whost.find(L":");
    if (colonPos != std::wstring::npos) {
        port = _wtoi(whost.substr(colonPos + 1).c_str());
        whost = whost.substr(0, colonPos);
    }
    HINTERNET hSes = WinHttpOpen(L"SSLClaw/1.1", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSes) return "";
    if (secure) {
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if (!WinHttpSetOption(hSes, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
            protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
            WinHttpSetOption(hSes, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
        }
    }
    HINTERNET hCon = WinHttpConnect(hSes, whost.c_str(), (INTERNET_PORT)port, 0);
    if (!hCon) { WinHttpCloseHandle(hSes); return ""; }
    DWORD reqFlags = secure ? WINHTTP_FLAG_SECURE : 0;
    std::wstring wmethod = A2W(method);
    HINTERNET hReq = WinHttpOpenRequest(hCon, wmethod.c_str(), wpathStr.c_str(), NULL, NULL, NULL, reqFlags);
    if (!hReq) { WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return ""; }
    for (auto& h : headers) { std::wstring hdr = A2W(h.first + ": " + h.second); WinHttpAddRequestHeaders(hReq, hdr.c_str(), (DWORD)hdr.size(), WINHTTP_ADDREQ_FLAG_ADD); }
    if (!contentType.empty()) { std::wstring ctHdr = L"Content-Type: " + A2W(contentType); WinHttpAddRequestHeaders(hReq, ctHdr.c_str(), (DWORD)ctHdr.size(), WINHTTP_ADDREQ_FLAG_ADD); }
    BOOL ok = WinHttpSendRequest(hReq, NULL, 0, body.empty() ? NULL : (void*)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (!ok) { WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes); return ""; }
    ok = WinHttpReceiveResponse(hReq, NULL);
    DWORD avail = 0; std::string resp;
    while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) { std::vector<char> b2(avail + 1); DWORD rd = 0; WinHttpReadData(hReq, (PUCHAR)b2.data(), avail, &rd); if (rd > 0) resp.append(b2.data(), rd); }
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hCon); WinHttpCloseHandle(hSes);
    return resp;
}

// ── 本地 HTTP[S] GET 自检 ──
static bool HttpSelfCheck(const std::wstring& host, const std::wstring& path, std::string& outBody) {
    auto tryCheck = [&](int port, bool secure) -> bool {
        HINTERNET hSess = WinHttpOpen(L"SSLClaw/1.1 ACME-Client", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        if (!hSess) return false;
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
        if (!WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols))) {
            protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2; WinHttpSetOption(hSess, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols)); }
        HINTERNET hConn = WinHttpConnect(hSess, host.c_str(), (INTERNET_PORT)port, 0);
        if (!hConn) { WinHttpCloseHandle(hSess); return false; }
        DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), NULL, NULL, NULL, flags);
        if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return false; }
        bool ok = false;
        if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hReq, NULL)) { DWORD read = 0; char buf[4096] = {}; outBody.clear(); while (WinHttpReadData(hReq, buf, sizeof(buf), &read) && read > 0) { outBody.append(buf, read); read = 0; } ok = true; } }
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); return ok;
    };
    if (tryCheck(80, false)) return true;
    return tryCheck(443, true);
}

// ── 80 端口检测 ──
bool IsPort80Free() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(80);
    bool ok = (bind(s, (sockaddr*)&a, sizeof(a)) == 0);
    closesocket(s); return ok;
}

// ── 临时 HTTP 验证服务器 ──
static volatile bool g_TempHttpRun = false;
static std::string g_TempHttpToken, g_TempHttpKA;
static CRITICAL_SECTION g_TempHttpCs;
static volatile LONG g_TempHttpCsInitialized = 0;

static void InitTempHttpCriticalSection() {
    if (InterlockedCompareExchange(&g_TempHttpCsInitialized, 1, 0) == 0) {
        InitializeCriticalSection(&g_TempHttpCs);
    }
}

static unsigned __stdcall TempHttpServerThread(void*) {
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) return 0;
    sockaddr_in a = {}; a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(80);
    if (bind(ls, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) { closesocket(ls); return 0; }
    if (listen(ls, 5) == SOCKET_ERROR) { closesocket(ls); return 0; }
    g_TempHttpRun = true;
    DWORD tv = 1000; setsockopt(ls, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    
    std::string localToken, localKA;
    EnterCriticalSection(&g_TempHttpCs);
    localToken = g_TempHttpToken;
    localKA = g_TempHttpKA;
    LeaveCriticalSection(&g_TempHttpCs);
    
    while (true) {
        EnterCriticalSection(&g_TempHttpCs);
        bool shouldRun = g_TempHttpRun;
        LeaveCriticalSection(&g_TempHttpCs);
        if (!shouldRun) break;
        sockaddr_in ca = {}; int cl = sizeof(ca);
        SOCKET cs = accept(ls, (sockaddr*)&ca, &cl); if (cs == INVALID_SOCKET) continue;
        // 为客户端 socket 也设置超时，避免永久阻塞
        setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(cs, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
        char buf[4096] = {}; 
        int recvLen = recv(cs, buf, sizeof(buf) - 1, 0);
        if (recvLen > 0) {
            std::string req(buf, recvLen);
            std::string exp = "GET /.well-known/acme-challenge/" + localToken + " ";
            if (req.find(exp) == 0) {
                std::string r = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + std::to_string(localKA.size()) + "\r\nConnection: close\r\n\r\n" + localKA;
                send(cs, r.c_str(), (int)r.size(), 0);
            } else {
                const char* r = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                send(cs, r, (int)strlen(r), 0);
            }
        }
        closesocket(cs);
    }
    closesocket(ls); return 0;
}

// 临时服务器对外访问点
bool StartTempHttpServer(const std::string& token, const std::string& keyAuth) {
    InitTempHttpCriticalSection();
    
    EnterCriticalSection(&g_TempHttpCs);
    g_TempHttpToken = token; 
    g_TempHttpKA = keyAuth; 
    g_TempHttpRun = false;
    LeaveCriticalSection(&g_TempHttpCs);
    
    HANDLE hT = (HANDLE)_beginthreadex(0, 0, TempHttpServerThread, 0, 0, 0);
    if (hT) CloseHandle(hT); 
    Sleep(200); 
    return g_TempHttpRun;
}

void StopTempHttpServer() { 
    EnterCriticalSection(&g_TempHttpCs);
    g_TempHttpRun = false; 
    LeaveCriticalSection(&g_TempHttpCs);
}

extern "C" bool DoHttpSelfCheck(const std::wstring& host, const std::wstring& path, const std::string& expected, std::string& outBody) {
    return HttpSelfCheck(host, path, outBody);
}
