// ssl_dnsapi.cpp - DNS 提供商 API（阿里云、腾讯云、Cloudflare）
#include "ssl_core.h"

extern void Log(const wchar_t* fmt, ...);
extern std::string DnsHttp(const std::string& url, const std::string& method,
    const std::string& contentType, const std::string& body,
    const std::vector<std::pair<std::string, std::string>>& headers);
extern std::vector<BYTE> HmacSha1(const std::string& key, const std::string& data);
extern std::vector<BYTE> HmacSha256Raw(const std::string& key, const std::string& data);
extern std::vector<BYTE> HmacSha256Raw(const std::vector<BYTE>& key, const std::string& data);
extern std::string Sha256Hex(const std::string& data);
extern std::string Sha256B64(const std::string& data);
extern std::string JsonStr(const std::string& json, const char* key);
extern std::string W2A(const std::wstring& w);
extern std::wstring A2W(const std::string& a);

// ── 通用 DNS TXT 验证 ──
bool DnsTxtExists(const std::wstring& queryName) {
    PDNS_RECORD pDns = NULL;
    DNS_STATUS st = DnsQuery_W(queryName.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pDns, NULL);
    bool exists = (st == ERROR_SUCCESS && pDns != NULL);
    if (pDns) DnsRecordListFree(pDns, DnsFreeRecordList);
    return exists;
}

// ── 阿里云 DNS API ──
static std::string AliyunDnsApi(const std::string& action, const std::string& akId, const std::string& akSecret,
    const std::vector<std::pair<std::string, std::string>>& params) {
    std::string ts; char buf[64]; SYSTEMTIME st; GetSystemTime(&st);
    sprintf_s(buf, "%04d-%02d-%02dT%02d:%02d:%02dZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    ts = buf;
    std::string nonce; { BYTE r[8]; BCryptGenRandom(NULL, r, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        for (int i = 0; i < 8; i++) { char b[3]; sprintf_s(b, "%02X", r[i]); nonce += b; } }

    std::vector<std::pair<std::string, std::string>> p;
    p.push_back({"Action", action});
    p.push_back({"AccessKeyId", akId});
    p.push_back({"Format", "JSON"});
    p.push_back({"RegionId", "cn-hangzhou"});
    p.push_back({"SignatureMethod", "HMAC-SHA1"});
    p.push_back({"SignatureNonce", nonce});
    p.push_back({"SignatureVersion", "1.0"});
    p.push_back({"Timestamp", ts});
    p.push_back({"Version", "2015-01-09"});
    for (auto& kv : params) p.push_back(kv);
    std::sort(p.begin(), p.end());

    std::string qs, toSign = "GET&%2F&";
    for (size_t i = 0; i < p.size(); i++) {
        std::string k = p[i].first, v = p[i].second;
        std::string enc; char eb[4];
        for (char c : k) { if (isalnum((unsigned char)c) || c=='-'||c=='_'||c=='.'||c=='~') enc+=c; else { sprintf_s(eb,"%%%02X",(unsigned char)c); enc+=eb; } }
        std::string ev; for (char c : v) { if (isalnum((unsigned char)c)||c=='-'||c=='_'||c=='.'||c=='~') ev+=c; else { sprintf_s(eb,"%%%02X",(unsigned char)c); ev+=eb; } }
        qs += enc + "=" + ev + "&";
        // toSign: 对已编码的值再做一次编码(% → %25)
        std::string ev2; for (char c : ev) { if (c == '%') ev2 += "%25"; else ev2 += c; }
        std::string enc2; for (char c : enc) { if (c == '%') enc2 += "%25"; else enc2 += c; }
        if (i > 0) toSign += "%26"; toSign += enc2 + "%3D" + ev2;
    }
    if (!qs.empty()) qs.pop_back();

    std::vector<BYTE> mac = HmacSha1(akSecret + "&", toSign);
    DWORD sl = 0; CryptBinaryToStringA(mac.data(), (DWORD)mac.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sl);
    std::string sb64; sb64.resize(sl); CryptBinaryToStringA(mac.data(), (DWORD)mac.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &sb64[0], &sl);
    while (!sb64.empty() && (sb64.back() == '\0' || sb64.back() == '\r' || sb64.back() == '\n')) sb64.pop_back();

    // URL-encode the Base64 signature (+ / = must be encoded)
    std::string sigEnc; char seb[4];
    for (char c : sb64) {
        if (isalnum((unsigned char)c) || c=='-'||c=='_'||c=='.'||c=='~') sigEnc+=c;
        else { sprintf_s(seb,"%%%02X",(unsigned char)c); sigEnc+=seb; }
    }
    std::string url = "https://dns.aliyuncs.com/?" + qs + "&Signature=" + sigEnc;
    return DnsHttp(url, "GET", "", "", {});
}

// ── 腾讯云 DNS API ──
static std::string TencentDnsApi(const std::string& action, const std::string& secretId, const std::string& secretKey,
    const std::vector<std::pair<std::string, std::string>>& params) {
    std::string host = "dnspod.tencentcloudapi.com", service = "dnspod", ver = "2021-03-23";
    // 使用单一时间源，避免两次 _time64 不一致
    __time64_t tNow; _time64(&tNow);
    char tsBuf[16]; sprintf_s(tsBuf, "%lld", tNow); std::string ts = tsBuf;
    // UTC 日期 YYYY-MM-DD
    struct tm tmUtc; gmtime_s(&tmUtc, &tNow);
    char dateBuf[16]; sprintf_s(dateBuf, "%04d-%02d-%02d", tmUtc.tm_year+1900, tmUtc.tm_mon+1, tmUtc.tm_mday);
    std::string date = dateBuf;
    // Payload
    std::string payload;
    {
        std::string jp;
        for (size_t i = 0; i < params.size(); i++) { if (i > 0) jp += ","; jp += "\"" + params[i].first + "\":\"" + params[i].second + "\""; }
        payload = "{" + jp + "}";
    }
    std::string sh = Sha256Hex(payload);
    // CanonicalRequest
    std::string csr = "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:" + host + "\n\ncontent-type;host\n" + sh;
    // StringToSign
    std::string credentialScope = date + "/" + service + "/tc3_request";
    std::string sts = "TC3-HMAC-SHA256\n" + ts + "\n" + credentialScope + "\n" + Sha256Hex(csr);
    // Signature
    std::vector<BYTE> kDate = HmacSha256Raw("TC3" + secretKey, date);
    std::vector<BYTE> kService = HmacSha256Raw(kDate, service);
    std::vector<BYTE> kCred = HmacSha256Raw(kService, "tc3_request");
    std::vector<BYTE> kSign = HmacSha256Raw(kCred, sts);
    std::string hex; char buf[4]; for (BYTE b : kSign) { sprintf_s(buf, "%02x", b); hex += buf; }
    // Authorization
    std::string auth = "TC3-HMAC-SHA256 Credential=" + secretId + "/" + credentialScope + ", SignedHeaders=content-type;host, Signature=" + hex;
    std::vector<std::pair<std::string, std::string>> hdrs;
    hdrs.push_back({"Authorization", auth}); hdrs.push_back({"Content-Type", "application/json; charset=utf-8"});
    hdrs.push_back({"Host", host}); hdrs.push_back({"X-TC-Action", action}); hdrs.push_back({"X-TC-Timestamp", ts});
    hdrs.push_back({"X-TC-Version", ver});
    return DnsHttp("https://" + host + "/", "POST", "application/json; charset=utf-8", payload, hdrs);
}

// ── Cloudflare DNS API ──
static std::string CfDnsApi(const std::wstring& apiToken, const std::string& method, const std::string& path, const std::string& body) {
    std::vector<std::pair<std::string, std::string>> hdrs;
    hdrs.push_back({"Authorization", "Bearer " + W2A(apiToken)});
    return DnsHttp("https://api.cloudflare.com/client/v4/" + path, method,
        body.empty() ? "" : "application/json", body, hdrs);
}

// ── DNS TXT 记录创建 ──
std::wstring DnsCreateTxtRecord(int provider, const std::wstring& apiId, const std::wstring& apiSecret,
    const std::wstring& domain, const std::wstring& subDomain, const std::wstring& value) {
    switch (provider) {
    case DNS_PROVIDER_ALIYUN:
    {
        DnsDeleteTxtRecord(provider, apiId, apiSecret, domain, subDomain);
        std::string rsp = AliyunDnsApi("AddDomainRecord", W2A(apiId), W2A(apiSecret),
            { {"DomainName", W2A(domain)}, {"RR", W2A(subDomain)}, {"Type", "TXT"}, {"Value", W2A(value)} });
        if (JsonStr(rsp, "RecordId").empty()) {
            std::string msg = JsonStr(rsp, "Message");
            return msg.empty() ? A2W(rsp) : A2W(msg);
        }
        Log(L"  [i] TXT 记录已创建");
        return L"";
    }
    case DNS_PROVIDER_TENCENT:
    {
        DnsDeleteTxtRecord(provider, apiId, apiSecret, domain, subDomain);
        std::string rsp = TencentDnsApi("CreateRecord", W2A(apiId), W2A(apiSecret),
            { {"Domain", W2A(domain)}, {"SubDomain", W2A(subDomain)}, {"RecordType", "TXT"}, {"Value", W2A(value)}, {"RecordLine", "默认"} });
        std::string err = JsonStr(rsp, "Code");
        if (!err.empty() && err != "NoError") return A2W(JsonStr(rsp, "Message"));
        Log(L"  [i] TXT 记录已创建");
        return L"";
    }
    case DNS_PROVIDER_CLOUDFLARE:
    {
        // subDomain 已经是 _acme-challenge（或 @ 表示根域），传给 CF API 会自动在 zone 范围内补全域名
        // 注意：@ 时传域名本身，非 @ 时传 subDomain 即可
        // domain 参数在 CF 下是 Zone ID，不能当域名用
        // 需要从 subDomain 和 Zone 名拼出完整记录名
        // 但这里没有 Zone 名... 改用简单规则：subDomain==@ 则传 @ 表示根域，否则传 subDomain
        // CF API: name 字段传 _acme-challenge 会自动解析为 _acme-challenge.zone-name
        std::string recName;
        if (subDomain == L"@") {
            recName = "@";
        } else if (subDomain.empty()) {
            recName = "_acme-challenge";
        } else {
            recName = W2A(subDomain);
        }
        std::string payload = "{\"type\":\"TXT\",\"name\":\"" + recName + "\",\"content\":\"" + W2A(value) + "\",\"ttl\":60}";
        std::string rsp = CfDnsApi(apiSecret, "POST", "zones/" + W2A(domain) + "/dns_records", payload);
        if (rsp.find("\"success\":true") == std::string::npos) {
            std::string msg = JsonStr(rsp, "message");
            return msg.empty() ? A2W(rsp) : A2W(msg);
        }
        Log(L"  [i] TXT 记录已创建");
        return L"";
    }
    default: return L"不支持的 DNS 提供商";
    }
}

// ── DNS TXT 记录删除 ──
std::wstring DnsDeleteTxtRecord(int provider, const std::wstring& apiId, const std::wstring& apiSecret,
    const std::wstring& domain, const std::wstring& subDomain) {
    switch (provider) {
    case DNS_PROVIDER_ALIYUN:
    {
        std::string rsp = AliyunDnsApi("DescribeDomainRecords", W2A(apiId), W2A(apiSecret),
            { {"DomainName", W2A(domain)}, {"RRKeyWord", W2A(subDomain)}, {"TypeKeyWord", "TXT"} });
        // 遍历所有匹配的 TXT 记录并删除
        size_t p = 0;
        while (true) {
            p = rsp.find("\"RecordId\":", p);
            if (p == std::string::npos) break;
            p += 11;
            size_t endPos = rsp.find_first_of(",}", p);
            if (endPos == std::string::npos) break;
            std::string rid = rsp.substr(p, endPos - p);
            bool valid = true;
            for (char c : rid) { if (!isdigit((unsigned char)c)) { valid = false; break; } }
            if (valid && !rid.empty()) {
                AliyunDnsApi("DeleteDomainRecord", W2A(apiId), W2A(apiSecret), { {"RecordId", rid} });
            }
            p = endPos;
        }
        return L"";
    }
    case DNS_PROVIDER_TENCENT:
    {
        std::string rsp = TencentDnsApi("DescribeRecordList", W2A(apiId), W2A(apiSecret),
            { {"Domain", W2A(domain)}, {"SubDomain", W2A(subDomain)} });
        std::string err = JsonStr(rsp, "Code");
        if (!err.empty() && err != "NoError") return L"";
        size_t p = 0;
        while (true) {
            p = rsp.find("\"RecordId\":", p);
            if (p == std::string::npos) break;
            p += 11;
            size_t endPos = rsp.find_first_of(",}", p);
            if (endPos == std::string::npos) break; // 安全检查
            std::string rid = rsp.substr(p, endPos - p);
            bool valid = true;
            for (char c : rid) { if (!isdigit((unsigned char)c)) { valid = false; break; } }
            if (valid && !rid.empty()) {
                TencentDnsApi("DeleteRecord", W2A(apiId), W2A(apiSecret), { {"Domain", W2A(domain)}, {"RecordId", rid} });
            }
            p = endPos;
        }
        return L"";
    }
    case DNS_PROVIDER_CLOUDFLARE:
    {
        // domain 是 Zone ID，列出所有 TXT 记录后按 name 匹配删除
        std::string rsp = CfDnsApi(apiSecret, "GET", "zones/" + W2A(domain) + "/dns_records?type=TXT", "");
        // 找 result 数组
        size_t arrStart = rsp.find("\"result\":[");
        if (arrStart == std::string::npos) return L"";
        arrStart += 10;
        std::string targetSub = W2A(subDomain);
        // 遍历 result 数组内每条记录对象
        size_t p = arrStart;
        while (p < rsp.size()) {
            // 找下一个对象起始 {
            size_t objStart = rsp.find('{', p);
            if (objStart == std::string::npos) break;
            // 找对象结束 }
            size_t objEnd = rsp.find('}', objStart);
            if (objEnd == std::string::npos) break;
            std::string obj = rsp.substr(objStart, objEnd - objStart + 1);
            // 从这个对象里提取 id 和 name
            std::string rid, recName;
            {
                size_t ip = obj.find("\"id\":\"");
                if (ip != std::string::npos) { ip += 6; size_t ie = obj.find("\"", ip); if (ie != std::string::npos) rid = obj.substr(ip, ie - ip); }
                size_t np = obj.find("\"name\":\"" );
                if (np != std::string::npos) { np += 8; size_t ne = obj.find("\"", np); if (ne != std::string::npos) recName = obj.substr(np, ne - np); }
            }
            // 匹配 _acme-challenge 记录
            bool match = (!rid.empty() && (recName == targetSub || recName.find(targetSub + ".") == 0));
            if (match) {
                CfDnsApi(apiSecret, "DELETE", "zones/" + W2A(domain) + "/dns_records/" + rid, "");
            }
            p = objEnd + 1;
        }
        return L"";
    }
    default: return L"不支持的 DNS 提供商";
    }
}

// 用于存储 Zone 信息的结构体
struct ZoneInfo {
    std::wstring name;
    std::wstring id; // Cloudflare 需要 Zone ID
};

// ── 查找 DNS Zone ──
std::wstring DnsFindZone(int provider, const std::wstring& apiId, const std::wstring& apiSecret,
    const std::wstring& recordName, std::wstring& outZone, std::wstring& outSubDomain) {
    std::string domain = W2A(recordName);
    if (domain.size() >= 2 && domain[0] == '*' && domain[1] == '.') domain = domain.substr(2);
    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

    std::vector<ZoneInfo> allZones;

    if (provider == DNS_PROVIDER_ALIYUN) {
        std::string rsp = AliyunDnsApi("DescribeDomains", W2A(apiId), W2A(apiSecret), { {"PageSize", "100"} });
        size_t p = 0;
        while (true) {
            p = rsp.find("\"DomainName\":\"", p);
            if (p == std::string::npos) break;
            p += 14; 
            size_t e = rsp.find("\"", p); 
            if (e == std::string::npos || e <= p) break; // 安全检查
            std::string dname = rsp.substr(p, e - p);
            std::transform(dname.begin(), dname.end(), dname.begin(), ::tolower);
            ZoneInfo zi;
            zi.name = A2W(dname);
            zi.id = zi.name; // 阿里云用域名作为标识
            allZones.push_back(zi);
            p = e;
        }
    }
    else if (provider == DNS_PROVIDER_TENCENT) {
        std::string rsp = TencentDnsApi("DescribeDomainList", W2A(apiId), W2A(apiSecret), {});
        size_t p = 0;
        while (true) {
            p = rsp.find("\"Name\":\"", p);
            if (p == std::string::npos) break;
            p += 8; 
            size_t e = rsp.find("\"", p); 
            if (e == std::string::npos || e <= p) break; // 安全检查
            std::string dname = rsp.substr(p, e - p);
            std::transform(dname.begin(), dname.end(), dname.begin(), ::tolower);
            ZoneInfo zi;
            zi.name = A2W(dname);
            zi.id = zi.name; // 腾讯云用域名作为标识
            allZones.push_back(zi);
            p = e;
        }
    }
    else if (provider == DNS_PROVIDER_CLOUDFLARE) {
        std::string rsp = CfDnsApi(apiSecret, "GET", "zones?per_page=100", "");
        // 找到 result 数组起始，避免解析外层容器的 id/name
        size_t arrStart = rsp.find("\"result\":[");
        if (arrStart == std::string::npos) return L"";
        arrStart += 10; // skip "result":[
        size_t p = arrStart;
        while (true) {
            // 先找 "id" 字段
            size_t idPos = rsp.find("\"id\":\"", p);
            if (idPos == std::string::npos) break;
            idPos += 6;
            size_t idEnd = rsp.find("\"", idPos);
            if (idEnd == std::string::npos || idEnd <= idPos) break;
            std::string zoneId = rsp.substr(idPos, idEnd - idPos);
            
            // 再找对应的 "name" 字段
            size_t namePos = rsp.find("\"name\":\"", idEnd);
            if (namePos == std::string::npos) break;
            namePos += 8;
            size_t nameEnd = rsp.find("\"", namePos);
            if (nameEnd == std::string::npos || nameEnd <= namePos) break;
            std::string dname = rsp.substr(namePos, nameEnd - namePos);
            std::transform(dname.begin(), dname.end(), dname.begin(), ::tolower);
            
            ZoneInfo zi;
            zi.name = A2W(dname);
            zi.id = A2W(zoneId); // Cloudflare 需要 Zone ID
            allZones.push_back(zi);
            
            p = nameEnd;
        }
    }

    ZoneInfo bestZone;
    int bestFit = 0;
    for (auto& z : allZones) {
        std::string zname = W2A(z.name);
        int fit = 0;
        if (_stricmp(domain.c_str(), zname.c_str()) == 0) {
            fit = (int)std::count(zname.begin(), zname.end(), '.') + 1;
        } else {
            std::string suffix = "." + zname;
            if (domain.size() > suffix.size() && _stricmp(domain.c_str() + domain.size() - suffix.size(), suffix.c_str()) == 0) {
                fit = (int)std::count(zname.begin(), zname.end(), '.') + 1;
            }
        }
        if (fit > bestFit) {
            bestFit = fit;
            bestZone = z;
        }
    }

    if (bestFit > 0) {
        // 对于 Cloudflare，我们返回 Zone ID 而不是域名，因为 API 需要 Zone ID
        if (provider == DNS_PROVIDER_CLOUDFLARE) {
            outZone = bestZone.id;
        } else {
            outZone = bestZone.name;
        }
        std::string zname = W2A(bestZone.name);
        std::string suffix = "." + zname;
        if (_stricmp(domain.c_str(), zname.c_str()) == 0) {
            outSubDomain = L"@";
        } else {
            std::string sub = domain.substr(0, domain.size() - suffix.size());
            outSubDomain = A2W(sub);
        }
    }
    return bestZone.name;
}

// ── DNS 权威服务器预验证 ──
// 流程：查询 NS 记录 → 解析权威 DNS IP → 直接向权威 DNS 查询 TXT 记录

static bool QueryTxtFromServer(const std::string& queryName, const std::string& serverIp, std::string& outValue) {
    outValue.clear();
    // 构建 IP4_ARRAY 结构体用于向特定 DNS 查询
    BYTE buf[sizeof(IP4_ARRAY) + sizeof(IP4_ADDRESS)];
    PIP4_ARRAY pSrvList = (PIP4_ARRAY)buf;
    pSrvList->AddrCount = 1;
    in_addr addr = {};
    if (inet_pton(AF_INET, serverIp.c_str(), &addr) != 1) return false;
    pSrvList->AddrArray[0] = addr.S_un.S_addr;

    PDNS_RECORD pDns = NULL;
    DNS_STATUS status = DnsQuery_UTF8(queryName.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, pSrvList, &pDns, NULL);
    if (status != ERROR_SUCCESS || !pDns) return false;
    bool found = false;
    for (PDNS_RECORD p = pDns; p; p = p->pNext) {
        if (p->wType == DNS_TYPE_TEXT && p->Data.Txt.dwStringCount > 0) {
            outValue = W2A(p->Data.Txt.pStringArray[0]);
            found = true; break;
        }
    }
    DnsRecordListFree(pDns, DnsFreeRecordList);
    return found;
}

bool DnsPreValidateAuthoritative(const std::wstring& queryName, const std::wstring& expectedValue, int maxRetries, int retryInterval) {
    std::string qName = W2A(queryName);
    std::string expected = W2A(expectedValue);

    // 从查询名提取基础域名：_acme-challenge.example.com → example.com
    std::string baseDomain = qName;
    if (baseDomain.size() >= 2 && baseDomain[0] == '*' && baseDomain[1] == '.')
        baseDomain = baseDomain.substr(2);
    // 去掉 _acme-challenge. 前缀
    const std::string acmePfx = "_acme-challenge.";
    if (baseDomain.size() > acmePfx.size() && _strnicmp(baseDomain.c_str(), acmePfx.c_str(), acmePfx.size()) == 0)
        baseDomain = baseDomain.substr(acmePfx.size());
    // 如果还有子域，继续剥离直到只剩下注册域名（至少一个点）
    // 策略：查询 NS 记录，如果失败就剥一级
    PDNS_RECORD pNS = NULL;
    DNS_STATUS nsStatus = DnsQuery_UTF8(baseDomain.c_str(), DNS_TYPE_NS, DNS_QUERY_STANDARD, NULL, &pNS, NULL);
    // 如果查不到 NS，尝试剥一级子域
    if (nsStatus != ERROR_SUCCESS || !pNS) {
        size_t dot = baseDomain.find('.');
        if (dot != std::string::npos && dot + 1 < baseDomain.size()) {
            baseDomain = baseDomain.substr(dot + 1);
            nsStatus = DnsQuery_UTF8(baseDomain.c_str(), DNS_TYPE_NS, DNS_QUERY_STANDARD, NULL, &pNS, NULL);
        }
    }
    if (nsStatus != ERROR_SUCCESS || !pNS) {
        if (pNS) DnsRecordListFree(pNS, DnsFreeRecordList);
        return false;
    }

    std::vector<std::string> servers;
    for (PDNS_RECORD p = pNS; p; p = p->pNext) {
        if (p->wType == DNS_TYPE_NS && p->Data.NS.pNameHost) {
            std::string nsHost = W2A(p->Data.NS.pNameHost);
            PDNS_RECORD pA = NULL;
            if (DnsQuery_UTF8(nsHost.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pA, NULL) == ERROR_SUCCESS && pA) {
                for (PDNS_RECORD pa = pA; pa; pa = pa->pNext) {
                    if (pa->wType == DNS_TYPE_A) {
                        char ipBuf[INET_ADDRSTRLEN];
                        in_addr a; a.s_addr = pa->Data.A.IpAddress;
                        if (inet_ntop(AF_INET, &a, ipBuf, sizeof(ipBuf))) servers.push_back(ipBuf);
                    }
                }
                DnsRecordListFree(pA, DnsFreeRecordList);
            }
        }
    }
    DnsRecordListFree(pNS, DnsFreeRecordList);
    if (servers.empty()) return false;

    for (int i = 0; i < maxRetries; i++) {
        for (size_t s = 0; s < servers.size(); s++) {
            std::string txtValue;
            if (QueryTxtFromServer(qName, servers[s], txtValue) && txtValue == expected)
                return true;
        }
        if (i < maxRetries - 1) Sleep(retryInterval * 1000);
    }
    return false;
}

bool DnsVerifyApi(int provider, const std::wstring& apiId, const std::wstring& apiSecret) {
    if (provider == DNS_PROVIDER_ALIYUN) {
        std::string rsp = AliyunDnsApi("DescribeDomains", W2A(apiId), W2A(apiSecret), { {"PageSize", "1"} });
        bool ok = rsp.find("DomainName") != std::string::npos || rsp.find("TotalCount") != std::string::npos;
        Log(L"  阿里云 API 验证%s", ok ? L"成功" : L"失败");
        if (!ok && !rsp.empty()) Log(L"  [错误] %s", A2W(rsp.substr(0, 200)).c_str());
        return ok;
    }
    else if (provider == DNS_PROVIDER_TENCENT) {
        std::string rsp = TencentDnsApi("DescribeDomainList", W2A(apiId), W2A(apiSecret), {});
        bool ok = rsp.find("DomainList") != std::string::npos || rsp.find("\"Code\":\"\"") != std::string::npos;
        Log(L"  腾讯云 API 验证%s", ok ? L"成功" : L"失败");
        if (!ok && !rsp.empty()) Log(L"  [错误] %s", A2W(rsp.substr(0, 200)).c_str());
        return ok;
    }
    else if (provider == DNS_PROVIDER_CLOUDFLARE) {
        std::string rsp = CfDnsApi(apiSecret, "GET", "zones?per_page=1", "");
        bool ok = rsp.find("\"success\":true") != std::string::npos;
        Log(L"  Cloudflare API 验证%s", ok ? L"成功" : L"失败");
        if (!ok && !rsp.empty()) Log(L"  [错误] %s", A2W(rsp.substr(0, 200)).c_str());
        return ok;
    }
    return false;
}
