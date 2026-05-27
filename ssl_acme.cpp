// ssl_acme.cpp - ACME 协议核心（账户密钥、JWS 签名、CSR 生成）
#include "ssl_core.h"
#include "ssl_keyfmt.h"

extern void Log(const wchar_t* fmt, ...);
extern bool WriteFileAtomic(const std::string& path, const std::string& content);

// 外部全局变量
extern BCRYPT_KEY_HANDLE g_AccKey;
extern std::string g_AccPubB64, g_AccExpB64;
extern std::string g_AccURL;

// ── DER 长度编码 ──
static void DerLenAppend(std::vector<BYTE>& out, size_t len) {
    if (len < 128) out.push_back((BYTE)len);
    else if (len <= 0xFF) { out.push_back(0x81); out.push_back((BYTE)len); }
    else { out.push_back(0x82); out.push_back((BYTE)(len >> 8)); out.push_back((BYTE)(len & 0xFF)); }
}

// ── CSR 生成 ──
std::vector<BYTE> BuildCSR(const std::string& domain, BCRYPT_KEY_HANDLE key, const std::vector<std::string>* extraSans) {
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
    static BYTE nullParam[] = { 0x05, 0x00 };
    cri.SubjectPublicKeyInfo.Algorithm.Parameters.cbData = 2;
    cri.SubjectPublicKeyInfo.Algorithm.Parameters.pbData = nullParam;
    cri.SubjectPublicKeyInfo.PublicKey.cbData = (DWORD)rsaPub.size();
    cri.SubjectPublicKeyInfo.PublicKey.pbData = rsaPub.data();
    cri.SubjectPublicKeyInfo.PublicKey.cUnusedBits = 0;

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
            CERT_EXTENSION ext = { 0 };
            ext.pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
            ext.fCritical = FALSE;
            ext.Value.cbData = sanEncodedSize;
            ext.Value.pbData = sanEncoded.data();
            CERT_EXTENSIONS exts = { 0 };
            exts.cExtension = 1;
            exts.rgExtension = &ext;
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

    BCRYPT_ALG_HANDLE ha = NULL; 
    if (BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return {};
    BCRYPT_HASH_HANDLE hh = NULL; 
    if (BCryptCreateHash(ha, &hh, NULL, 0, NULL, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(ha, 0);
        return {};
    }
    if (BCryptHashData(hh, (PUCHAR)tbsBuf.data(), (ULONG)tbsLen, 0) != 0) {
        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(ha, 0);
        return {};
    }
    BYTE hash[32]; 
    if (BCryptFinishHash(hh, hash, 32, 0) != 0) {
        BCryptDestroyHash(hh);
        BCryptCloseAlgorithmProvider(ha, 0);
        return {};
    }
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(ha, 0);

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

// ── 账户密钥 ──
bool ExtractPublicKey() {
    if (!g_AccKey) return false;
    DWORD pl = 0; if (BCryptExportKey(g_AccKey, 0, BCRYPT_RSAPUBLIC_BLOB, 0, 0, &pl, 0)) return false;
    std::vector<BYTE> pb(pl); if (BCryptExportKey(g_AccKey, 0, BCRYPT_RSAPUBLIC_BLOB, pb.data(), pl, &pl, 0)) return false;
    BCRYPT_RSAKEY_BLOB* hd = (BCRYPT_RSAKEY_BLOB*)pb.data();
    BYTE* ep = pb.data() + sizeof(BCRYPT_RSAKEY_BLOB); BYTE* md = ep + hd->cbPublicExp;
    g_AccPubB64 = B64Url(std::vector<BYTE>(md, md + hd->cbModulus));
    g_AccExpB64 = B64Url(std::vector<BYTE>(ep, ep + hd->cbPublicExp)); return true;
}

bool MakeAccountKey() {
    if (g_AccKey) { (void)BCryptDestroyKey(g_AccKey); g_AccKey = NULL; }
    BCRYPT_ALG_HANDLE a = NULL; if (BCryptOpenAlgorithmProvider(&a, BCRYPT_RSA_ALGORITHM, 0, 0)) return false;
    BCRYPT_KEY_HANDLE k = NULL; if (BCryptGenerateKeyPair(a, &k, 2048, 0)) { (void)BCryptCloseAlgorithmProvider(a, 0); return false; }
    if (BCryptFinalizeKeyPair(k, 0)) { (void)BCryptDestroyKey(k); (void)BCryptCloseAlgorithmProvider(a, 0); return false; }
    (void)BCryptCloseAlgorithmProvider(a, 0); g_AccKey = k; return ExtractPublicKey();
}

bool LoadAccountKey(const std::string& path) {
    std::wstring wPath = A2W(path);
    HANDLE hf = CreateFileW(wPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return false;
    DWORD fsz = GetFileSize(hf, NULL); std::string pem(fsz, '\0'); DWORD rd = 0;
    (void)ReadFile(hf, &pem[0], fsz, &rd, NULL); CloseHandle(hf); pem.resize(rd);
    size_t s = pem.find("-----BEGIN"); size_t e = pem.find("-----END");
    if (s == std::string::npos || e == std::string::npos) return false;
    s = pem.find('\n', s); if (s == std::string::npos) s = pem.find('\r', s); if (s == std::string::npos) return false; s++;
    std::string b64 = pem.substr(s, e - s); DWORD cb = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, NULL, &cb, NULL, NULL)) return false;
    std::vector<BYTE> der(cb); if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, der.data(), &cb, NULL, NULL)) return false;
    NCRYPT_PROV_HANDLE hProv = NULL; if (NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0)) return false;
    NCRYPT_KEY_HANDLE hNKey = NULL;
    SECURITY_STATUS ss = NCryptImportKey(hProv, NULL, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &hNKey, der.data(), (DWORD)der.size(), 0);
    NCryptFreeObject(hProv); if (ss) return false;
    DWORD cbBlob = 0; SECURITY_STATUS ssExport = NCryptExportKey(hNKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &cbBlob, 0);
    if (ssExport != 0 || cbBlob == 0) { NCryptFreeObject(hNKey); return false; }
    std::vector<BYTE> blob(cbBlob); ssExport = NCryptExportKey(hNKey, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, blob.data(), cbBlob, &cbBlob, 0);
    NCryptFreeObject(hNKey); if (ssExport != 0) return false;
    BCRYPT_ALG_HANDLE hAlg = NULL; 
    NTSTATUS stOpen = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (stOpen != 0) return false;
    
    BCRYPT_KEY_HANDLE hBKey = NULL; 
    NTSTATUS st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPRIVATE_BLOB, &hBKey, blob.data(), (ULONG)blob.size(), 0);
    (void)BCryptCloseAlgorithmProvider(hAlg, 0); 
    if (st != 0) return false;
    if (g_AccKey) (void)BCryptDestroyKey(g_AccKey); g_AccKey = hBKey; return true;
}

std::string MakeJWK() { return "{\"e\":\"" + g_AccExpB64 + "\",\"kty\":\"RSA\",\"n\":\"" + g_AccPubB64 + "\"}"; }

std::string AccThumbprint() {
    std::string jwk = MakeJWK();
    BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, 0, 0);
    BCRYPT_HASH_HANDLE hh = NULL; (void)BCryptCreateHash(ha, &hh, 0, 0, 0, 0, 0);
    (void)BCryptHashData(hh, (PUCHAR)jwk.data(), (ULONG)jwk.size(), 0);
    BYTE hash[32]; (void)BCryptFinishHash(hh, hash, 32, 0);
    (void)BCryptDestroyHash(hh); (void)BCryptCloseAlgorithmProvider(ha, 0);
    return B64Url(std::vector<BYTE>(hash, hash + 32));
}

void SavePKEY(const std::string& path) {
    DWORD fl = 0; NTSTATUS st = BCryptExportKey(g_AccKey, 0, BCRYPT_RSAFULLPRIVATE_BLOB, 0, 0, &fl, 0);
    if (st == 0 && fl > 0) {
        std::vector<BYTE> fb(fl); st = BCryptExportKey(g_AccKey, 0, BCRYPT_RSAFULLPRIVATE_BLOB, fb.data(), fl, &fl, 0);
        if (st == 0) {
            std::string pem = RsaFullBlobToPkcs8Pem(fb);
            if (!pem.empty()) { WriteFileAtomic(path, pem); return; }
        }
    }
    DWORD pl = 0; st = BCryptExportKey(g_AccKey, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, 0, 0, &pl, 0);
    if (st == 0 && pl > 0) {
        std::vector<BYTE> pk(pl); st = BCryptExportKey(g_AccKey, 0, BCRYPT_PKCS8_PRIVATE_KEY_BLOB, pk.data(), pl, &pl, 0);
        if (st == 0) {
            std::string b = B64Pem(pk);
            std::string pem = "-----BEGIN PRIVATE KEY-----\r\n" + b + "\r\n-----END PRIVATE KEY-----\r\n";
            WriteFileAtomic(path, pem); return;
        }
    }
    Log(L"[错误] 导出账户密钥失败");
}

// ── JWS 签名 ──
std::string SignJWS(const std::string& payload, const std::string& nonce, const std::string& url, bool useJWK) {
    std::string prot = "{\"alg\":\"RS256\"";
    if (useJWK) prot += ",\"jwk\":" + MakeJWK(); else prot += ",\"kid\":\"" + g_AccURL + "\"";
    if (!nonce.empty()) prot += ",\"nonce\":\"" + nonce + "\"";
    prot += ",\"url\":\"" + url + "\"}";
    std::string pb64 = B64UrlS(prot); std::string pay64 = B64UrlS(payload);
    std::string toSign = pb64 + "." + pay64;
    BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, 0, 0);
    BCRYPT_HASH_HANDLE hh = NULL; (void)BCryptCreateHash(ha, &hh, 0, 0, 0, 0, 0);
    (void)BCryptHashData(hh, (PUCHAR)toSign.data(), (ULONG)toSign.size(), 0);
    BYTE hash[32]; (void)BCryptFinishHash(hh, hash, 32, 0);
    (void)BCryptDestroyHash(hh); (void)BCryptCloseAlgorithmProvider(ha, 0);
    BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
    DWORD sl = 0; (void)BCryptSignHash(g_AccKey, &pi, hash, 32, 0, 0, &sl, BCRYPT_PAD_PKCS1);
    std::vector<BYTE> sig(sl); (void)BCryptSignHash(g_AccKey, &pi, hash, 32, sig.data(), sl, &sl, BCRYPT_PAD_PKCS1);
    std::string sig64 = B64Url(sig);
    return "{\"protected\":\"" + pb64 + "\",\"payload\":\"" + pay64 + "\",\"signature\":\"" + sig64 + "\"}";
}

std::string AcmePost(const std::string& urlStr, const std::string& payload, std::string& nonce, bool useJWK, std::string* outLocation, DWORD* outStatus) {
    std::wstring wurl = A2W(urlStr);
    std::string jws = SignJWS(payload, nonce, urlStr, useJWK);
    std::string newNonce, loc; DWORD statusCode = 0;
    std::string result = HttpJson(wurl.c_str(), L"POST", jws.c_str(), (int)jws.size(), &newNonce, outLocation ? &loc : NULL, &statusCode);
    if (!newNonce.empty()) nonce = newNonce;
    if (outLocation && !loc.empty()) *outLocation = loc;
    if (outStatus) *outStatus = statusCode;
    return result;
}
