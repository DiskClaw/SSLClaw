// ssl_deploy.cpp - 部署模块（PFX 导出、证书存储导入）
#include "ssl_core.h"
#include "ssl_keyfmt.h"

extern void Log(const wchar_t* fmt, ...);

// PFX 导出（IIS 用）
bool SavePFX(BCRYPT_KEY_HANDLE dk, const std::string& certPem, const std::wstring& pfxPath) {
    if (certPem.empty()) { Log(L"[错误] PFX: 证书数据为空"); return false; }

    // 1. 先用 RsaFullBlobToPkcs8Pem 获取 PKCS8 PEM（这个肯定没问题，主流程已经验证过）
    DWORD fullBlobLen = 0;
    if (BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, 0, 0, &fullBlobLen, 0)) { Log(L"[错误] PFX: 获取密钥大小失败"); return false; }
    std::vector<BYTE> rsaFullBlob(fullBlobLen);
    if (BCryptExportKey(dk, 0, BCRYPT_RSAFULLPRIVATE_BLOB, rsaFullBlob.data(), fullBlobLen, &fullBlobLen, 0)) { Log(L"[错误] PFX: 导出密钥失败"); return false; }
    std::string pkcs8Pem = RsaFullBlobToPkcs8Pem(rsaFullBlob);
    if (pkcs8Pem.empty()) { Log(L"[错误] PFX: 密钥格式转换失败 (RsaFullBlobToPkcs8Pem)"); return false; }

    // 2. 将 PKCS8 PEM 转成 DER
    std::string b64;
    for (size_t i = 0; i < pkcs8Pem.size(); i++) {
        if (pkcs8Pem[i] == '-') { // 跳过 -----BEGIN/END...----- 行
            while (i < pkcs8Pem.size() && pkcs8Pem[i] != '\n' && pkcs8Pem[i] != '\r') i++;
            while (i < pkcs8Pem.size() && (pkcs8Pem[i] == '\n' || pkcs8Pem[i] == '\r')) i++;
            i--;
            continue;
        }
        if (pkcs8Pem[i] == '\n' || pkcs8Pem[i] == '\r' || pkcs8Pem[i] == ' ') continue;
        b64 += pkcs8Pem[i];
    }
    if (b64.empty()) { Log(L"[错误] PFX: PKCS8 PEM 解析失败"); return false; }

    DWORD cbDer = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, NULL, &cbDer, NULL, NULL)) {
        Log(L"[错误] PFX: CryptStringToBinaryA 1 失败"); return false;
    }
    std::vector<BYTE> pkcs8Der(cbDer);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, pkcs8Der.data(), &cbDer, NULL, NULL)) {
        Log(L"[错误] PFX: CryptStringToBinaryA 2 失败"); return false;
    }

    // 3. 写证书 PEM 到临时文件，CertOpenStore 解析
    wchar_t tempDir[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tempDir)) { Log(L"[错误] PFX: 获取临时目录失败"); return false; }
    std::wstring tempPem = std::wstring(tempDir) + L"SSLClaw_temp_cert.pem";
    {
        HANDLE hTemp = CreateFileW(tempPem.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTemp == INVALID_HANDLE_VALUE) { Log(L"[错误] PFX: 创建证书临时文件失败"); return false; }
        DWORD written = 0;
        WriteFile(hTemp, certPem.data(), (DWORD)certPem.size(), &written, NULL);
        CloseHandle(hTemp);
    }

    // 4. 打开证书存储，复制到内存存储
    HCERTSTORE hFileStore = CertOpenStore(CERT_STORE_PROV_FILENAME, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
        CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, tempPem.c_str());
    DeleteFileW(tempPem.c_str());
    if (!hFileStore) { Log(L"[错误] PFX: 解析证书链失败"); return false; }

    HCERTSTORE hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    if (!hMemStore) { CertCloseStore(hFileStore, 0); Log(L"[错误] PFX: 无法创建内存存储"); return false; }

    PCCERT_CONTEXT pLeaf = NULL;
    PCCERT_CONTEXT pEnum = NULL;
    while ((pEnum = CertEnumCertificatesInStore(hFileStore, pEnum)) != NULL) {
        PCCERT_CONTEXT pAdded = NULL;
        if (!CertAddCertificateContextToStore(hMemStore, pEnum, CERT_STORE_ADD_ALWAYS, &pAdded)) {
            Log(L"[错误] PFX: 添加证书失败"); continue;
        }
        if (!pLeaf && pAdded) pLeaf = pAdded;
        else if (pAdded) CertFreeCertificateContext(pAdded);
    }
    CertCloseStore(hFileStore, 0);
    if (!pLeaf) { CertCloseStore(hMemStore, 0); Log(L"[错误] PFX: 未找到叶证书"); return false; }

    // 5. 用 NCrypt 导入 PKCS8 密钥（瞬态导入，不持久化到 KSP 存储）
    //    带名字导入会被 KSP 立即持久化，默认不可导出，且事后无法升级导出策略
    //    瞬态密钥不走 KSP 存储，直接就是可导出的，PFX 导出完即释放
    NCRYPT_PROV_HANDLE hNcProv = 0;
    if (NCryptOpenStorageProvider(&hNcProv, MS_KEY_STORAGE_PROVIDER, 0)) {
        CertFreeCertificateContext(pLeaf); CertCloseStore(hMemStore, 0); Log(L"[错误] PFX: NCryptOpenStorageProvider 失败"); return false;
    }

    NCRYPT_KEY_HANDLE hNcKey = 0;
    if (NCryptImportKey(hNcProv, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL,
        &hNcKey, pkcs8Der.data(), (DWORD)pkcs8Der.size(), 0)) {
        NCryptFreeObject(hNcProv); CertFreeCertificateContext(pLeaf); CertCloseStore(hMemStore, 0);
        Log(L"[错误] PFX: NCryptImportKey 失败"); return false;
    }

    // 瞬态密钥设置导出策略（不需要 PERSIST_FLAG，因为不持久化）
    DWORD exportPolicy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    NCryptSetProperty(hNcKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&exportPolicy, sizeof(exportPolicy), 0);

    // 验证导出策略是否生效
    DWORD actualPolicy = 0, cbPolicy = sizeof(DWORD);
    NCryptGetProperty(hNcKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&actualPolicy, cbPolicy, &cbPolicy, 0);
    if (!(actualPolicy & NCRYPT_ALLOW_EXPORT_FLAG)) {
        NCryptFreeObject(hNcKey); NCryptFreeObject(hNcProv); CertFreeCertificateContext(pLeaf); CertCloseStore(hMemStore, 0);
        Log(L"[错误] PFX: 无法设置密钥为可导出 (策略=0x%08X)", actualPolicy); return false;
    }

    // 6. 关联密钥到证书——用 CERT_KEY_CONTEXT_PROP_ID 直接传 NCRYPT_KEY_HANDLE
    //    这样 PFXExportCertStoreEx 不会重新打开密钥，直接用这个句柄
    CERT_KEY_CONTEXT keyCtx = {};
    keyCtx.cbSize = sizeof(CERT_KEY_CONTEXT);
    keyCtx.hCryptProv = (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)hNcKey;
    keyCtx.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
    if (!CertSetCertificateContextProperty(pLeaf, CERT_KEY_CONTEXT_PROP_ID, 0, &keyCtx)) {
        DWORD err = GetLastError();
        NCryptFreeObject(hNcKey); NCryptFreeObject(hNcProv); CertFreeCertificateContext(pLeaf); CertCloseStore(hMemStore, 0);
        Log(L"[错误] PFX: CertSetCertificateContextProperty(KEY_CONTEXT) 失败 (0x%08X)", err); return false;
    }

    // 7. 终于，PFX 导出！
    CRYPT_DATA_BLOB pfxBlob = {};
    DWORD exportFlags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, L"", NULL, exportFlags)) {
        DWORD err = GetLastError();
        NCryptFreeObject(hNcKey); NCryptFreeObject(hNcProv); CertFreeCertificateContext(pLeaf); CertCloseStore(hMemStore, 0);
        Log(L"[错误] PFX: PFXExportCertStoreEx 1 失败 (0x%08X)", err); return false;
    }
    pfxBlob.pbData = (BYTE*)LocalAlloc(LMEM_FIXED, pfxBlob.cbData);
    if (!pfxBlob.pbData) {
        NCryptFreeObject(hNcKey); NCryptFreeObject(hNcProv); CertFreeCertificateContext(pLeaf); CertCloseStore(hMemStore, 0);
        return false;
    }
    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, L"", NULL, exportFlags)) {
        DWORD err = GetLastError();
        LocalFree(pfxBlob.pbData);
        NCryptFreeObject(hNcKey); NCryptFreeObject(hNcProv); CertFreeCertificateContext(pLeaf); CertCloseStore(hMemStore, 0);
        Log(L"[错误] PFX: PFXExportCertStoreEx 2 失败 (0x%08X)", err); return false;
    }

    // 8. 写 PFX 文件
    HANDLE hf = CreateFileW(pfxPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    bool ok = false;
    if (hf != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        ok = (WriteFile(hf, pfxBlob.pbData, pfxBlob.cbData, &written, NULL) && written == pfxBlob.cbData);
        CloseHandle(hf);
    }

    // 9. 清理资源
    LocalFree(pfxBlob.pbData);
    CertFreeCertificateContext(pLeaf);
    CertCloseStore(hMemStore, 0);
    NCryptFreeObject(hNcKey);  // 释放瞬态密钥（不持久化，无需删除）
    NCryptFreeObject(hNcProv);

    if (!ok) Log(L"[错误] PFX: 写文件失败");
    return ok;
}
