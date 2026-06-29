// ssl_utils.cpp - 工具函数（字符串、Base64、SHA256、JSON 解析、GUID、DPAPI 加密）
#include "ssl_core.h"

// ── 字符串转换 ──
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

// ── Base64 URL ──
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
    while (!s.empty() && (s.back() == '\0' || s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s;
}

// ── SHA-256 ──
std::string Sha256B64(const std::string& data) {
    BCRYPT_ALG_HANDLE ha = NULL; (void)BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, 0, 0);
    BCRYPT_HASH_HANDLE hh = NULL; (void)BCryptCreateHash(ha, &hh, 0, 0, 0, 0, 0);
    (void)BCryptHashData(hh, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BYTE hash[32]; (void)BCryptFinishHash(hh, hash, 32, 0);
    (void)BCryptDestroyHash(hh); (void)BCryptCloseAlgorithmProvider(ha, 0);
    return B64Url(std::vector<BYTE>(hash, hash + 32));
}

// ── JSON 解析（简单字符串匹配，不依赖第三方库） ──
std::string JsonStr(const std::string& json, const char* key) {
    std::string k = "\"" + std::string(key) + "\"";
    size_t pos = 0;
    while (true) {
        pos = json.find(k, pos);
        if (pos == std::string::npos) return "";
        if (pos + k.size() >= json.size() || json[pos + k.size()] != ':') {
            pos += k.size(); continue;
        }
        int depth = 0; bool inStr = false;
        for (size_t i = 0; i < pos; i++) {
            if (inStr) { if (json[i] == '\\') i++; else if (json[i] == '"') inStr = false; }
            else if (json[i] == '"') inStr = true;
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

// ── GUID 生成 ──
std::wstring NewGuid() {
    GUID guid; if (CoCreateGuid(&guid) != S_OK) return L"";
    wchar_t buf[64]; swprintf_s(buf, L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return buf;
}

// ── 原子文件写入 ──
bool WriteFileAtomic(const std::string& path, const std::string& content) {
    std::wstring wPath = A2W(path);
    std::wstring wTmp  = wPath + L".tmp";
    {
        HANDLE h = CreateFileW(wTmp.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) return false;
        DWORD written = 0;
        BOOL ok = WriteFile(h, content.data(), (DWORD)content.size(), &written, NULL);
        CloseHandle(h);
        if (!ok || written != (DWORD)content.size()) { _wunlink(wTmp.c_str()); return false; }
    }
    if (!MoveFileExW(wTmp.c_str(), wPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        _wunlink(wTmp.c_str()); return false;
    }
    return true;
}

// ── 随机密码生成 ──
std::wstring GeneratePassword(int len) {
    const wchar_t chars[] = L"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    const int n = (sizeof(chars) / sizeof(wchar_t)) - 1;
    std::wstring pwd; pwd.reserve(len);
    for (int i = 0; i < len; i++) {
        BYTE r; BCryptGenRandom(NULL, &r, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        pwd += chars[r % n];
    }
    return pwd;
}

// ── 加密/解密（AES-256-CBC + 机器特征密钥，兼容旧 DPAPI 格式） ──
// Protect: "aes-" + base64(aes1 + IV + 密文)
// Unprotect: 兼容旧 "enc-"(DPAPI) 和新 "aes-"(AES)

static bool GetMachineBoundKey(std::vector<BYTE>& outKey32) {
    // 种子: 混合机器特征，换机器密钥不同
    std::string seed = "SSLClaw-AES-Key-2026";
    // 加入机器名
    WCHAR compName[MAX_COMPUTERNAME_LENGTH + 1]; DWORD cnLen = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(compName, &cnLen)) seed += W2A(compName);
    // 加入可执行文件路径的卷序列号
    WCHAR exePath[MAX_PATH]; GetModuleFileNameW(NULL, exePath, MAX_PATH);
    WCHAR driveRoot[4] = { exePath[0], exePath[1], exePath[2], 0 };
    DWORD volSerial = 0; GetVolumeInformationW(driveRoot, NULL, 0, &volSerial, NULL, NULL, NULL, 0);
    seed += std::to_string(volSerial);
    // SHA-256
    outKey32.resize(32);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
    BCryptHashData(hHash, (PUCHAR)seed.c_str(), (ULONG)seed.size(), 0);
    BCryptFinishHash(hHash, outKey32.data(), 32, 0);
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

static std::vector<BYTE> Aes256CbcEncrypt(const std::vector<BYTE>& key32, const std::vector<BYTE>& iv16, const std::vector<BYTE>& plaintext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return {};
    DWORD cbObj = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(DWORD), &cbData, 0);
    // 设置 CBC 模式
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCRYPT_KEY_HANDLE hKey = NULL;
    std::vector<BYTE> keyObj(cbObj);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), cbObj, (PUCHAR)key32.data(), 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return {};
    }
    // PKCS7 填充
    DWORD padLen = 16 - (plaintext.size() % 16);
    if (padLen == 0) padLen = 16; // 如果正好对齐，添加完整块填充
    std::vector<BYTE> padded = plaintext;
    padded.resize(plaintext.size() + padLen, (BYTE)padLen);
    DWORD cbCipher = 0;
    if (BCryptEncrypt(hKey, padded.data(), (ULONG)padded.size(), NULL, (PUCHAR)iv16.data(), 16, NULL, 0, &cbCipher, 0) != 0) {
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    std::vector<BYTE> cipher(cbCipher);
    if (BCryptEncrypt(hKey, padded.data(), (ULONG)padded.size(), NULL, (PUCHAR)iv16.data(), 16, cipher.data(), cbCipher, &cbCipher, 0) != 0) {
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    return cipher;
}

static std::vector<BYTE> Aes256CbcDecrypt(const std::vector<BYTE>& key32, const std::vector<BYTE>& iv16, const std::vector<BYTE>& ciphertext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return {};
    DWORD cbObj = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(DWORD), &cbData, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    BCRYPT_KEY_HANDLE hKey = NULL;
    std::vector<BYTE> keyObj(cbObj);
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), cbObj, (PUCHAR)key32.data(), 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0); return {};
    }
    DWORD cbPlain = 0;
    std::vector<BYTE> ctCopy(ciphertext); // BCryptDecrypt 需要 PUCHAR 非 const
    if (BCryptDecrypt(hKey, ctCopy.data(), (ULONG)ctCopy.size(), NULL, (PUCHAR)iv16.data(), 16, NULL, 0, &cbPlain, 0) != 0) {
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    std::vector<BYTE> plain(cbPlain);
    if (BCryptDecrypt(hKey, ctCopy.data(), (ULONG)ctCopy.size(), NULL, (PUCHAR)iv16.data(), 16, plain.data(), cbPlain, &cbPlain, 0) != 0) {
        BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    // PKCS7 去填充
    if (plain.empty()) return plain;
    BYTE pad = plain.back();
    if (pad > 0 && pad <= 16) {
        bool validPad = true;
        for (size_t i = plain.size() - pad; i < plain.size(); i++) { if (plain[i] != pad) { validPad = false; break; } }
        if (validPad) plain.resize(plain.size() - pad);
    }
    return plain;
}

std::string ProtectString(const std::string& clearText) {
    if (clearText.empty()) return "";
    std::vector<BYTE> key32;
    if (!GetMachineBoundKey(key32)) return clearText; // 降级明文
    // 随机 IV
    BYTE ivBuf[16]; BCryptGenRandom(NULL, ivBuf, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::vector<BYTE> iv(ivBuf, ivBuf + 16);
    std::vector<BYTE> plain(clearText.begin(), clearText.end());
    std::vector<BYTE> cipher = Aes256CbcEncrypt(key32, iv, plain);
    if (cipher.empty()) return clearText;
    // 拼接: "aes1" + IV + 密文
    std::vector<BYTE> blob; blob.reserve(4 + 16 + cipher.size());
    const char* magic = "aes1"; blob.insert(blob.end(), magic, magic + 4);
    blob.insert(blob.end(), iv.begin(), iv.end());
    blob.insert(blob.end(), cipher.begin(), cipher.end());
    // Base64（CRYPT_STRING_NOCRLF 仍可能在 64 字符处换行，需彻底去除所有 \r \n）
    DWORD b64len = 0;
    CryptBinaryToStringA(blob.data(), (DWORD)blob.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64len);
    std::string b64; b64.resize(b64len);
    CryptBinaryToStringA(blob.data(), (DWORD)blob.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &b64[0], &b64len);
    // 去除所有 \r \n \0（不仅是尾部，CryptBinaryToStringA 可能在 64 字符边界插入换行）
    std::string clean64;
    clean64.reserve(b64.size());
    for (char c : b64) {
        if (c != '\r' && c != '\n' && c != '\0') clean64 += c;
    }
    return "aes-" + clean64;
}

std::string UnprotectString(const std::string& protectedText) {
    if (protectedText.empty()) return "";
    // 兼容旧 DPAPI 格式 "enc-"
    if (protectedText.size() >= 4 && protectedText.substr(0, 4) == "enc-") {
        std::string b64 = protectedText.substr(4);
        DWORD dlen = 0;
        if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, NULL, &dlen, NULL, NULL))
            return b64;
        std::vector<BYTE> decoded(dlen);
        if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, decoded.data(), &dlen, NULL, NULL))
            return b64;
        DATA_BLOB dataIn = {}; dataIn.pbData = decoded.data(); dataIn.cbData = dlen;
        DATA_BLOB dataOut = {};
        BOOL ok = CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut);
        if (!ok) return b64; // DPAPI 解密失败，返回原始 Base64
        std::string result((char*)dataOut.pbData, dataOut.cbData);
        LocalFree(dataOut.pbData);
        return result;
    }
    // 新 AES 格式 "aes-"
    if (protectedText.size() < 5 || protectedText.substr(0, 4) != "aes-") return protectedText; // 明文
    std::string b64 = protectedText.substr(4);
    DWORD dlen = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, NULL, &dlen, NULL, NULL))
        return b64;
    std::vector<BYTE> decoded(dlen);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, decoded.data(), &dlen, NULL, NULL))
        return b64;
    // 解析: "aes1" + 16字节IV + 密文
    if (decoded.size() < 20 || decoded[0] != 'a' || decoded[1] != 'e' || decoded[2] != 's' || decoded[3] != '1')
        return b64;
    std::vector<BYTE> iv(decoded.begin() + 4, decoded.begin() + 20);
    std::vector<BYTE> cipher(decoded.begin() + 20, decoded.end());
    std::vector<BYTE> key32;
    if (!GetMachineBoundKey(key32)) return b64;
    std::vector<BYTE> plain = Aes256CbcDecrypt(key32, iv, cipher);
    if (plain.empty()) return b64;
    return std::string(plain.begin(), plain.end());
}

void EnsureIniUtf8(const wchar_t* iniPath) {
    HANDLE hFile = CreateFileW(iniPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        BYTE hdr[3] = {};
        DWORD read = 0;
        ReadFile(hFile, hdr, 3, &read, NULL);
        // 已经是 UTF-8 BOM，无需处理
        if (read >= 3 && hdr[0] == 0xEF && hdr[1] == 0xBB && hdr[2] == 0xBF) {
            CloseHandle(hFile); return;
        }
        // UTF-16 LE BOM → 转换为 UTF-8
        if (read >= 2 && hdr[0] == 0xFF && hdr[1] == 0xFE) {
            CloseHandle(hFile);
            hFile = CreateFileW(iniPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return;
            DWORD fileSize = GetFileSize(hFile, NULL);
            if (fileSize < 2 || fileSize > 1024 * 1024) { CloseHandle(hFile); return; }
            std::vector<BYTE> data(fileSize);
            DWORD totalRead = 0;
            ReadFile(hFile, data.data(), fileSize, &totalRead, NULL);
            CloseHandle(hFile);
            // 跳过 BOM，将 UTF-16 LE 转为 UTF-8
            int wlen = (int)((totalRead - 2) / 2);
            if (wlen <= 0) return;
            int ulen = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(data.data() + 2), wlen, NULL, 0, NULL, NULL);
            if (ulen <= 0) return;
            std::string utf8(ulen, '\0');
            WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(data.data() + 2), wlen, &utf8[0], ulen, NULL, NULL);
            hFile = CreateFileW(iniPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE) return;
            DWORD written = 0;
            BYTE bom8[3] = { 0xEF, 0xBB, 0xBF };
            WriteFile(hFile, bom8, 3, &written, NULL);
            WriteFile(hFile, utf8.data(), (DWORD)utf8.size(), &written, NULL);
            CloseHandle(hFile);
            return;
        }
        // ANSI 或其他编码，不处理
        CloseHandle(hFile);
        return;
    }
    // 文件不存在，创建新文件并写入 UTF-8 BOM
    hFile = CreateFileW(iniPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        BYTE bom8[3] = { 0xEF, 0xBB, 0xBF };
        DWORD written;
        WriteFile(hFile, bom8, 3, &written, NULL);
        CloseHandle(hFile);
    }
}

void WriteProtectedProfileStringW(const wchar_t* iniPath, const wchar_t* section, const wchar_t* key, const std::wstring& value) {
    EnsureIniUtf8(iniPath);
    if (value.empty()) { WritePrivateProfileStringW(section, key, L"", iniPath); return; }
    std::string clear = W2A(value);
    std::string protectedStr = ProtectString(clear);
    WritePrivateProfileStringW(section, key, A2W(protectedStr).c_str(), iniPath);
}

std::wstring GetProtectedProfileStringW(const wchar_t* iniPath, const wchar_t* section, const wchar_t* key, const wchar_t* def) {
    EnsureIniUtf8(iniPath);
    wchar_t buf[4096];
    GetPrivateProfileStringW(section, key, L"", buf, 4096, iniPath);
    std::string stored = W2A(buf);
    if (stored.empty()) return def;
    std::string clear = UnprotectString(stored);
    return A2W(clear);
}

// ── SMTP 邮件通知 ──
// 配置从同目录下的 settings.ini 读取，未配置则静默跳过
void SendNotificationEmail(const std::wstring& subject, const std::wstring& body, const std::wstring& saveDir, const std::wstring& iniPath) {
    wchar_t buf[4096];
    GetPrivateProfileStringW(L"Notification", L"SmtpServer", L"", buf, 4096, iniPath.c_str());
    std::wstring smtpServer = buf;
    if (smtpServer.empty()) return;

    GetPrivateProfileStringW(L"Notification", L"SmtpPort", L"25", buf, 4096, iniPath.c_str());
    int smtpPort = _wtoi(buf);
    GetPrivateProfileStringW(L"Notification", L"SmtpUser", L"", buf, 4096, iniPath.c_str());
    std::wstring smtpUser = buf;
    GetPrivateProfileStringW(L"Notification", L"SmtpPass", L"", buf, 4096, iniPath.c_str());
    std::wstring smtpPass = buf;
    GetPrivateProfileStringW(L"Notification", L"SmtpFrom", L"", buf, 4096, iniPath.c_str());
    std::wstring smtpFrom = buf;
    GetPrivateProfileStringW(L"Notification", L"SmtpTo", L"", buf, 4096, iniPath.c_str());
    std::wstring smtpTo = buf;
    if (smtpFrom.empty() || smtpTo.empty()) return;

    // 安全方案：通过环境变量传递 SMTP 密码，避免明文写入临时脚本文件
    std::wstring tempScriptPath = saveDir + L"\\sslclaw_temp_mail.ps1";
    std::string scriptContent;

    // 转义 PowerShell 脚本中的单引号
    auto EscapeSingleQuote = [](const std::wstring& s) -> std::string {
        std::string result;
        for (wchar_t c : s) {
            if (c == '\'') {
                result += "''";
            } else {
                result += W2A(std::wstring(1, c));
            }
        }
        return result;
    };

    // 密码通过环境变量传递，脚本中不出现明文密码
    scriptContent = "$ErrorActionPreference = 'Stop'\n";
    scriptContent += "$smtpPass = $env:SSLCLAW_SMTP_PASS\n";
    scriptContent += "$secpass = ConvertTo-SecureString -String $smtpPass -AsPlainText -Force\n";
    scriptContent += "$cred = New-Object System.Management.Automation.PSCredential('" + EscapeSingleQuote(smtpUser) + "', $secpass)\n";
    scriptContent += "Send-MailMessage -SmtpServer '" + EscapeSingleQuote(smtpServer) + "' -Port " + std::to_string(smtpPort) + "\n";
    scriptContent += "  -From '" + EscapeSingleQuote(smtpFrom) + "' -To '" + EscapeSingleQuote(smtpTo) + "'\n";
    scriptContent += "  -Subject '" + EscapeSingleQuote(subject) + "' -Body '" + EscapeSingleQuote(body) + "'\n";
    scriptContent += "  -Credential $cred\n";
    scriptContent += "Remove-Item Env:SSLCLAW_SMTP_PASS\n";

    // 写入临时脚本文件（原子写入）
    if (!WriteFileAtomic(W2A(tempScriptPath), scriptContent)) {
        return;
    }

    // 设置密码环境变量（仅当前进程，子进程继承）
    std::wstring envPass = L"SSLCLAW_SMTP_PASS=" + smtpPass;
    _wputenv_s(L"SSLCLAW_SMTP_PASS", smtpPass.c_str());

    // 执行临时脚本
    std::wstring cmd = L"powershell.exe -ExecutionPolicy Bypass -File \"" + tempScriptPath + L"\"";
    STARTUPINFOW si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    CreateProcessW(NULL, (wchar_t*)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) { 
        DWORD wr = WaitForSingleObject(pi.hProcess, 30000);
        if (wr == WAIT_TIMEOUT) TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess); 
        CloseHandle(pi.hThread); 
    }

    // 清理临时文件和环境变量
    DeleteFileW(tempScriptPath.c_str());
    _wputenv_s(L"SSLCLAW_SMTP_PASS", L"");
}

// ── HMAC 辅助函数（DNS API 签名用） ──
std::vector<BYTE> HmacSha1(const std::string& key, const std::string& data) {
    BCRYPT_ALG_HANDLE ha = NULL; BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCRYPT_HASH_HANDLE hh = NULL; BCryptCreateHash(ha, &hh, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    BCryptHashData(hh, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    DWORD hashLen = 0, sz2 = sizeof(hashLen); BCryptGetProperty(hh, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &sz2, 0);
    std::vector<BYTE> result(hashLen); BCryptFinishHash(hh, result.data(), hashLen, 0);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(ha, 0); return result;
}

std::vector<BYTE> HmacSha256Raw(const std::string& key, const std::string& data) {
    BCRYPT_ALG_HANDLE ha = NULL; BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCRYPT_HASH_HANDLE hh = NULL; BCryptCreateHash(ha, &hh, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    BCryptHashData(hh, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    DWORD hashLen = 0, sz2 = sizeof(hashLen); BCryptGetProperty(hh, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &sz2, 0);
    std::vector<BYTE> result(hashLen); BCryptFinishHash(hh, result.data(), hashLen, 0);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(ha, 0); return result;
}

std::vector<BYTE> HmacSha256Raw(const std::vector<BYTE>& key, const std::string& data) {
    BCRYPT_ALG_HANDLE ha = NULL; BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BCRYPT_HASH_HANDLE hh = NULL; BCryptCreateHash(ha, &hh, NULL, 0, (PUCHAR)key.data(), (ULONG)key.size(), 0);
    BCryptHashData(hh, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    DWORD hashLen = 0, sz2 = sizeof(hashLen); BCryptGetProperty(hh, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &sz2, 0);
    std::vector<BYTE> result(hashLen); BCryptFinishHash(hh, result.data(), hashLen, 0);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(ha, 0); return result;
}

std::string Sha256Hex(const std::string& data) {
    BCRYPT_ALG_HANDLE ha = NULL; BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCRYPT_HASH_HANDLE hh = NULL; BCryptCreateHash(ha, &hh, NULL, 0, NULL, 0, 0);
    BCryptHashData(hh, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    DWORD hashLen = 0, sz2 = sizeof(hashLen); BCryptGetProperty(hh, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &sz2, 0);
    std::vector<BYTE> hash(hashLen); BCryptFinishHash(hh, hash.data(), hashLen, 0);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(ha, 0);
    std::string r; char buf[3];
    for (BYTE b : hash) { sprintf_s(buf, "%02x", b); r += buf; }
    return r;
}
