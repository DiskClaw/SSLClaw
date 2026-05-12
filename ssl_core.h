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
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <vector>
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

// CA 机构（固定 Let's Encrypt）
const wchar_t* GetAcmeDirectory();
const wchar_t* GetAccountKeySuffix();

extern int g_CAIndex;  // 固定 0 (Let's Encrypt)

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

// CSR 生成
std::vector<BYTE> BuildCSR(const std::string& domain, BCRYPT_KEY_HANDLE key);

// 全局状态
extern BCRYPT_KEY_HANDLE g_AccKey;
extern std::string g_AccPubB64;
extern std::string g_AccExpB64;
extern std::string g_AccURL;

// 证书申请线程
extern bool g_Running;
extern HANDLE g_hDnsReady;  // DNS-01 手动继续事件
extern std::wstring g_WebRoot;
extern CRITICAL_SECTION g_cs;
unsigned __stdcall ApplyThread(void* param);
