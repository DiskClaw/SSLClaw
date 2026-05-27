// ssl_keyfmt.h - 私钥格式转换（PKCS#1 / PKCS#8）
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

// BCRYPT_RSAFULLPRIVATE_BLOB → PKCS#8 PEM（BEGIN PRIVATE KEY）
std::string RsaFullBlobToPkcs8Pem(const std::vector<BYTE>& blob);

// BCRYPT_RSAFULLPRIVATE_BLOB → PKCS#8 原始 DER
std::vector<BYTE> RsaFullBlobToPkcs8Der(const std::vector<BYTE>& blob);

// BCRYPT_RSAFULLPRIVATE_BLOB → PKCS#1 PEM（BEGIN RSA PRIVATE KEY）
std::string RsaFullBlobToPkcs1Pem(const std::vector<BYTE>& blob);

// PKCS#8 PEM → PKCS#1 PEM（CryptDecodeObjectEx 两步解码）
std::string Pkcs8PemToPkcs1Pem(const std::string& pkcs8Pem);

// B64Pem 由 ssl_core.cpp 提供，此处仅声明
extern std::string B64Pem(const std::vector<BYTE>& d);
