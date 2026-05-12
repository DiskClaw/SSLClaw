// ssl_keyfmt.cpp - 私钥格式转换（PKCS#1 / PKCS#8）
// PKCS#1: 手动构建 ASN.1 DER（最可靠，不依赖 CryptEncodeObjectEx 的不确定行为）
// PKCS#8: CryptEncodeObjectEx 两轮编码
#include "ssl_keyfmt.h"

#ifndef szOID_RSA_RSA
#define szOID_RSA_RSA "1.2.840.113549.1.1.1"
#endif

// ===== ASN.1 DER 编码辅助 =====

// 编码 ASN.1 长度字段，返回字节数
static int DerLenEncode(size_t len, BYTE* out) {
    if (len < 128) {
        out[0] = (BYTE)len;
        return 1;
    } else if (len < 256) {
        out[0] = 0x81; out[1] = (BYTE)len;
        return 2;
    } else {
        out[0] = 0x82; out[1] = (BYTE)(len >> 8); out[2] = (BYTE)len;
        return 3;
    }
}

// 大端序字节 → ASN.1 INTEGER (0x02 + 长度 + 数据，高位为1时补前导0)
static std::vector<BYTE> DerInteger(const BYTE* data, DWORD len) {
    // 跳过前导零
    DWORD off = 0;
    while (off < len && data[off] == 0) off++;
    DWORD contentLen = len - off;
    if (contentLen == 0) { contentLen = 1; off = len - 1; } // 全零则为单字节0
    bool needPad = (data[off] & 0x80) != 0;
    DWORD totalData = contentLen + (needPad ? 1 : 0);

    BYTE hdr[4];
    hdr[0] = 0x02; // INTEGER tag
    int hl = DerLenEncode(totalData, hdr + 1);

    std::vector<BYTE> r;
    r.reserve(1 + hl + totalData);
    r.insert(r.end(), hdr, hdr + 1 + hl);
    if (needPad) r.push_back(0x00);
    r.insert(r.end(), data + off, data + len);
    return r;
}

// 多个 DER 元素 → SEQUENCE (0x30 + 长度 + 数据)
static std::vector<BYTE> DerSequence(const std::vector<std::vector<BYTE>>& items) {
    size_t innerLen = 0;
    for (auto& it : items) innerLen += it.size();

    BYTE hdr[4];
    hdr[0] = 0x30; // SEQUENCE tag
    int hl = DerLenEncode(innerLen, hdr + 1);

    std::vector<BYTE> r;
    r.reserve(1 + hl + innerLen);
    r.insert(r.end(), hdr, hdr + 1 + hl);
    for (auto& it : items) r.insert(r.end(), it.begin(), it.end());
    return r;
}

// ===== BCRYPT_RSAFULLPRIVATE_BLOB 布局 =====
// BCRYPT_RSAKEY_BLOB 头 (6 x ULONG)
// PublicExponent[cbPublicExp]
// Modulus[cbModulus]
// Prime1[cbPrime1]
// Prime2[cbPrime2]
// Exponent1[cbPrime1]  (dp)
// Exponent2[cbPrime2]  (dq)
// Coefficient[cbPrime1] (qInv)
// PrivateExponent[cbModulus] (d)

struct RsaFullFields {
    const BYTE* pubExp;     // e
    const BYTE* modulus;    // n
    const BYTE* prime1;     // p
    const BYTE* prime2;     // q
    const BYTE* exponent1;  // dp
    const BYTE* exponent2;  // dq
    const BYTE* coefficient;// qInv
    const BYTE* privExp;    // d
    DWORD cbPubExp = 0, cbModulus = 0, cbPrime1 = 0, cbPrime2 = 0;
};

static bool ParseRsaFullBlob(const std::vector<BYTE>& blob, RsaFullFields& f) {
    if (blob.size() < sizeof(BCRYPT_RSAKEY_BLOB)) return false;
    BCRYPT_RSAKEY_BLOB* hdr = (BCRYPT_RSAKEY_BLOB*)blob.data();
    // 检查 Magic
    if (hdr->Magic != 0x33415352) return false; // BCRYPT_RSAFULLPRIVATE_MAGIC

    const BYTE* p = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    f.cbPubExp  = hdr->cbPublicExp;
    f.cbModulus = hdr->cbModulus;
    f.cbPrime1  = hdr->cbPrime1;
    f.cbPrime2  = hdr->cbPrime2;

    f.pubExp     = p; p += f.cbPubExp;
    f.modulus    = p; p += f.cbModulus;
    f.prime1     = p; p += f.cbPrime1;
    f.prime2     = p; p += f.cbPrime2;
    f.exponent1  = p; p += f.cbPrime1;
    f.exponent2  = p; p += f.cbPrime2;
    f.coefficient= p; p += f.cbPrime1;
    f.privExp    = p;
    return true;
}

// ===== 公开接口 =====

// BCRYPT_RSAFULLPRIVATE_BLOB → PKCS#1 PEM
// 手动构建 PKCS#1 RSAPrivateKey ASN.1 DER
//   SEQUENCE { version, n, e, d, p, q, dp, dq, qInv }
std::string RsaFullBlobToPkcs1Pem(const std::vector<BYTE>& blob) {
    RsaFullFields f;
    if (!ParseRsaFullBlob(blob, f)) return "";

    BYTE ver0 = 0;
    auto der = DerSequence({
        DerInteger(&ver0, 1),           // version = 0
        DerInteger(f.modulus, f.cbModulus),   // n
        DerInteger(f.pubExp, f.cbPubExp),     // e
        DerInteger(f.privExp, f.cbModulus),   // d
        DerInteger(f.prime1, f.cbPrime1),     // p
        DerInteger(f.prime2, f.cbPrime2),     // q
        DerInteger(f.exponent1, f.cbPrime1),  // dp
        DerInteger(f.exponent2, f.cbPrime2),  // dq
        DerInteger(f.coefficient, f.cbPrime1) // qInv
    });

    std::string bp = B64Pem(der);
    return "-----BEGIN RSA PRIVATE KEY-----\r\n" + bp + "\r\n-----END RSA PRIVATE KEY-----\r\n";
}

// BCRYPT_RSAFULLPRIVATE_BLOB → PKCS#8 PEM
// 先手动构建 PKCS#1 DER，再包装 PKCS#8
std::string RsaFullBlobToPkcs8Pem(const std::vector<BYTE>& blob) {
    RsaFullFields f;
    if (!ParseRsaFullBlob(blob, f)) return "";

    // 先构建 PKCS#1 DER
    BYTE ver0 = 0;
    auto pkcs1Der = DerSequence({
        DerInteger(&ver0, 1),
        DerInteger(f.modulus, f.cbModulus),
        DerInteger(f.pubExp, f.cbPubExp),
        DerInteger(f.privExp, f.cbModulus),
        DerInteger(f.prime1, f.cbPrime1),
        DerInteger(f.prime2, f.cbPrime2),
        DerInteger(f.exponent1, f.cbPrime1),
        DerInteger(f.exponent2, f.cbPrime2),
        DerInteger(f.coefficient, f.cbPrime1)
    });

    // PKCS#8 包装: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING(PKCS#1) }
    // AlgorithmIdentifier: SEQUENCE { OID rsaEncryption, NULL }
    static const BYTE rsaAlgId[] = {
        0x30, 0x0D,                                           // SEQUENCE 13
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,     // OID 1.2.840.113549.1.1.1
        0x01, 0x01, 0x01,                                     // (rsaEncryption)
        0x05, 0x00                                            // NULL
    };

    // version = 0
    static const BYTE pkcs8Ver[] = { 0x02, 0x01, 0x00 }; // INTEGER 0

    // OCTET STRING 包装 PKCS#1
    BYTE octHdr[4];
    octHdr[0] = 0x04;
    int ohl = DerLenEncode(pkcs1Der.size(), octHdr + 1);
    std::vector<BYTE> octStr;
    octStr.insert(octStr.end(), octHdr, octHdr + 1 + ohl);
    octStr.insert(octStr.end(), pkcs1Der.begin(), pkcs1Der.end());

    // 外层 SEQUENCE
    size_t innerLen = sizeof(pkcs8Ver) + sizeof(rsaAlgId) + octStr.size();
    std::vector<BYTE> pkcs8Der;
    BYTE seqHdr[4];
    seqHdr[0] = 0x30;
    int shl = DerLenEncode(innerLen, seqHdr + 1);
    pkcs8Der.reserve(1 + shl + innerLen);
    pkcs8Der.insert(pkcs8Der.end(), seqHdr, seqHdr + 1 + shl);
    pkcs8Der.insert(pkcs8Der.end(), pkcs8Ver, pkcs8Ver + sizeof(pkcs8Ver));
    pkcs8Der.insert(pkcs8Der.end(), rsaAlgId, rsaAlgId + sizeof(rsaAlgId));
    pkcs8Der.insert(pkcs8Der.end(), octStr.begin(), octStr.end());

    std::string bp = B64Pem(pkcs8Der);
    return "-----BEGIN PRIVATE KEY-----\r\n" + bp + "\r\n-----END PRIVATE KEY-----\r\n";
}

// PKCS#8 PEM → PKCS#1 PEM
// 方案: 微软官方 CryptDecodeObjectEx 两步解码法
//   第一步: CryptDecodeObjectEx(PKCS_PRIVATE_KEY_INFO) 剥 PKCS#8 外壳
//   第二步: PrivateKey.pbData 就是 PKCS#1 DER，直接 Base64 包装
std::string Pkcs8PemToPkcs1Pem(const std::string& pkcs8Pem) {
    // 剥离 PEM 头尾，Base64 → DER
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
    DWORD cbDer = 0;
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, NULL, &cbDer, NULL, NULL))
        return "";
    std::vector<BYTE> der(cbDer);
    if (!CryptStringToBinaryA(b64.c_str(), (DWORD)b64.size(), CRYPT_STRING_BASE64, der.data(), &cbDer, NULL, NULL))
        return "";

    // 第一步: PKCS#8 DER → CRYPT_PRIVATE_KEY_INFO（剥外层）
    PCRYPT_PRIVATE_KEY_INFO pInfo = NULL;
    DWORD cbInfo = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
            der.data(), cbDer, CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            0, (void**)&pInfo, &cbInfo))
        return "";

    // 第二步: 内层 PrivateKey.pbData 就是 PKCS#1 DER
    std::string bp = B64Pem(std::vector<BYTE>(pInfo->PrivateKey.pbData, pInfo->PrivateKey.pbData + pInfo->PrivateKey.cbData));
    LocalFree(pInfo);
    return "-----BEGIN RSA PRIVATE KEY-----\r\n" + bp + "\r\n-----END RSA PRIVATE KEY-----\r\n";
}
