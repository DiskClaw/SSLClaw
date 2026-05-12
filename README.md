# SSLClaw

Windows SSL 证书申请工具，基于 ACME 协议自动申请 Let's Encrypt 免费证书。

## 功能

- **HTTP-01 验证**：自动启动临时验证服务器或写入网站目录
- **DNS-01 验证**：适用于内网/无 Web 服务器环境，支持通配符证书
- **CA 连通性检测**：实时指示灯显示 Let's Encrypt 连接状态
- **IP 轮播显示**：多网卡时自动轮播显示有效 IP 地址

## 编译

需要 MSVC x64 编译环境：

```bat
_build.bat
```

或使用 Visual Studio 打开 `SSLClaw.sln`。

## 使用

1. 选择验证方式（HTTP-01 或 DNS-01）
2. 填写域名和邮箱
3. 点击"申请证书"
4. 按日志提示操作

## 技术栈

- C++ / Win32 API 原生 GUI
- CNG (BCrypt/NCrypt) 密钥管理
- WinHTTP 网络请求
- ACME v2 协议
