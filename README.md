# 软件如图：
<img width="590" height="690" alt="ScreenShot_2026-05-12_151858_435" src="https://github.com/user-attachments/assets/3a1ea4c6-e0b9-4dd2-81a9-2983baa571f7" />
<img width="589" height="688" alt="ScreenShot_2026-05-13_153521_719" src="https://github.com/user-attachments/assets/d1070bed-c0b0-4c79-ab84-f12ff645e920" />

# SSLClaw

Windows SSL 证书申请工具，基于 ACME 协议自动申请 Let's Encrypt 免费SSL证书。

## 功能

- **HTTP-01 验证**：自动启动临时验证服务器或写入网站目录
- **DNS-01 验证**：适用于内网/无 Web 服务器环境，支持通配符证书
- **CA 连通性检测**：实时指示灯显示 Let's Encrypt 连接状态
- **IP 轮播显示**：多网卡时自动轮播显示有效 IP 地址

## 编译

使用 Visual Studio 打开 `SSLClaw.sln`，选择 Release x64 编译。

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
