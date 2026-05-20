# 软件如图：
## http-01 成功界面
<img width="590" height="690" alt="ScreenShot_2026-05-12_151858_435" src="https://github.com/user-attachments/assets/3a1ea4c6-e0b9-4dd2-81a9-2983baa571f7" />

## cloudflare和阿里云 api自动申请成功界面 （可手工txt和自动api注册）
<img width="599" height="690" alt="ScreenShot_2026-05-20_140351_678" src="https://github.com/user-attachments/assets/28d890c2-8f6e-44ad-ab23-1a7d6695fb46" />

# SSLClaw

Windows SSL 证书管理工具，基于 ACME 协议自动申请和续签 Let's Encrypt 免费证书。

## 功能

- **HTTP-01 验证**：自动启动临时验证服务器或写入网站目录
- **DNS-01 验证**：适用于内网/无 Web 服务器环境，支持通配符证书
- **DNS API 自动化**：支持阿里云、腾讯云、Cloudflare 自动添加/删除 TXT 记录
- **CA 连通性检测**：实时指示灯显示 Let's Encrypt 连接状态
- **IP 轮播显示**：多网卡时自动轮播显示有效 IP 地址
- **自动续签**：后台线程 6 小时轮询，到期前自动续签，指数退避重试
- **IIS 部署**：自动导入证书到 Certificate Store 并更新 IIS 站点绑定
- **系统托盘**：关闭窗口最小化到托盘，后台续签持续运行
- **续签脚本**：支持前置/后置脚本执行，30 秒超时保护

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
