# SSLClaw

Windows SSL 证书管理工具，基于 ACME 协议自动申请和续签 Let's Encrypt 免费证书。

## 界面预览

### HTTP-01 申请成功

<img width="590" height="690" alt="HTTP-01" src="https://github.com/user-attachments/assets/3a1ea4c6-e0b9-4dd2-81a9-2983baa571f7" />

### DNS-01 申请成功（Cloudflare / 阿里云 API 自动验证）

<img width="599" height="690" alt="DNS-01 Cloudflare" src="https://github.com/user-attachments/assets/28d890c2-8f6e-44ad-ab23-1a7d6695fb46" />
<img width="591" height="590" alt="DNS-01 阿里云" src="https://github.com/user-attachments/assets/fe49e463-f567-4bc9-9500-25716abf3269" />
<img width="590" height="601" alt="DNS-01 阿里云2" src="https://github.com/user-attachments/assets/2d204481-2934-442a-9232-1352489e4115" />

### 续签成功

<img width="595" height="699" alt="续签成功" src="https://github.com/user-attachments/assets/fb7a048f-5160-4cdc-bdec-1a53254a3018" />

## 功能

- **HTTP-01 验证** — 自动启动临时验证服务器或写入网站目录
- **DNS-01 验证** — 适用于内网和无 Web 服务器环境，支持通配符证书
- **DNS API 自动化** — 阿里云、腾讯云、Cloudflare 自动添加/删除 TXT 记录，也支持手动 TXT
- **正式/测试环境切换** — 先用测试环境验证，再切正式环境，避免 ACME 限速
- **自动续签** — 后台 6 小时轮询，到期前自动续签，指数退避重试
- **IIS 部署** — 自动导入证书到 Certificate Store 并更新站点绑定
- **续签脚本** — 支持前置/后置脚本，30 秒超时保护
- **系统托盘** — 关闭窗口最小化到托盘，后台续签持续运行
- **CA 连通性检测** — 实时指示灯显示 Let's Encrypt 连接状态

## 使用

1. 选择验证方式（HTTP-01 或 DNS-01）
2. 填写域名和邮箱
3. 点击"申请证书"
4. 按日志提示操作

## 编译

Visual Studio 打开 SSLClaw.sln，Release x64 编译。

## 技术栈

C++ / Win32 API 原生 GUI · CNG (BCrypt/NCrypt) 密钥管理 · WinHTTP · ACME v2
