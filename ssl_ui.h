// ssl_ui.h - SSL 证书工具 UI
#pragma once

#include <winsock2.h>
#include <windows.h>
#include <string>
#include <vector>

// UI 控件句柄
extern HWND g_hWnd;
extern HWND g_hDomain;
extern HWND g_hEmail;
extern HWND g_hBtnApply;
extern HWND g_hLog;
extern HWND g_hStatus;
extern HWND g_hSaveDirEdit;
extern HWND g_hBtnBrowse;
extern HWND g_hBtnOpen;
extern HWND g_hDaysEdit;
extern HWND g_hServer;
extern HWND g_hIP;
extern HWND g_hVerifyMode;
extern HWND g_hWebRoot;
extern HWND g_hBtnWebRootBrowse;
extern HWND g_hBtnWebRootOpen;
extern HWND g_hCA;
extern HWND g_hCAEnv;   // CA 环境选择(生产/测试)
extern int g_CAEnvIndex; // 0=生产 1=测试
extern HWND g_hCAInd;  // CA 连接指示灯
extern HWND g_hCAStatus; // CA 状态文字
extern HWND g_hWildcard;  // 通配符复选框（DNS-01 专用）
extern HWND g_RenewWnd;   // 续签窗口

// CA 指示灯状态
extern int g_caStatus;

// IP 轮播
extern std::vector<std::wstring> g_ipList;
extern int g_ipIndex;

// 全局状态
extern std::wstring g_SaveDir;
extern std::wstring g_IniPath;

// 回调函数
void Log(const wchar_t* fmt, ...);
void LogUI(const wchar_t* fmt, ...);
void SetStatus(const wchar_t* t);

// 线程安全 UI 操作（后台线程必须用这些，自动判断是否需要 PostMessage）
#define WM_SAFE_SETSTATUS   (WM_USER + 0x202)
#define WM_SAFE_ENABLE      (WM_USER + 0x203)
#define WM_SAFE_SETTEXT     (WM_USER + 0x204)
#define WM_SAFE_INVALIDATE  (WM_USER + 0x205)

void SafeSetStatus(const wchar_t* t);
void SafeEnableWindow(HWND h, BOOL enable);
void SafeSetWindowText(HWND h, const wchar_t* t);
void SafeInvalidateRect(HWND h);

// UI 函数
void BrowseDir();
void SyncWebRootVis();
void ShowVerifySteps(int vm);
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l);
void ShowDnsConfigDialog(HWND hwParent, const std::wstring& overrideDomain = std::wstring());

// DNS API 配置（供 ssl_core.cpp 读取）
extern int g_DnsProvider;
extern std::wstring g_DnsApiId;
extern std::wstring g_DnsApiSecret;
void LoadDnsConfig();
void LoadDnsConfigForDomain(const std::wstring& domain);
void SaveDnsConfigForDomain(const std::wstring& domain);

// 托盘
extern UINT WM_TASKBARCREATED;
