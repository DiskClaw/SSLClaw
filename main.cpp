// main.cpp - SSL 证书申请工具入口
#include "ssl_ui.h"
#include "ssl_core.h"
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

static LONG WINAPI SSLClawExceptionFilter(EXCEPTION_POINTERS* ep) {
    wchar_t path[MAX_PATH]; GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t* p = wcsrchr(path, L'\\'); if (p) *p = 0;
    wcscat_s(path, L"\\crash.log");
    HANDLE hf = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        SYSTEMTIME st; GetLocalTime(&st);
        wchar_t line[256];
        int n = swprintf_s(line, L"[%04d-%02d-%02d %02d:%02d:%02d] Exception code: 0x%08X at 0x%p\r\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
        DWORD w; WriteFile(hf, line, n * sizeof(wchar_t), &w, NULL);
        CloseHandle(hf);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static BOOL SafeDispatchMsg(MSG* pMsg) {
    __try {
        TranslateMessage(pMsg);
        DispatchMessageW(pMsg);
        return TRUE;
    } __except(SSLClawExceptionFilter(GetExceptionInformation())) {
        return TRUE;
    }
}

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma warning(suppress:28251) // WinMain 批注与 SDK 声明不一致，已知问题
int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow) {
    SetUnhandledExceptionFilter(SSLClawExceptionFilter);
    // 检测命令行续签模式
    {
        int argc; LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        bool renewMode = false;
        for (int i = 1; i < argc; i++) {
            if (wcscmp(argv[i], L"--renew") == 0) {
                renewMode = true; break;
            }
        }
        LocalFree(argv);
        if (renewMode) {
            HRESULT hr2 = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
            WSADATA wd2; WSAStartup(MAKEWORD(2, 2), &wd2);
            int ret = RunRenewalMode();
            WSACleanup();
            if (SUCCEEDED(hr2)) CoUninitialize();
            return ret;
        }
    }

    // GUI 模式进程唯一：防止多开
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"SSLClaw_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND existing = FindWindowW(L"S", NULL);
        if (existing) { SetForegroundWindow(existing); ShowWindow(existing, SW_RESTORE); }
        return 0;
    }

    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    bool comInitialized = SUCCEEDED(hr);
    if (FAILED(hr)) {
        MessageBoxW(NULL, L"COM 初始化失败，部分功能可能异常", L"SSLClaw", MB_ICONWARNING);
    }
    WSADATA wd; if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
        MessageBoxW(NULL, L"网络初始化失败，无法运行", L"SSLClaw", MB_ICONERROR);
        if (comInitialized) CoUninitialize();
        return 1;
    }

    // ini 放 exe 同目录
    wchar_t exePath[MAX_PATH]; GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (slash) { slash[1] = 0; g_IniPath = exePath; g_IniPath += L"sslclaw.ini"; }

    // 日志文件放 exe 同目录
    extern std::wstring g_LogFilePath;
    g_LogFilePath = exePath; g_LogFilePath += L"sslclaw.log";

    // 先确保 sslclaw.ini 是 UTF-16 LE BOM，再进行任何 INI 操作
    EnsureIniUtf16(g_IniPath.c_str());

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(1));
    wc.hIconSm = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(1), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
    wc.hCursor = LoadCursor(0, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(245, 245, 245));
    wc.lpszClassName = L"S";
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    g_hWnd = CreateWindowExW(WS_EX_CONTEXTHELP, L"S", L"SSLClaw 证书申请工具",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_MINIMIZEBOX & ~WS_THICKFRAME,
        (sw - 480) / 2, max(0, (sh - 560) / 2), 480, 560, 0, 0, hInstance, 0);

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    // 注册任务栏重建消息（Explorer 崩溃后托盘图标恢复用）
    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");

    // 检测管理员状态并更新标题
    {
        wchar_t title[64];
        GetWindowTextW(g_hWnd, title, 64);
        wcscat_s(title, IsUserAnAdmin() ? L" [管理员]" : L" [非管理员]");
        SetWindowTextW(g_hWnd, title);
    }

    // 加载配置
    {
        wchar_t buf[512];
        if (GetPrivateProfileStringW(L"SSLClaw", L"Domain", L"", buf, 512, g_IniPath.c_str()))
            SetWindowTextW(g_hDomain, buf);
        if (GetPrivateProfileStringW(L"SSLClaw", L"Email", L"", buf, 512, g_IniPath.c_str()))
            SetWindowTextW(g_hEmail, buf);
        if (GetPrivateProfileStringW(L"SSLClaw", L"ServerType", L"0", buf, 512, g_IniPath.c_str()))
            SendMessageW(g_hServer, CB_SETCURSEL, _wtoi(buf), 0);
        if (GetPrivateProfileStringW(L"SSLClaw", L"SaveDir", L"", buf, 512, g_IniPath.c_str())) {
            g_SaveDir = buf;
            SetWindowTextW(g_hSaveDirEdit, buf);
        }
        if (GetPrivateProfileStringW(L"SSLClaw", L"VerifyMode", L"0", buf, 512, g_IniPath.c_str()))
            SendMessageW(g_hVerifyMode, CB_SETCURSEL, _wtoi(buf), 0);
        SyncWebRootVis();
        if (GetPrivateProfileStringW(L"SSLClaw", L"WebRoot", L"", buf, 512, g_IniPath.c_str())) {
            g_WebRoot = buf;
            SetWindowTextW(g_hWebRoot, buf);
        }
        // 恢复通配符复选框
        int wc = GetPrivateProfileIntW(L"SSLClaw", L"Wildcard", 0, g_IniPath.c_str());
        SendMessageW(g_hWildcard, BM_SETCHECK, wc ? BST_CHECKED : BST_UNCHECKED, 0);
        // 加载 DNS API 配置（按当前域名加载，无域名则加载默认）
        {
            wchar_t domainBuf[512];
            GetWindowTextW(g_hDomain, domainBuf, 512);
            if (domainBuf[0]) LoadDnsConfigForDomain(domainBuf);
            else LoadDnsConfig();
        }
    }

    // 根据当前验证方式显示步骤提示
    ShowVerifySteps((int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0));

    // 加载配置
    {
        std::vector<RenewalRecord> records;
        LoadRenewalRecords(records);
        bool hasAutoRenew = false;
        for (auto& r : records) if (r.autoRenew) { hasAutoRenew = true; break; }
        if (hasAutoRenew) StartRenewalBackgroundThread();
    }

    MSG msg;
    while (GetMessageW(&msg, 0, 0, 0)) {
        SafeDispatchMsg(&msg);
    }

    // 停止后台续签线程
    StopRenewalBackgroundThread();

    // 释放全局 ACME 密钥
    if (g_AccKey) { BCryptDestroyKey(g_AccKey); g_AccKey = NULL; }

    WSACleanup();
    CoUninitialize();
    return 0;
}
