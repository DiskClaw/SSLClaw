// main.cpp - SSL 证书申请工具入口
#include "ssl_ui.h"
#include "ssl_core.h"

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma warning(suppress:28251) // WinMain 批注与 SDK 声明不一致，已知问题
int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow) {
    HRESULT hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        MessageBoxW(NULL, L"COM 初始化失败，部分功能可能异常", L"SSLClaw", MB_ICONWARNING);
    }
    WSADATA wd; if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) {
        MessageBoxW(NULL, L"网络初始化失败，无法运行", L"SSLClaw", MB_ICONERROR);
        CoUninitialize(); return 1;
    }

    // ini 放 exe 同目录
    wchar_t exePath[MAX_PATH]; GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t* slash = wcsrchr(exePath, L'\\');
    if (slash) { slash[1] = 0; g_IniPath = exePath; g_IniPath += L"sslclaw.ini"; }

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(0, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(245, 245, 245));
    wc.lpszClassName = L"S";
    RegisterClassExW(&wc);

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    g_hWnd = CreateWindowExW(0, L"S", L"SSLClaw 证书申请工具",
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        (sw - 480) / 2, max(0, (sh - 560) / 2), 480, 560, 0, 0, hInstance, 0);

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

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
        // CA 固定 Let's Encrypt，忽略 ini 中的旧 CA 设置
        // (ZeroSSL/Buypass 已移除)
    }

    // 根据当前验证方式显示步骤提示
    ShowVerifySteps((int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0));

    MSG msg;
    while (GetMessageW(&msg, 0, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }

    // 释放全局 ACME 密钥
    if (g_AccKey) { BCryptDestroyKey(g_AccKey); g_AccKey = NULL; }

    WSACleanup();
    CoUninitialize();
    return 0;
}
