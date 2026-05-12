// ssl_ui.cpp - SSL 证书工具 UI 实现
#include "ssl_ui.h"
#include "ssl_core.h"
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <process.h>

// UI 控件句柄
HWND g_hWnd = NULL;
HWND g_hDomain = NULL;
HWND g_hEmail = NULL;
HWND g_hBtnApply = NULL;
HWND g_hLog = NULL;
HWND g_hStatus = NULL;
HWND g_hSaveDirEdit = NULL;
HWND g_hBtnBrowse = NULL;
HWND g_hBtnOpen = NULL;
HWND g_hDaysEdit = NULL;
HWND g_hServer = NULL;
HWND g_hIP = NULL;
HWND g_hVerifyMode = NULL;
HWND g_hWebRoot = NULL;
HWND g_hBtnWebRootBrowse = NULL;
HWND g_hBtnWebRootOpen = NULL;
HWND g_hCA = NULL;       // CA 名称文本
HWND g_hCAInd = NULL;    // CA 连接指示灯
HWND g_hCAStatus = NULL; // CA 状态文字
HWND g_hWildcard = NULL; // 通配符复选框

// CA 指示灯状态: 0=检测中(灰) 1=可连接(绿) 2=不可连接(红)
int g_caStatus = 0;

// IP 轮播
std::vector<std::wstring> g_ipList;
int g_ipIndex = 0;
#define IP_TIMER_ID 1001

// 全局状态
std::wstring g_SaveDir;
std::wstring g_IniPath;

// 验证步骤提示（避免 main.cpp 与 ssl_ui.cpp 重复）
void ShowVerifySteps(int vm) {
    if (vm == 0) {
        Log(L"HTTP-01 验证步骤：");
        Log(L"1. 填写域名");
        Log(L"2. 填写邮箱（可选填，用于接收到期提醒）");
        Log(L"3. 点击\"申请证书\"");
        Log(L"4. 若本机80端口空闲，自动启动临时验证服务器");
        Log(L"5. 若80端口被占用（Web服务器运行中），需填写网站目录（即 index.html 所在文件夹）");
        Log(L"6. CA 完成验证后自动签发证书");
        Log(L"");
        Log(L"说明: 验证时域名 A 记录需指向本机");
    } else {
        Log(L"DNS-01 验证步骤：");
        Log(L"1. 填写域名");
        Log(L"2. 填写邮箱（可选填，用于接收到期提醒）");
        Log(L"3. 日志栏显示 TXT 记录值（自动生成）");
        Log(L"4. 登录域名 DNS 管理后台");
        Log(L"5. 添加 DNS TXT 记录：");
        Log(L"   主机记录: _acme-challenge");
        Log(L"   记录类型: TXT");
        Log(L"   记录值:  日志栏显示的值（区分大小写）");
        Log(L"6. 等待 DNS 记录生效（通常需数分钟）");
        Log(L"7. 点击「继续验证」按钮，工具自动验证并签发证书");
        Log(L"");
        Log(L"说明: 无需公网访问，适用于内网或无 Web 服务器环境");
    }
}

// 日志输出
void Log(const wchar_t* fmt, ...) {
    wchar_t buf[4096]; va_list va; va_start(va, fmt);
    _vsnwprintf_s(buf, sizeof(buf) / sizeof(wchar_t), fmt, va); va_end(va);
    int len = GetWindowTextLengthW(g_hLog);
    if (len > 0) {
        // 追加模式：在末尾插入新文本
        SendMessageW(g_hLog, EM_SETSEL, len, len);
        std::wstring msg = buf;
        msg += L"\r\n";
        SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)msg.c_str());
    } else {
        // 编辑框为空，直接设置
        std::wstring msg = buf;
        msg += L"\r\n";
        SetWindowTextW(g_hLog, msg.c_str());
        SendMessageW(g_hLog, EM_SETSEL, msg.size(), msg.size());
    }
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

// 设置状态栏
void SetStatus(const wchar_t* t) { SetWindowTextW(g_hStatus, t); }

// 根据验证模式显示/隐藏网站根目录行及通配符选项
void SyncWebRootVis() {
    int vm = (int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0);
    int show = (vm == 0) ? SW_SHOW : SW_HIDE;
    ShowWindow(GetDlgItem(g_hWnd, 28), show);
    ShowWindow(g_hWebRoot, show);
    ShowWindow(g_hBtnWebRootBrowse, show);
    ShowWindow(g_hBtnWebRootOpen, show);
    // 通配符复选框仅在 DNS-01 时显示
    int showWild = (vm == 1) ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hWildcard, showWild);
    if (vm != 1 && g_hWildcard)
        SendMessageW(g_hWildcard, BM_SETCHECK, BST_UNCHECKED, 0);
}

// IFileDialog 事件回调，首次居中
class DlgCenterEvents : public IFileDialogEvents {
    HWND m_owner;
    DWORD m_cookie;
    IFileDialog* m_pfd;
    bool m_done;
public:
    DlgCenterEvents(HWND owner, IFileDialog* pfd)
        : m_owner(owner), m_cookie(0), m_pfd(pfd), m_done(false) {}
    void Advise() { m_pfd->Advise(this, &m_cookie); }
    void Unadvise() { if (m_cookie) { m_pfd->Unadvise(m_cookie); m_cookie = 0; } }
    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) {
        if (riid == IID_IUnknown || riid == IID_IFileDialogEvents) { *ppv = this; return S_OK; }
        *ppv = NULL; return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() { return 2; }
    STDMETHODIMP_(ULONG) Release() { return 1; }
    // IFileDialogEvents
    STDMETHODIMP OnFileOk(IFileDialog*) { return S_OK; }
    STDMETHODIMP OnFolderChanging(IFileDialog*, IShellItem*) { return S_OK; }
    STDMETHODIMP OnFolderChange(IFileDialog* pfd) {
        if (m_done) return S_OK;
        m_done = true;
        Unadvise();
        IOleWindow* pow = NULL;
        if (SUCCEEDED(pfd->QueryInterface(IID_PPV_ARGS(&pow)))) {
            HWND hDlg = NULL;
            if (SUCCEEDED(pow->GetWindow(&hDlg)) && hDlg) {
                RECT rd, ro; GetWindowRect(hDlg, &rd); GetWindowRect(m_owner, &ro);
                int x = ro.left + (ro.right - ro.left - (rd.right - rd.left)) / 2;
                int y = ro.top + (ro.bottom - ro.top - (rd.bottom - rd.top)) / 2;
                SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
            }
            pow->Release();
        }
        return S_OK;
    }
    STDMETHODIMP OnSelectionChange(IFileDialog*) { return S_OK; }
    STDMETHODIMP OnShareViolation(IFileDialog*, IShellItem*, FDE_SHAREVIOLATION_RESPONSE*) { return S_OK; }
    STDMETHODIMP OnTypeChange(IFileDialog*) { return S_OK; }
    STDMETHODIMP OnOverwrite(IFileDialog*, IShellItem*, FDE_OVERWRITE_RESPONSE*) { return S_OK; }
};

static bool PickFolder(HWND owner, const wchar_t* title, const std::wstring& defaultPath, std::wstring& outPath) {
    IFileDialog* pfd = NULL;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&pfd)))) return false;
    pfd->SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_DONTADDTORECENT);
    pfd->SetTitle(title);
    // 固定 GUID，用户拖小后系统记住尺寸和位置
    pfd->SetClientGuid({ 0xa1b2c3d4, 0xe5f6, 0x4a7b, { 0x8c, 0x9d, 0x0e, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d } });
    if (!defaultPath.empty()) {
        IShellItem* psi = NULL;
        if (SUCCEEDED(SHCreateItemFromParsingName(defaultPath.c_str(), NULL, IID_PPV_ARGS(&psi)))) {
            pfd->SetDefaultFolder(psi);
            psi->Release();
        }
    }
    // 首次弹出居中：ini 中无标记则居中，之后由系统记住位置
    bool needCenter = (GetPrivateProfileIntW(L"SSLClaw", L"FolderDlgPos", 0, g_IniPath.c_str()) == 0);
    DlgCenterEvents* evt = NULL;
    if (needCenter) {
        evt = new DlgCenterEvents(owner, pfd);
        evt->Advise();
    }
    HRESULT hr = pfd->Show(owner);
    if (evt) { evt->Unadvise(); delete evt; }
    if (needCenter && SUCCEEDED(hr))
        WritePrivateProfileStringW(L"SSLClaw", L"FolderDlgPos", L"1", g_IniPath.c_str());
    if (FAILED(hr)) { pfd->Release(); return false; }
    IShellItem* psiResult = NULL;
    hr = pfd->GetResult(&psiResult);
    pfd->Release();
    if (FAILED(hr)) return false;
    LPWSTR pPath = NULL;
    hr = psiResult->GetDisplayName(SIGDN_FILESYSPATH, &pPath);
    psiResult->Release();
    if (FAILED(hr)) return false;
    outPath = pPath;
    CoTaskMemFree(pPath);
    return true;
}

void BrowseDir() {
    wchar_t dt[MAX_PATH];
            GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
    if (dt[0]) g_SaveDir = dt;
    std::wstring out;
    if (PickFolder(g_hWnd, L"选择证书保存目录", g_SaveDir, out)) {
        g_SaveDir = out;
        SetWindowTextW(g_hSaveDirEdit, out.c_str());
    }
}

// 窗口过程
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        HFONT f = CreateFontW(18, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, PROOF_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
        HFONT fm = CreateFontW(17, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, PROOF_QUALITY,
            FIXED_PITCH | FF_MODERN, L"Consolas");

        CreateWindowW(L"STATIC", L"域名", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)20, 0, 0);
        SendMessageW(GetDlgItem(h, 20), WM_SETFONT, (WPARAM)f, 0);
        g_hDomain = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hDomain, WM_SETFONT, (WPARAM)f, 0);

        CreateWindowW(L"STATIC", L"邮箱", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)27, 0, 0);
        SendMessageW(GetDlgItem(h, 27), WM_SETFONT, (WPARAM)f, 0);
        g_hEmail = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hEmail, WM_SETFONT, (WPARAM)f, 0);

        CreateWindowW(L"STATIC", L"CA机构", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)29, 0, 0);
        SendMessageW(GetDlgItem(h, 29), WM_SETFONT, (WPARAM)f, 0);
        g_hCA = CreateWindowW(L"STATIC", L"Let's Encrypt", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hCA, WM_SETFONT, (WPARAM)f, 0);
        g_hCAStatus = CreateWindowW(L"STATIC", L"检测中...", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)31, 0, 0);
        SendMessageW(g_hCAStatus, WM_SETFONT, (WPARAM)f, 0);
        g_hCAInd = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 0, 0, h, (HMENU)30, 0, 0);

        // 启动后台线程检测 CA 连接
        HANDLE hCheck = (HANDLE)_beginthreadex(0, 0, [](void*)->unsigned {
            DWORD status = 0;
            HttpJson(L"https://acme-v02.api.letsencrypt.org/directory", L"GET", NULL, 0, NULL, NULL, &status);
            g_caStatus = (status == 200) ? 1 : 2;
            if (g_hCAStatus) SetWindowTextW(g_hCAStatus, g_caStatus == 1 ? L"已连接" : L"不可达");
            if (g_hCAInd) InvalidateRect(g_hCAInd, NULL, TRUE);
            return 0;
        }, 0, 0, 0);
        // CA 检测线程: lambda 已包含 return 0
        if (hCheck) CloseHandle(hCheck);

        CreateWindowW(L"STATIC", L"服务器", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)25, 0, 0);
        SendMessageW(GetDlgItem(h, 25), WM_SETFONT, (WPARAM)f, 0);
        g_hServer = CreateWindowW(L"COMBOBOX", 0, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hServer, WM_SETFONT, (WPARAM)f, 0);
        for (auto* s : { L"Apache",L"Nginx",L"IIS",L"HAProxy",L"Tomcat",L"Caddy",L"通用" })
            SendMessageW(g_hServer, CB_ADDSTRING, 0, (LPARAM)s);
        SendMessageW(g_hServer, CB_SETCURSEL, 0, 0);

        CreateWindowW(L"STATIC", L"验证方式", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)26, 0, 0);
        SendMessageW(GetDlgItem(h, 26), WM_SETFONT, (WPARAM)f, 0);
        g_hVerifyMode = CreateWindowW(L"COMBOBOX", 0, WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hVerifyMode, WM_SETFONT, (WPARAM)f, 0);
        SendMessageW(g_hVerifyMode, CB_ADDSTRING, 0, (LPARAM)L"HTTP-01");
        SendMessageW(g_hVerifyMode, CB_ADDSTRING, 0, (LPARAM)L"DNS-01");
        SendMessageW(g_hVerifyMode, CB_SETCURSEL, 0, 0);

        CreateWindowW(L"STATIC", L"保存目录", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)21, 0, 0);
        SendMessageW(GetDlgItem(h, 21), WM_SETFONT, (WPARAM)f, 0);
        g_hSaveDirEdit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hSaveDirEdit, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnBrowse = CreateWindowW(L"BUTTON", L"选择", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)2, 0, 0);
        SendMessageW(g_hBtnBrowse, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnOpen = CreateWindowW(L"BUTTON", L"打开", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)4, 0, 0);
        SendMessageW(g_hBtnOpen, WM_SETFONT, (WPARAM)f, 0);

        CreateWindowW(L"STATIC", L"网站目录", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE, 0, 0, 0, 0, h, (HMENU)28, 0, 0);
        SendMessageW(GetDlgItem(h, 28), WM_SETFONT, (WPARAM)f, 0);
        g_hWebRoot = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hWebRoot, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnWebRootBrowse = CreateWindowW(L"BUTTON", L"选择", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)6, 0, 0);
        SendMessageW(g_hBtnWebRootBrowse, WM_SETFONT, (WPARAM)f, 0);
        g_hBtnWebRootOpen = CreateWindowW(L"BUTTON", L"打开", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)7, 0, 0);
        SendMessageW(g_hBtnWebRootOpen, WM_SETFONT, (WPARAM)f, 0);

        // 通配符复选框（DNS-01 时显示）
        g_hWildcard = CreateWindowW(L"BUTTON", L"通配符证书（*.域名）", WS_CHILD | BS_AUTOCHECKBOX, 0, 0, 0, 0, h, (HMENU)32, 0, 0);
        SendMessageW(g_hWildcard, WM_SETFONT, (WPARAM)f, 0);

        g_hBtnApply = CreateWindowW(L"BUTTON", L"申请证书", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)1, 0, 0);
        SendMessageW(g_hBtnApply, WM_SETFONT, (WPARAM)f, 0);
        g_hDaysEdit = CreateWindowW(L"BUTTON", L"证书查询", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, h, (HMENU)5, 0, 0);
        SendMessageW(g_hDaysEdit, WM_SETFONT, (WPARAM)f, 0);

        CreateWindowW(L"STATIC", 0, WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ, 0, 0, 0, 0, h, (HMENU)13, 0, 0);
        g_hLog = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hLog, WM_SETFONT, (WPARAM)fm, 0);
        g_hStatus = CreateWindowW(L"STATIC", L"就绪", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)f, 0);
        g_hIP = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_RIGHT | SS_CENTERIMAGE | SS_NOTIFY, 0, 0, 0, 0, h, 0, 0, 0);
        SendMessageW(g_hIP, WM_SETFONT, (WPARAM)f, 0);

        // 获取本机所有IP（遍历网卡，跳过回环和虚拟网卡）
        {
            ULONG sz = 0;
            GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, NULL, &sz);
            std::vector<BYTE> buf(sz);
            PIP_ADAPTER_ADDRESSES aa = (PIP_ADAPTER_ADDRESSES)buf.data();
            if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, NULL, aa, &sz) == 0) {
                g_ipList.clear();
                for (auto a = aa; a; a = a->Next) {
                    if (a->OperStatus != IfOperStatusUp) continue;
                    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
                    for (auto ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                        if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                        auto sa = (sockaddr_in*)ua->Address.lpSockaddr;
                        DWORD ip = sa->sin_addr.S_un.S_addr;
                        if ((ip & 0xFF) == 127 || (ip & 0xFF) == 0) continue;
                        if ((ip & 0xFFFF) == htons(0xFEA9)) continue;
                        wchar_t ipStr[64];
                        swprintf_s(ipStr, L"%d.%d.%d.%d",
                            sa->sin_addr.S_un.S_un_b.s_b1, sa->sin_addr.S_un.S_un_b.s_b2,
                            sa->sin_addr.S_un.S_un_b.s_b3, sa->sin_addr.S_un.S_un_b.s_b4);
                        g_ipList.push_back(ipStr);
                    }
                }
                if (!g_ipList.empty()) {
                    g_ipIndex = 0;
                    wchar_t display[128];
                    swprintf_s(display, L"本机IP: %s", g_ipList[0].c_str());
                    SetWindowTextW(g_hIP, display);
                    if (g_ipList.size() > 1)
                        SetTimer(h, IP_TIMER_ID, 5000, NULL);
                } else {
                    SetWindowTextW(g_hIP, L"本机IP: --");
                }
            }
        }
        SetPropW(h, L"F", (HANDLE)f); SetPropW(h, L"FM", (HANDLE)fm);
        SyncWebRootVis();
        break;
    }
    case WM_SIZE: {
        int W = LOWORD(l), H = HIWORD(l);
        int LM = 35, RM = 35, LW = 52, G = 8, RH = 26, RG = 8;
        int IX = LM + LW + G, IW = W - IX - RM;
        if (IW < 100) IW = 100;  // 防御性保护
        int y = 12;
        // CA机构行（标签 + 文本 + 状态文字 + 指示灯）— 第一行
        SetWindowPos(GetDlgItem(h, 29), 0, LM + 10, y, LW, RH, 4);
        SetWindowPos(g_hCA, 0, IX + 10, y, IW - 82, RH, 4);
        SetWindowPos(g_hCAStatus, 0, IX + IW - 70, y, 48, RH, 4);
        SetWindowPos(g_hCAInd, 0, IX + IW - 20, y + 5, 16, 16, 4);
        y += RH + RG;
        SetWindowPos(GetDlgItem(h, 20), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hDomain, 0, IX, y, IW, RH, 4);
        y += RH + RG;
        SetWindowPos(GetDlgItem(h, 27), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hEmail, 0, IX, y, IW, RH, 4);
        y += RH + RG;
        // 服务器 | 验证方式
        SetWindowPos(GetDlgItem(h, 25), 0, LM, y, LW, RH, 4);
        int half = (IW - LW - G) / 2;
        if (half < 60) half = 60;
        SetWindowPos(g_hServer, 0, IX, y, half, RH + 140, 4);
        SetWindowPos(GetDlgItem(h, 26), 0, IX + half + G, y, LW, RH, 4);
        SetWindowPos(g_hVerifyMode, 0, IX + half + G + LW + G, y, IW - half - LW - 2 * G, RH + 140, 4);
        y += RH + RG;
        int bw = 60, bg = 6, ew = IW - 2 * bw - 2 * bg;
        if (ew < 40) ew = 40;
        SetWindowPos(GetDlgItem(h, 21), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hSaveDirEdit, 0, IX, y, ew, RH, 4);
        SetWindowPos(g_hBtnBrowse, 0, IX + ew + bg, y, bw, RH, 4);
        SetWindowPos(g_hBtnOpen, 0, IX + ew + bg + bw + bg, y, bw, RH, 4);
        y += RH + RG;
        int bw2 = 60, bg2 = 6, ew2 = IW - 2 * bw2 - 2 * bg2;
        if (ew2 < 40) ew2 = 40;
        SetWindowPos(GetDlgItem(h, 28), 0, LM, y, LW, RH, 4);
        SetWindowPos(g_hWebRoot, 0, IX, y, ew2, RH, 4);
        SetWindowPos(g_hBtnWebRootBrowse, 0, IX + ew2 + bg2, y, bw2, RH, 4);
        SetWindowPos(g_hBtnWebRootOpen, 0, IX + ew2 + bg2 + bw2 + bg2, y, bw2, RH, 4);
        // 通配符复选框与网站目录同行（互相隐藏）
        SetWindowPos(g_hWildcard, 0, IX, y, 200, RH, 4);
        y += RH + 12;
        int gap = 120, bx = (W - 2 * 100 - gap) / 2;
        SetWindowPos(g_hBtnApply, 0, bx, y, 100, 32, 4);
        SetWindowPos(g_hDaysEdit, 0, bx + 100 + gap, y, 100, 32, 4);
        y += 40;
        SetWindowPos(GetDlgItem(h, 13), 0, LM, y, W - LM - RM, 2, 4);
        y += 6;
        // 日志区域：从 y 到底部，最小 60px
        int sh = 26;
        int bottomY = y + 60 + sh + 4;  // 至少需要 log(60) + status(22) + gap(4)
        if (H < bottomY) H = bottomY;    // 确保空间够放日志+状态栏
        int lh = H - y - sh - 4; if (lh < 60) lh = 60;
        SetWindowPos(g_hLog, 0, LM, y, W - LM - RM, lh, 4);
        // 状态栏和 IP 紧跟日志下方，不依赖窗口总高度倒推
        int statusY = y + lh + 4;
        SetWindowPos(g_hStatus, 0, LM, statusY, 150, sh, 4);
        int ipW = 200;
        SetWindowPos(g_hIP, 0, W - RM - ipW, statusY, ipW, sh, 4);
        break;
    }
    case WM_GETMINMAXINFO: {
        // 限制最小窗口尺寸，防止远程桌面/DPI变化压烂布局
        MINMAXINFO* mm = (MINMAXINFO*)l;
        mm->ptMinTrackSize.x = 480;
        mm->ptMinTrackSize.y = 560;
        return 0;
    }
    case WM_COMMAND: {
        if (LOWORD(w) == 1) {
            // DNS-01 等待中：触发继续验证
            if (g_hDnsReady) { SetEvent(g_hDnsReady); EnableWindow(g_hBtnApply, FALSE); break; }
            if (!IsWindowEnabled(g_hBtnApply)) break;
            EnableWindow(g_hBtnApply, FALSE);
            // 同步 UI 输入到全局变量，避免重启才生效
            wchar_t dt[MAX_PATH];
            GetWindowTextW(g_hWebRoot, dt, MAX_PATH);
            if (dt[0]) g_WebRoot = dt;
            GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
            if (dt[0]) g_SaveDir = dt; if (g_SaveDir.empty()) { BrowseDir(); if (g_SaveDir.empty()) { EnableWindow(g_hBtnApply, TRUE); break; } }
            Log(L"开始申请..."); HANDLE hh = (HANDLE)_beginthreadex(0, 0, ApplyThread, 0, 0, 0); if (hh) CloseHandle(hh);
        }
        else if (LOWORD(w) == 2) BrowseDir();
        else if (LOWORD(w) == 6) {
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hWebRoot, dt, MAX_PATH);
            if (dt[0]) g_WebRoot = dt;
            std::wstring out;
            if (PickFolder(g_hWnd, L"选择网站目录", g_WebRoot, out)) {
                g_WebRoot = out;
                SetWindowTextW(g_hWebRoot, out.c_str());
            }
        }
        else if (LOWORD(w) == 7) {
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hWebRoot, dt, MAX_PATH);
            if (dt[0]) ShellExecuteW(0, L"open", dt, 0, 0, SW_SHOWNORMAL);
        }
        else if (LOWORD(w) == 4) {
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
            if (dt[0]) ShellExecuteW(0, L"open", dt, 0, 0, SW_SHOWNORMAL);
        }
        else if (LOWORD(w) == 5) {
            wchar_t dt[MAX_PATH]; GetWindowTextW(g_hSaveDirEdit, dt, MAX_PATH);
            if (dt[0]) g_SaveDir = dt;
            if (g_SaveDir.empty()) { BrowseDir(); if (g_SaveDir.empty()) break; }
            Log(L"扫描证书...");
            HANDLE hh = (HANDLE)_beginthreadex(0, 0, [](void*)->unsigned {
                WIN32_FIND_DATAW fd; HANDLE hFind;
                std::wstring pattern = g_SaveDir + L"\\*.crt";
                hFind = FindFirstFileW(pattern.c_str(), &fd);
                if (hFind == INVALID_HANDLE_VALUE) {
                    Log(L"未找到证书文件");
                    Log(L"证书保存目录未设置，或该目录下无 .crt 文件");
                    SetStatus(L"证书保存目录未设置");
                    return 0;
                }
                int count = 0;
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        std::wstring path = g_SaveDir + L"\\" + fd.cFileName;
                        // 用宽字符路径读取，支持中文目录
                        HANDLE hcrt = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hcrt == INVALID_HANDLE_VALUE) continue;
                        DWORD fsz2 = GetFileSize(hcrt, NULL);
                        std::string pem(fsz2, '\0');
                        DWORD rd2 = 0;
                        (void)ReadFile(hcrt, &pem[0], fsz2, &rd2, NULL);
                        CloseHandle(hcrt);
                        pem.resize(rd2);
                        DWORD cb = 0;
                        if (!CryptStringToBinaryA(pem.c_str(), (DWORD)pem.size(), CRYPT_STRING_BASE64HEADER, NULL, &cb, NULL, NULL)) continue;
                        std::vector<BYTE> der(cb);
                        if (!CryptStringToBinaryA(pem.c_str(), (DWORD)pem.size(), CRYPT_STRING_BASE64HEADER, der.data(), &cb, NULL, NULL)) continue;
                        PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), cb);
                        if (!ctx) continue;
                        wchar_t subj[256] = { 0 }; DWORD slen = 256;
                        CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subj, slen);
                        FILETIME ft = ctx->pCertInfo->NotAfter;
                        CertFreeCertificateContext(ctx);
                
                        FILETIME ftNow; GetSystemTimeAsFileTime(&ftNow);
                        ULARGE_INTEGER u1, u2; u1.LowPart = ft.dwLowDateTime; u1.HighPart = ft.dwHighDateTime;
                        u2.LowPart = ftNow.dwLowDateTime; u2.HighPart = ftNow.dwHighDateTime;
                        LONGLONG diff = u1.QuadPart - u2.QuadPart;
                        int days = (int)(diff / 864000000000LL);
                        Log(L"%s - %s, 剩余 %d 天", fd.cFileName, subj[0] ? subj : L"未知", days);
                        count++;
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
                if (count == 0) {
                    Log(L"未找到证书文件");
                    Log(L"证书保存目录未设置，或该目录下无 .crt 文件");
                    SetStatus(L"证书保存目录未设置");
                }
                else { wchar_t buf[64]; swprintf_s(buf, L"找到 %d 个证书", count); SetStatus(buf); }
                return 0;
            }, 0, 0, 0);
            if (hh) CloseHandle(hh);
        }
        else if (HIWORD(w) == CBN_SELCHANGE && (HWND)l == g_hVerifyMode) {
            SyncWebRootVis();
            SetWindowTextW(g_hLog, L"");
            ShowVerifySteps((int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0));
        }
        else if ((HWND)l == g_hIP && HIWORD(w) == 0) {
            // 点击复制当前显示的IP（不含"本机IP: "前缀）
            if (g_ipIndex < (int)g_ipList.size()) {
                const std::wstring& ip = g_ipList[g_ipIndex];
                OpenClipboard(NULL); EmptyClipboard();
                HGLOBAL hm = GlobalAlloc(GMEM_MOVEABLE, (ip.size() + 1) * sizeof(wchar_t));
                memcpy(GlobalLock(hm), ip.c_str(), (ip.size() + 1) * sizeof(wchar_t));
                GlobalUnlock(hm); SetClipboardData(CF_UNICODETEXT, hm);
                CloseClipboard(); SetStatus(L"IP 已复制");
            }
        }
        break;
    }
    case WM_TIMER: {
        if (w == IP_TIMER_ID && g_ipList.size() > 1) {
            g_ipIndex = (g_ipIndex + 1) % (int)g_ipList.size();
            wchar_t display[128];
            swprintf_s(display, L"本机IP: %s", g_ipList[g_ipIndex].c_str());
            SetWindowTextW(g_hIP, display);
        }
        break;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)l;
        if (dis->CtlID == 30) { // CA 指示灯
            COLORREF clr;
            switch (g_caStatus) {
                case 1:  clr = RGB(0, 200, 80);  break; // 绿色
                case 2:  clr = RGB(220, 50, 50); break; // 红色
                default: clr = RGB(180, 180, 180); break; // 灰色
            }
            RECT rc = dis->rcItem;
            int cx = rc.left + (rc.right - rc.left) / 2;
            int cy = rc.top + (rc.bottom - rc.top) / 2;
            int r = min(rc.right - rc.left, rc.bottom - rc.top) / 2 - 1;
            if (r < 2) r = 2;
            HBRUSH br = CreateSolidBrush(clr);
            HPEN pen = CreatePen(PS_SOLID, 1, clr);
            HBRUSH oldBr = (HBRUSH)SelectObject(dis->hDC, br);
            HPEN oldPen = (HPEN)SelectObject(dis->hDC, pen);
            Ellipse(dis->hDC, cx - r, cy - r, cx + r, cy + r);
            // 高光效果（每通道 +60，独立 clamp 到 255）
            BYTE hlR = (GetRValue(clr) > 195) ? 255 : GetRValue(clr) + 60;
            BYTE hlG = (GetGValue(clr) > 195) ? 255 : GetGValue(clr) + 60;
            BYTE hlB = (GetBValue(clr) > 195) ? 255 : GetBValue(clr) + 60;
            COLORREF hlClr = RGB(hlR, hlG, hlB);
            HBRUSH brHL = CreateSolidBrush(hlClr);
            SelectObject(dis->hDC, brHL);
            int hr = max(r / 3, 1);
            Ellipse(dis->hDC, cx - hr, cy - r + 1, cx + hr, cy - r + 1 + hr * 2);
            SelectObject(dis->hDC, oldBr);
            SelectObject(dis->hDC, oldPen);
            DeleteObject(br); DeleteObject(pen); DeleteObject(brHL);
            return TRUE;
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)w;
        SetBkColor(dc, RGB(245, 245, 245));
        HWND ctrl = (HWND)l;
        if (ctrl == g_hCAStatus) {
            if (g_caStatus == 1) SetTextColor(dc, RGB(0, 150, 60));      // 绿色文字
            else if (g_caStatus == 2) SetTextColor(dc, RGB(200, 40, 40));  // 红色文字
            else SetTextColor(dc, RGB(120, 120, 120));                     // 灰色文字
        } else {
            SetTextColor(dc, RGB(0, 0, 0));
        }
        return (LRESULT)GetClassLongPtrW(h, GCLP_HBRBACKGROUND);
    }
    case WM_DESTROY: {
        KillTimer(h, IP_TIMER_ID);  // 停止 IP 轮播
        wchar_t buf[512];
        if (GetWindowTextW(g_hDomain, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"Domain", buf, g_IniPath.c_str());
        if (GetWindowTextW(g_hEmail, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"Email", buf, g_IniPath.c_str());
        int si = (int)SendMessageW(g_hServer, CB_GETCURSEL, 0, 0);
        swprintf_s(buf, L"%d", si);
        WritePrivateProfileStringW(L"SSLClaw", L"ServerType", buf, g_IniPath.c_str());
        if (GetWindowTextW(g_hSaveDirEdit, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"SaveDir", buf, g_IniPath.c_str());
        int vm = (int)SendMessageW(g_hVerifyMode, CB_GETCURSEL, 0, 0);
        swprintf_s(buf, L"%d", vm);
        WritePrivateProfileStringW(L"SSLClaw", L"VerifyMode", buf, g_IniPath.c_str());
        if (GetWindowTextW(g_hWebRoot, buf, 512)) WritePrivateProfileStringW(L"SSLClaw", L"WebRoot", buf, g_IniPath.c_str());
        // 保存通配符复选框状态
        int wc = (int)SendMessageW(g_hWildcard, BM_GETCHECK, 0, 0);
        WritePrivateProfileStringW(L"SSLClaw", L"Wildcard", wc ? L"1" : L"0", g_IniPath.c_str());
        // CA 固定 Let's Encrypt (index 0)
        WritePrivateProfileStringW(L"SSLClaw", L"CA", L"0", g_IniPath.c_str());
        DeleteObject((HFONT)GetPropW(h, L"F")); DeleteObject((HFONT)GetPropW(h, L"FM"));
        PostQuitMessage(0); break;
    }
    default: return DefWindowProcW(h, m, w, l);
    }
    return 0;
}
