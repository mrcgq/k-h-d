

















// =========================================================================================
// Xlink Genesis Client v28.2 (Ultimate Stable Edition)
// [修复] 采用 Mutex 机制重写 WinMain，根治“无法启动”和“多开”问题
// [修复] 整合所有缺失的函数实现，确保代码完整性
// [修复] 修正所有 GCC 编译警告，提升代码健壮性
// [部分 1/3] 头文件与数据结构
// =========================================================================================

#define _WIN32_IE 0x0600
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wincrypt.h>
#include <wininet.h> 
#include <io.h>

// --- 常量与ID ---
#define IDI_APP_ICON 101
#define APP_VERSION "28.2 (Stable)"
#define APP_TITLE "Xlink客户端 v" APP_VERSION

#define ID_NODE_LISTVIEW 1000
#define ID_NODE_ADD 1001
#define ID_NODE_DELETE 1002
#define ID_NODE_RENAME 1003
#define ID_LISTEN_EDIT 1004
#define ID_SERVER_URL_EDIT 1005
#define ID_IP_EDIT 1006
#define ID_TOKEN_EDIT 1007
#define ID_SECRET_KEY_EDIT 1008
#define ID_FALLBACK_IP_EDIT 1009
#define ID_START_SELECTED 1010
#define ID_STOP_SELECTED 1011
#define ID_START_ALL 1012
#define ID_STOP_ALL 1013
#define ID_CLEAR_LOG 1014
#define ID_EXPORT_BTN 1015
#define ID_AUTOSTART_CHECK 1016
#define ID_IMPORT_BTN 1017
#define ID_S5_EDIT 1018
#define ID_LOG_EDIT 1020
#define ID_ROUTING_MODE_COMBO 1040
#define ID_STRATEGY_COMBO 1041 
#define ID_PING_TEST_BTN 1060
#define ID_IMMERSION_CHECK 1061

// [v28.0 新增流控控件ID]
#define ID_TRAFFIC_MIN_EDIT 1070
#define ID_TRAFFIC_MAX_EDIT 1071
#define ID_TIMEOUT_CAP_EDIT 1072
#define ID_EXEMPT_LIST_EDIT 1073

#define ID_RULE_LISTVIEW 1100
#define ID_RULE_ADD 1101
#define ID_RULE_DEL 1102
#define ID_RULE_EDIT_CMD 1105 

#define ID_DLG_TYPE 2001
#define ID_DLG_MATCH 2002
#define ID_DLG_TARGET 2003
#define ID_DLG_OK 2004
#define ID_DLG_CANCEL 2005
#define ID_DLG_STRATEGY 2006 

#define ID_INPUT_EDIT 3001
#define ID_INPUT_OK 3002
#define ID_INPUT_CANCEL 3003
#define ID_TRAY_ICON 9001
#define ID_TRAY_OPEN 9002
#define ID_TRAY_EXIT 9003

#define MAX_RULE_LEN 16384 
#define MAX_SMALL_LEN 256
#define MAX_NODES 50
#define MAX_RULES 300
#define MAX_URL_LEN 8192 
#define MAX_NAME_LEN 128
#define SAFE_PATH_LEN (MAX_PATH + 128) 
#define WM_TRAYICON (WM_USER + 1)
#define WM_APPEND_LOG (WM_USER + 2)

// 全局互斥体名称，用于防止多开
const char* g_szMutexName = "XLinkClient_Global_Mutex_v28";

// 字符串分割辅助函数
char* my_strtok_s(char* str, const char* delimiters, char** context) {
    char* s = str ? str : *context;
    if (!s) return NULL;
    s += strspn(s, delimiters);
    if (!*s) { *context = NULL; return NULL; }
    char* end = s + strcspn(s, delimiters);
    if (*end) { *end++ = '\0'; *context = end; } 
    else { *context = NULL; }
    return s;
}

// --- 数据结构 ---
typedef struct { 
    PROCESS_INFORMATION xray_pi; 
    PROCESS_INFORMATION xlink_pi; 
    HANDLE hLogPipeRead; 
    HANDLE hLogThread; 
    int runningNodeIndex; 
} SidecarEngineStatus;

typedef struct { 
    char type[32]; 
    char match[256]; 
    char target[512]; 
    int mode; 
} RoutingRule;

typedef struct { 
    char name[MAX_NAME_LEN]; 
    char listen[256]; 
    char server[MAX_URL_LEN]; 
    char ip[256]; 
    char token[MAX_URL_LEN]; 
    char secret_key[MAX_URL_LEN]; 
    char fallback_ip[256]; 
    char s5[256]; 
    
    // [v28.0 新增字段]
    char traffic_min[16];
    char traffic_max[16];
    char timeout_cap[16];
    char exempt_list[1024];

    char rules_str[MAX_RULE_LEN]; 
    RoutingRule rule_list[MAX_RULES]; 
    int rule_count; 
    BOOL isRunning; 
    int routing_mode; 
    int xlink_internal_port; 
    int strategy_mode; 
    BOOL global_keep_alive; 
} NodeConfig;

typedef struct { char* buffer; int bufferSize; const char* title; const char* prompt; BOOL result; } InputDialogData;
typedef struct { char type[32]; char match[256]; char target[512]; int mode; BOOL result; } RuleDialogData;
typedef struct { HANDLE hPipe; int nodeIndex; } LogThreadParam;

// --- 全局变量 ---
HINSTANCE hInst;
HWND hMainWindow, hNodeListView, hRuleListView;
HWND hListenEdit, hServerUrlEdit, hIpEdit, hTokenEdit, hSecretKeyEdit, hFallbackIpEdit, hS5Edit, hLogEdit;
HWND hAutoStartCheck, hRoutingModeCombo, hStrategyCombo, hImmersionCheck;
HWND hTrafficMinEdit, hTrafficMaxEdit, hTimeoutCapEdit, hExemptListEdit;
char g_exeDir[SAFE_PATH_LEN] = {0};
HFONT hFontUI = NULL, hFontBold = NULL, hFontLog = NULL;
NOTIFYICONDATA nid;
BOOL g_isAutoStart = FALSE, g_autoStartEnabled = FALSE, g_isEditing = FALSE;
NodeConfig g_nodes[MAX_NODES];
int g_nodeCount = 0, g_currentNodeIndex = -1;
SidecarEngineStatus g_engineStatuses[MAX_NODES];
int g_dpi = 96;

// --- 函数声明 ---
int Scale(int x);
LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK RuleDialogProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK InputDialogProc(HWND, UINT, WPARAM, LPARAM);
void CreateControls(HWND);
void StartEngineForNode(int nodeIndex, BOOL isTest);
void StopSidecarForNode(int nodeIndex);
void StartAll();
void StopAll();
BOOL GenerateXrayConfigFile(int idx, const char* path);
void AppendLog(const char*);
void AppendLogAsync(const char*);
DWORD WINAPI LogReaderThread(LPVOID);
void SaveConfig();
void LoadConfig();
void InitDefaultNode();
void RefreshNodeList();
void SwitchNode(int index);
void GetControlValues(int index);
void SetControlValues(int index);
void AddNewNode(NodeConfig* initialData);
void DeleteSelectedNode();
void RenameSelectedNode();
void OnImportClicked(HWND);
void OnExportClicked(HWND);
BOOL ShowInputDialog(HWND parent, const char* title, const char* prompt, char* buffer, int bufferSize);
BOOL ShowRuleDialog(HWND parent, RuleDialogData* data);
void InitExeDir();
void InitTrayIcon(HWND);
void TranslateLog(const char* originalLog, int nodeIndex); 
void MimicOldLogStartForNode(int n); 
BOOL SetAutoStart(BOOL enable);
BOOL IsAutoStartEnabled();
void UpdateAutoStartCheckbox();
void Utf8ToAnsi(const char* utf8, char* ansi, int ansiLen);
void AnsiToUtf8(const char* ansi, char* utf8, int utf8Len);
void ApplyFont(HWND hCtrl, HFONT hFont);
BOOL CALLBACK ApplyFontToChildren(HWND hwnd, LPARAM lParam);
typedef BOOL(WINAPI *SetProcessDPIAwareFuncType)(void); 
int FindFreePort();
BOOL FileExists(const char* filename);
void RefreshRuleListUI(NodeConfig* cfg);
void SerializeRules(NodeConfig* cfg);
void ParseRulesString(NodeConfig* cfg);













// [部分 2/3] 主入口、UI 构建与消息处理

// =================================== WinMain (v28.2 稳定版) ===================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    hInst = hInstance;

    // [v28.2 核心修复] 使用互斥体 (Mutex) 检查程序是否已运行
    HANDLE hMutex = CreateMutexA(NULL, TRUE, g_szMutexName);
    if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND hExistingWnd = FindWindowA("XLinkClient_v28", NULL);
        if (hExistingWnd) {
            ShowWindow(hExistingWnd, SW_RESTORE);
            SetForegroundWindow(hExistingWnd);
        }
        CloseHandle(hMutex);
        return 0; // 退出当前进程
    }

    INITCOMMONCONTROLSEX icex; icex.dwSize = sizeof(INITCOMMONCONTROLSEX); icex.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES;
    if (!InitCommonControlsEx(&icex)) return 0;

    InitExeDir();
    if (lpCmdLine && strstr(lpCmdLine, "-autostart")) g_isAutoStart = TRUE;

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (hUser32) { 
        FARPROC proc = GetProcAddress(hUser32, "SetProcessDPIAware"); 
        if (proc) ((SetProcessDPIAwareFuncType)proc)(); 
        FreeLibrary(hUser32); 
    }
    
    HDC hdc = GetDC(NULL); 
    if (hdc) { g_dpi = GetDeviceCaps(hdc, LOGPIXELSX); ReleaseDC(NULL, hdc); }
    
    hFontUI = CreateFont(Scale(19), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Microsoft YaHei UI");
    if (!hFontUI) hFontUI = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    hFontBold = CreateFont(Scale(19), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, "Microsoft YaHei UI");
    hFontLog = CreateFont(Scale(16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH, "Consolas");
    
    WNDCLASSA wc = {0}; 
    wc.lpfnWndProc = WindowProc; 
    wc.hInstance = hInstance; 
    wc.lpszClassName = "XLinkClient_v28"; 
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1); 
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); 
    wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APP_ICON)); 
    if(!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION); 
    RegisterClassA(&wc);
    
    WNDCLASSA wcRule = {0}; 
    wcRule.lpfnWndProc = RuleDialogProc; 
    wcRule.hInstance = hInstance; 
    wcRule.lpszClassName = "RuleEditorDlg"; 
    wcRule.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1); 
    wcRule.hCursor = LoadCursor(NULL, IDC_ARROW); 
    RegisterClassA(&wcRule);
    
    int winWidth = Scale(980), winHeight = Scale(1250);
    int screenW = GetSystemMetrics(SM_CXSCREEN), screenH = GetSystemMetrics(SM_CYSCREEN);
    
    hMainWindow = CreateWindowExA(0, "XLinkClient_v28", APP_TITLE, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, (screenW - winWidth) / 2, (screenH - winHeight) / 2, winWidth, winHeight, NULL, NULL, hInstance, NULL);
    
    if (!hMainWindow) {
        MessageBoxA(NULL, "窗口创建失败!", "严重错误", MB_ICONERROR);
        return 1;
    }

    InitTrayIcon(hMainWindow); 
    Shell_NotifyIcon(NIM_ADD, &nid);
    
    if (g_isAutoStart) ShowWindow(hMainWindow, SW_HIDE); 
    else ShowWindow(hMainWindow, nCmdShow); 
    
    UpdateWindow(hMainWindow);
    
    MSG msg; 
    while (GetMessage(&msg, NULL, 0, 0)) { 
        if (!IsDialogMessage(hMainWindow, &msg)) { 
            TranslateMessage(&msg); 
            DispatchMessage(&msg); 
        } 
    }
    
    if (hMutex) ReleaseMutex(hMutex);
    return (int)msg.wParam;
}

void CreateControls(HWND hwnd) {
    RECT rect; GetClientRect(hwnd, &rect);
    int winW = rect.right, winH = rect.bottom;
    int margin = Scale(20), gap = Scale(10); 
    int leftPanelW = Scale(240); int inputH = Scale(26); int btnH = Scale(30);   
    int rightX = margin + leftPanelW + margin; int rightW = winW - rightX - margin; int curY = margin;

    HWND hStaticCfg = CreateWindow("STATIC", "节点配置 (Trinity Defense 一体化)", WS_VISIBLE | WS_CHILD | SS_LEFT, rightX, curY, rightW, Scale(20), hwnd, NULL, NULL, NULL);
    ApplyFont(hStaticCfg, hFontBold); curY += Scale(30);

    #define CREATE_ROW(txt, id_edit, var_ptr) \
    do { \
        CreateWindow("STATIC", txt, WS_VISIBLE | WS_CHILD | SS_RIGHT | SS_CENTERIMAGE, rightX, curY, Scale(100), inputH, hwnd, NULL, NULL, NULL); \
        var_ptr = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, rightX + Scale(100) + gap, curY, rightW - Scale(100) - gap, inputH, hwnd, (HMENU)id_edit, NULL, NULL); \
        SendMessage(var_ptr, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(Scale(5), Scale(5))); \
        curY += inputH + gap; \
    } while(0)

    CREATE_ROW("本地监听:", ID_LISTEN_EDIT, hListenEdit);
    int poolH = inputH * 3; 
    CreateWindow("STATIC", "域名池 (格式: domain#ip:port):", WS_VISIBLE | WS_CHILD | SS_LEFT, rightX, curY, rightW, inputH, hwnd, NULL, NULL, NULL);
    curY += Scale(22);
    hServerUrlEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | WS_VSCROLL | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN, rightX, curY, rightW, poolH, hwnd, (HMENU)ID_SERVER_URL_EDIT, NULL, NULL);
    SendMessage(hServerUrlEdit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(Scale(5), Scale(5))); curY += poolH + gap;
    CREATE_ROW("全局指定 IP:", ID_IP_EDIT, hIpEdit);
    CREATE_ROW("Token:", ID_TOKEN_EDIT, hTokenEdit);
    CREATE_ROW("Key:", ID_SECRET_KEY_EDIT, hSecretKeyEdit);
    CREATE_ROW("回源 IP:", ID_FALLBACK_IP_EDIT, hFallbackIpEdit);
    CREATE_ROW("SOCKS5:", ID_S5_EDIT, hS5Edit); 
    
    // [v28.0] 新增：高级流控配置区
    CreateWindow("STATIC", "流控参数 (可选):", WS_VISIBLE | WS_CHILD | SS_LEFT, rightX, curY, rightW, inputH, hwnd, NULL, NULL, NULL);
    curY += Scale(20);
    
    // 最小流量 - 最大流量
    int quarterW = (rightW - Scale(220)) / 2;
    CreateWindow("STATIC", "阈值(MB):", WS_VISIBLE | WS_CHILD | SS_RIGHT | SS_CENTERIMAGE, rightX, curY, Scale(60), inputH, hwnd, NULL, NULL, NULL);
    hTrafficMinEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_NUMBER | ES_AUTOHSCROLL | WS_TABSTOP, rightX + Scale(65), curY, quarterW, inputH, hwnd, (HMENU)ID_TRAFFIC_MIN_EDIT, NULL, NULL);
    CreateWindow("STATIC", "-", WS_VISIBLE | WS_CHILD | SS_CENTER | SS_CENTERIMAGE, rightX + Scale(65) + quarterW, curY, Scale(10), inputH, hwnd, NULL, NULL, NULL);
    hTrafficMaxEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_NUMBER | ES_AUTOHSCROLL | WS_TABSTOP, rightX + Scale(80) + quarterW, curY, quarterW, inputH, hwnd, (HMENU)ID_TRAFFIC_MAX_EDIT, NULL, NULL);
    
    // 最大超时
    CreateWindow("STATIC", "最大超时(ms):", WS_VISIBLE | WS_CHILD | SS_RIGHT | SS_CENTERIMAGE, rightX + Scale(80) + quarterW*2 + gap, curY, Scale(90), inputH, hwnd, NULL, NULL, NULL);
    hTimeoutCapEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_NUMBER | ES_AUTOHSCROLL | WS_TABSTOP, rightX + Scale(80) + quarterW*2 + gap + Scale(95), curY, rightW - (Scale(80) + quarterW*2 + gap + Scale(95)), inputH, hwnd, (HMENU)ID_TIMEOUT_CAP_EDIT, NULL, NULL);
    curY += inputH + gap;

    // 豁免名单
    CreateWindow("STATIC", "豁免名单 (逗号分隔):", WS_VISIBLE | WS_CHILD | SS_LEFT, rightX, curY, rightW, inputH, hwnd, NULL, NULL, NULL);
    curY += Scale(20);
    hExemptListEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | WS_TABSTOP, rightX, curY, rightW, inputH, hwnd, (HMENU)ID_EXEMPT_LIST_EDIT, NULL, NULL);
    curY += inputH + gap;

    curY += gap/2;
    CreateWindow("STATIC", "路由模式:", WS_VISIBLE | WS_CHILD | SS_RIGHT | SS_CENTERIMAGE, rightX, curY + Scale(4), Scale(100), inputH, hwnd, NULL, NULL, NULL);
    hRoutingModeCombo = CreateWindow(WC_COMBOBOX, "", CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE, rightX + Scale(100) + gap, curY, rightW - Scale(100) - gap, inputH * 5, hwnd, (HMENU)ID_ROUTING_MODE_COMBO, NULL, NULL);
    SendMessage(hRoutingModeCombo, CB_ADDSTRING, 0, (LPARAM)"全局代理 (经由 Xlink)");
    SendMessage(hRoutingModeCombo, CB_ADDSTRING, 0, (LPARAM)"智能分流 (需Xray)+广告过滤");
    SendMessage(hRoutingModeCombo, CB_SETCURSEL, (WPARAM)0, 0);
    curY += inputH + gap;

    CreateWindow("STATIC", "负载策略:", WS_VISIBLE | WS_CHILD | SS_RIGHT | SS_CENTERIMAGE, rightX, curY + Scale(4), Scale(100), inputH, hwnd, NULL, NULL, NULL);
    hStrategyCombo = CreateWindow(WC_COMBOBOX, "", CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_CHILD | WS_OVERLAPPED | WS_VISIBLE, rightX + Scale(100) + gap, curY, rightW - Scale(100) - gap, inputH * 5, hwnd, (HMENU)ID_STRATEGY_COMBO, NULL, NULL);
    SendMessage(hStrategyCombo, CB_ADDSTRING, 0, (LPARAM)"[Random] 混沌模式 (推荐)");
    SendMessage(hStrategyCombo, CB_ADDSTRING, 0, (LPARAM)"[RR] 加特林模式 (轮询)");
    SendMessage(hStrategyCombo, CB_ADDSTRING, 0, (LPARAM)"[Hash] 狙击模式 (会话保持)");
    SendMessage(hStrategyCombo, CB_SETCURSEL, (WPARAM)0, 0);
    curY += inputH + gap;

    hImmersionCheck = CreateWindow("BUTTON", "沉浸模式 (全局禁用断流 - 游戏/视频专用)", 
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, 
        rightX, curY, rightW, Scale(24), hwnd, (HMENU)ID_IMMERSION_CHECK, NULL, NULL);
    curY += Scale(24) + gap + Scale(5);

    CreateWindow("STATIC", "分流规则 (v21.0 策略版):", WS_VISIBLE | WS_CHILD | SS_LEFT, rightX, curY, rightW/2, inputH, hwnd, NULL, NULL, NULL);
    int ruleBtnW = Scale(60); int ruleBtnX = rightX + rightW - (ruleBtnW * 2) - gap;
    CreateWindow("BUTTON", "+ 添加", WS_VISIBLE | WS_CHILD, ruleBtnX, curY-Scale(2), ruleBtnW, Scale(22), hwnd, (HMENU)ID_RULE_ADD, NULL, NULL);
    CreateWindow("BUTTON", "- 删除", WS_VISIBLE | WS_CHILD, ruleBtnX + ruleBtnW + gap, curY-Scale(2), ruleBtnW, Scale(22), hwnd, (HMENU)ID_RULE_DEL, NULL, NULL);
    curY += Scale(22); int ruleListH = Scale(120);
    hRuleListView = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP, rightX, curY, rightW, ruleListH, hwnd, (HMENU)ID_RULE_LISTVIEW, NULL, NULL);
    ListView_SetExtendedListViewStyle(hRuleListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
    
    LVCOLUMN lvc; lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = "类型"; lvc.cx = Scale(70); ListView_InsertColumn(hRuleListView, 0, &lvc);
    lvc.pszText = "匹配内容"; lvc.cx = Scale(150); ListView_InsertColumn(hRuleListView, 1, &lvc);
    lvc.pszText = "目标节点"; lvc.cx = rightW - Scale(70) - Scale(150) - Scale(70) - Scale(25); ListView_InsertColumn(hRuleListView, 2, &lvc);
    lvc.pszText = "策略"; lvc.cx = Scale(70); ListView_InsertColumn(hRuleListView, 3, &lvc);
    
    curY += ruleListH + gap;

    int exportBtnW = Scale(140); CreateWindow("BUTTON", "导出配置到剪贴板", WS_VISIBLE | WS_CHILD | WS_TABSTOP, rightX + rightW - exportBtnW, curY, exportBtnW, Scale(30), hwnd, (HMENU)ID_EXPORT_BTN, NULL, NULL);
    curY += Scale(30) + gap;
    int actionBtnW = Scale(100);
    CreateWindow("BUTTON", "启动当前", WS_VISIBLE | WS_CHILD | WS_TABSTOP, rightX, curY, actionBtnW, btnH, hwnd, (HMENU)ID_START_SELECTED, NULL, NULL);
    CreateWindow("BUTTON", "停止当前", WS_VISIBLE | WS_CHILD | WS_TABSTOP, rightX + actionBtnW + gap, curY, actionBtnW, btnH, hwnd, (HMENU)ID_STOP_SELECTED, NULL, NULL);
    CreateWindow("BUTTON", "全部启动", WS_VISIBLE | WS_CHILD | WS_TABSTOP, rightX + actionBtnW*2 + gap*2, curY, actionBtnW, btnH, hwnd, (HMENU)ID_START_ALL, NULL, NULL);
    CreateWindow("BUTTON", "全部停止", WS_VISIBLE | WS_CHILD | WS_TABSTOP, rightX + actionBtnW*3 + gap*3, curY, actionBtnW, btnH, hwnd, (HMENU)ID_STOP_ALL, NULL, NULL);
    CreateWindow("BUTTON", "清空日志", WS_VISIBLE | WS_CHILD | WS_TABSTOP, rightX + rightW - actionBtnW, curY, actionBtnW, btnH, hwnd, (HMENU)ID_CLEAR_LOG, NULL, NULL);
    curY += btnH + gap;
    hAutoStartCheck = CreateWindow("BUTTON", "开机自启所有节点", WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP, rightX, curY, Scale(200), Scale(24), hwnd, (HMENU)ID_AUTOSTART_CHECK, NULL, NULL);
    curY += Scale(24) + gap; int dividerY = curY; 

    int leftStartY = margin; HWND hStaticList = CreateWindow("STATIC", "节点列表", WS_VISIBLE | WS_CHILD | SS_LEFT, margin, leftStartY, leftPanelW, Scale(20), hwnd, NULL, NULL, NULL);
    ApplyFont(hStaticList, hFontBold); leftStartY += Scale(25);
    int leftBtnAreaHeight = (btnH * 3) + (gap * 2); int listHeight = dividerY - leftStartY - leftBtnAreaHeight - gap; 
    hNodeListView = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP, margin, leftStartY, leftPanelW, listHeight, hwnd, (HMENU)ID_NODE_LISTVIEW, NULL, NULL);
    ListView_SetExtendedListViewStyle(hNodeListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    lvc.pszText = "别名"; lvc.cx = leftPanelW - Scale(70); ListView_InsertColumn(hNodeListView, 0, &lvc);
    lvc.pszText = "状态"; lvc.cx = Scale(60); lvc.fmt = LVCFMT_CENTER; ListView_InsertColumn(hNodeListView, 1, &lvc);
    int btnY = leftStartY + listHeight + gap; int halfBtnW = (leftPanelW - gap) / 2;
    CreateWindow("BUTTON", "新建", WS_VISIBLE | WS_CHILD | WS_TABSTOP, margin, btnY, halfBtnW, btnH, hwnd, (HMENU)ID_NODE_ADD, NULL, NULL);
    CreateWindow("BUTTON", "删除", WS_VISIBLE | WS_CHILD | WS_TABSTOP, margin + halfBtnW + gap, btnY, halfBtnW, btnH, hwnd, (HMENU)ID_NODE_DELETE, NULL, NULL);
    btnY += btnH + gap; CreateWindow("BUTTON", "重命名", WS_VISIBLE | WS_CHILD | WS_TABSTOP, margin, btnY, halfBtnW, btnH, hwnd, (HMENU)ID_NODE_RENAME, NULL, NULL);
    CreateWindow("BUTTON", "导入", WS_VISIBLE | WS_CHILD | WS_TABSTOP, margin + halfBtnW + gap, btnY, halfBtnW, btnH, hwnd, (HMENU)ID_IMPORT_BTN, NULL, NULL);
    btnY += btnH + gap; CreateWindow("BUTTON", "延迟测速 (Ping)", WS_VISIBLE | WS_CHILD | WS_TABSTOP, margin, btnY, leftPanelW, btnH, hwnd, (HMENU)ID_PING_TEST_BTN, NULL, NULL);

    int logStartY = dividerY + Scale(5); HWND hStaticLog = CreateWindow("STATIC", "运行日志 (详细调试模式)", WS_VISIBLE | WS_CHILD | SS_LEFT, margin, logStartY, winW - margin*2, Scale(20), hwnd, NULL, NULL, NULL);
    ApplyFont(hStaticLog, hFontBold); logStartY += Scale(25); int logHeight = winH - logStartY - margin; 
    hLogEdit = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, margin, logStartY, winW - margin * 2, logHeight, hwnd, (HMENU)ID_LOG_EDIT, NULL, NULL);

    EnumChildWindows(hwnd, ApplyFontToChildren, (LPARAM)hFontUI);
    ApplyFont(hNodeListView, hFontUI); ApplyFont(hRuleListView, hFontUI); ApplyFont(hLogEdit, hFontLog);
    ApplyFont(hStaticList, hFontBold); ApplyFont(hStaticCfg, hFontBold); ApplyFont(hStaticLog, hFontBold);
}







LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
case WM_CREATE:
        CreateControls(hwnd);
        LoadConfig();
        if (g_nodeCount == 0) InitDefaultNode();
        RefreshNodeList();
        
        // [修复] 加上大括号，防止宏展开导致 else 报错
        if (g_nodeCount > 0) {
            ListView_SetItemState(hNodeListView, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        } else {
            SwitchNode(-1);
        }
        
        UpdateAutoStartCheckbox();
        if (g_isAutoStart && g_nodeCount > 0) PostMessage(hwnd, WM_COMMAND, ID_START_ALL, 0);
        break;

    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == ID_NODE_LISTVIEW && pnmh->code == LVN_ITEMCHANGED) {
            LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
            if ((pnmv->uChanged & LVIF_STATE) && (pnmv->uNewState & LVIS_SELECTED)) {
                if (g_currentNodeIndex != pnmv->iItem) SwitchNode(pnmv->iItem);
            }
        }
        if (pnmh->idFrom == ID_RULE_LISTVIEW && pnmh->code == NM_RCLICK) {
            LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE)lParam;
            int sel = lpnmitem->iItem; 
            if (sel != -1) {
                ListView_SetItemState(hRuleListView, sel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                HMENU hMenu = CreatePopupMenu();
                AppendMenu(hMenu, MF_STRING, ID_RULE_EDIT_CMD, "编辑规则 (&E)"); 
                AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
                AppendMenu(hMenu, MF_STRING, ID_RULE_DEL, "删除规则 (&D)");
                POINT pt; GetCursorPos(&pt); SetForegroundWindow(hwnd);
                int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
                if (cmd == ID_RULE_EDIT_CMD) {
                    if (g_currentNodeIndex != -1) {
                        NodeConfig* cfg = &g_nodes[g_currentNodeIndex];
                        RuleDialogData data = {0};
                        strcpy(data.type, cfg->rule_list[sel].type);
                        strcpy(data.match, cfg->rule_list[sel].match);
                        strcpy(data.target, cfg->rule_list[sel].target);
                        data.mode = cfg->rule_list[sel].mode;
                        if (ShowRuleDialog(hwnd, &data)) {
                            strcpy(cfg->rule_list[sel].type, data.type);
                            strcpy(cfg->rule_list[sel].match, data.match);
                            strcpy(cfg->rule_list[sel].target, data.target);
                            cfg->rule_list[sel].mode = data.mode;
                            RefreshRuleListUI(cfg); SerializeRules(cfg); SaveConfig();
                        }
                    }
                } else if (cmd == ID_RULE_DEL) PostMessage(hwnd, WM_COMMAND, ID_RULE_DEL, 0);
            }
        }
        break;
    }

    case WM_COMMAND:
        if ((HIWORD(wParam) == EN_CHANGE || HIWORD(wParam) == CBN_SELCHANGE) && !g_isEditing && g_currentNodeIndex != -1) {
             GetControlValues(g_currentNodeIndex);
        }
        switch (LOWORD(wParam)) {
        case ID_RULE_ADD:
            if (g_currentNodeIndex != -1) {
                RuleDialogData data = {0};
                if (ShowRuleDialog(hwnd, &data)) {
                    NodeConfig* cfg = &g_nodes[g_currentNodeIndex];
                    if (cfg->rule_count < MAX_RULES) {
                        strcpy(cfg->rule_list[cfg->rule_count].type, data.type);
                        strcpy(cfg->rule_list[cfg->rule_count].match, data.match);
                        strcpy(cfg->rule_list[cfg->rule_count].target, data.target);
                        cfg->rule_list[cfg->rule_count].mode = data.mode;
                        cfg->rule_count++;
                        RefreshRuleListUI(cfg); SerializeRules(cfg); SaveConfig();
                    }
                }
            }
            break;
        case ID_RULE_DEL:
            if (g_currentNodeIndex != -1) {
                int sel = ListView_GetNextItem(hRuleListView, -1, LVNI_SELECTED);
                if (sel != -1) {
                    NodeConfig* cfg = &g_nodes[g_currentNodeIndex];
                    for (int i = sel; i < cfg->rule_count - 1; i++) cfg->rule_list[i] = cfg->rule_list[i+1];
                    cfg->rule_count--;
                    RefreshRuleListUI(cfg); SerializeRules(cfg); SaveConfig();
                }
            }
            break;
        case ID_START_SELECTED:
            if (g_currentNodeIndex != -1) { GetControlValues(g_currentNodeIndex); SaveConfig(); StartEngineForNode(g_currentNodeIndex, FALSE); } 
            else MessageBox(hwnd, "请先选择一个节点。", "提示", MB_OK);
            break;
        case ID_PING_TEST_BTN:
            if (g_currentNodeIndex != -1) { GetControlValues(g_currentNodeIndex); SaveConfig(); AppendLogAsync("\r\n[系统] 正在启动延迟测速 (Ping)... 请稍候...\r\n"); StartEngineForNode(g_currentNodeIndex, TRUE); } 
            else MessageBox(hwnd, "请选择一个要测速的节点。", "提示", MB_OK);
            break;
        case ID_STOP_SELECTED: if (g_currentNodeIndex != -1) StopSidecarForNode(g_currentNodeIndex); break;
        case ID_START_ALL: if(g_nodeCount > 0) { if(g_currentNodeIndex != -1) GetControlValues(g_currentNodeIndex); SaveConfig(); StartAll(); } break;
        case ID_STOP_ALL: StopAll(); break;
        case ID_CLEAR_LOG: SetWindowTextA(hLogEdit, ""); break;
        case ID_NODE_ADD: AddNewNode(NULL); break;
        case ID_NODE_DELETE: DeleteSelectedNode(); break;
        case ID_NODE_RENAME: RenameSelectedNode(); break;
        case ID_IMPORT_BTN: OnImportClicked(hwnd); break;
        case ID_EXPORT_BTN: OnExportClicked(hwnd); break;
        case ID_AUTOSTART_CHECK: {
            BOOL c = (SendMessage(hAutoStartCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
            if (!SetAutoStart(c)) { MessageBox(hwnd, "设置开机自启失败，请尝试以管理员身份运行本程序。", "错误", MB_OK); SendMessage(hAutoStartCheck, BM_SETCHECK, !c, 0); } 
            else g_autoStartEnabled = c;
            break;
        }
        case ID_TRAY_OPEN: ShowWindow(hwnd, SW_RESTORE); SetForegroundWindow(hwnd); break;
        case ID_TRAY_EXIT: DestroyWindow(hwnd); break;
        }
        break;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK || lParam == WM_LBUTTONUP) { ShowWindow(hwnd, SW_RESTORE); SetForegroundWindow(hwnd); }
        else if (lParam == WM_RBUTTONUP) { 
            POINT pt; GetCursorPos(&pt); HMENU hMenu = CreatePopupMenu(); 
            AppendMenu(hMenu, MF_STRING, ID_TRAY_OPEN, "打开主界面"); AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, "退出程序"); 
            SetForegroundWindow(hwnd); TrackPopupMenu(hMenu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN, pt.x, pt.y, 0, hwnd, NULL); 
            PostMessage(hwnd, WM_NULL, 0, 0); DestroyMenu(hMenu); 
        }
        break;

    case WM_APPEND_LOG: AppendLog((char*)lParam); free((void*)lParam); break;
    case WM_CLOSE: ShowWindow(hwnd, SW_HIDE); return 0;
    case WM_DESTROY:
        if(g_currentNodeIndex != -1) GetControlValues(g_currentNodeIndex);
        SaveConfig(); StopAll(); Shell_NotifyIcon(NIM_DELETE, &nid); PostQuitMessage(0);
        break;
    default: return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}




















// [部分 3/3] 辅助函数与工具类实现

LRESULT CALLBACK RuleDialogProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    RuleDialogData* data = (RuleDialogData*)GetProp(hwnd, "RULE_DATA");
    switch (uMsg) {
    case WM_CREATE: {
        int x = Scale(20), y = Scale(20), w = Scale(260), h = Scale(24); int gap = Scale(10);
        CreateWindow("STATIC", "匹配类型:", WS_VISIBLE | WS_CHILD, x, y, w, h, hwnd, NULL, hInst, NULL);
        HWND hCombo = CreateWindow("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST | WS_VSCROLL, x, y + h, w, Scale(140), hwnd, (HMENU)ID_DLG_TYPE, hInst, NULL);
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)"关键词 (Keyword)");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)"精准域名 (Domain)");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)"正则 (Regexp)");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)"Geosite (智能分流/去广告)");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)"GeoIP (国家/IP分流)");
        SendMessage(hCombo, CB_SETCURSEL, 0, 0); SendMessage(hCombo, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        y += h + h + gap;
        CreateWindow("STATIC", "匹配内容 (如 youtube, cn):", WS_VISIBLE | WS_CHILD, x, y, w, h, hwnd, NULL, hInst, NULL);
        HWND hMatch = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, x, y + h, w, h, hwnd, (HMENU)ID_DLG_MATCH, hInst, NULL);
        SendMessage(hMatch, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        y += h + h + gap;
        CreateWindow("STATIC", "目标节点 (如 us-node:443):", WS_VISIBLE | WS_CHILD, x, y, w, h, hwnd, NULL, hInst, NULL);
        HWND hTarget = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, x, y + h, w, h, hwnd, (HMENU)ID_DLG_TARGET, hInst, NULL);
        SendMessage(hTarget, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        y += h + h + gap;
        CreateWindow("STATIC", "连接策略:", WS_VISIBLE | WS_CHILD, x, y, w, h, hwnd, NULL, hInst, NULL);
        HWND hStrategy = CreateWindow("COMBOBOX", "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, x, y + h, w, Scale(100), hwnd, (HMENU)ID_DLG_STRATEGY, hInst, NULL);
        SendMessage(hStrategy, CB_ADDSTRING, 0, (LPARAM)"默认 (智能判断)");
        SendMessage(hStrategy, CB_ADDSTRING, 0, (LPARAM)"长连接 (Keep - 视频/游戏)");
        SendMessage(hStrategy, CB_ADDSTRING, 0, (LPARAM)"短连接 (Cut - 网页/爬虫)");
        SendMessage(hStrategy, CB_SETCURSEL, 0, 0); SendMessage(hStrategy, WM_SETFONT, (WPARAM)hFontUI, TRUE);

        y += h + h + gap + gap;
        int btnW = Scale(80);
        HWND hOk = CreateWindow("BUTTON", "确定", WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, x + Scale(40), y, btnW, Scale(30), hwnd, (HMENU)ID_DLG_OK, hInst, NULL);
        HWND hCancel = CreateWindow("BUTTON", "取消", WS_VISIBLE | WS_CHILD, x + Scale(40) + btnW + gap, y, btnW, Scale(30), hwnd, (HMENU)ID_DLG_CANCEL, hInst, NULL);
        SendMessage(hOk, WM_SETFONT, (WPARAM)hFontUI, TRUE); SendMessage(hCancel, WM_SETFONT, (WPARAM)hFontUI, TRUE);
        EnumChildWindows(hwnd, ApplyFontToChildren, (LPARAM)hFontUI);
        break;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == ID_DLG_OK) {
            if (!data) return 0;
            char typeText[64]; GetDlgItemTextA(hwnd, ID_DLG_TYPE, typeText, 64);
            if (strstr(typeText, "Keyword")) strcpy(data->type, "");
            else if (strstr(typeText, "Domain")) strcpy(data->type, "domain:");
            else if (strstr(typeText, "Regexp")) strcpy(data->type, "regexp:");
            else if (strstr(typeText, "Geosite")) strcpy(data->type, "geosite:");
            else if (strstr(typeText, "GeoIP")) strcpy(data->type, "geoip:");
            GetDlgItemTextA(hwnd, ID_DLG_MATCH, data->match, 256);
            GetDlgItemTextA(hwnd, ID_DLG_TARGET, data->target, 512);
            data->mode = SendMessage(GetDlgItem(hwnd, ID_DLG_STRATEGY), CB_GETCURSEL, 0, 0); 

            if (strlen(data->match) > 0 && strlen(data->target) > 0) { data->result = TRUE; DestroyWindow(hwnd); }
            else MessageBoxA(hwnd, "内容和目标不能为空！", "错误", MB_OK);
        } else if (LOWORD(wParam) == ID_DLG_CANCEL) { if(data) data->result = FALSE; DestroyWindow(hwnd); }
        break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

BOOL ShowRuleDialog(HWND parent, RuleDialogData* data) {
    HWND hDlg = CreateWindowEx(WS_EX_DLGMODALFRAME, "RuleEditorDlg", "编辑分流规则", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 0, 0, Scale(320), Scale(340), parent, NULL, hInst, NULL);
    RECT rcOwner, rcDlg; GetWindowRect(parent, &rcOwner); GetWindowRect(hDlg, &rcDlg);
    SetWindowPos(hDlg, 0, rcOwner.left + (rcOwner.right - rcOwner.left - (rcDlg.right - rcDlg.left)) / 2, rcOwner.top + (rcOwner.bottom - rcOwner.top - (rcDlg.bottom - rcDlg.top)) / 2, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    SetProp(hDlg, "RULE_DATA", (HANDLE)data);
    if (data) {
        SetDlgItemTextA(hDlg, ID_DLG_MATCH, data->match);
        SetDlgItemTextA(hDlg, ID_DLG_TARGET, data->target);
        HWND hCombo = GetDlgItem(hDlg, ID_DLG_TYPE);
        if (strcmp(data->type, "domain:") == 0) SendMessage(hCombo, CB_SETCURSEL, 1, 0);
        else if (strcmp(data->type, "regexp:") == 0) SendMessage(hCombo, CB_SETCURSEL, 2, 0);
        else if (strcmp(data->type, "geosite:") == 0) SendMessage(hCombo, CB_SETCURSEL, 3, 0);
        else if (strcmp(data->type, "geoip:") == 0) SendMessage(hCombo, CB_SETCURSEL, 4, 0);
        else SendMessage(hCombo, CB_SETCURSEL, 0, 0);
        SendMessage(GetDlgItem(hDlg, ID_DLG_STRATEGY), CB_SETCURSEL, data->mode, 0); 
    }
    EnableWindow(parent, FALSE);
    MSG msg; while (IsWindow(hDlg)) { if (GetMessage(&msg, NULL, 0, 0)) { if (!IsDialogMessage(hDlg, &msg)) { TranslateMessage(&msg); DispatchMessage(&msg); } } }
    EnableWindow(parent, TRUE); SetForegroundWindow(parent);
    return data->result;
}

void RefreshRuleListUI(NodeConfig* cfg) {
    ListView_DeleteAllItems(hRuleListView);
    for (int i = 0; i < cfg->rule_count; i++) {
        LVITEMA lvi = {0}; lvi.mask = LVIF_TEXT; lvi.iItem = i;
        char typeDisplay[32];
        if (strcmp(cfg->rule_list[i].type, "domain:") == 0) strcpy(typeDisplay, "精准域名");
        else if (strcmp(cfg->rule_list[i].type, "regexp:") == 0) strcpy(typeDisplay, "正则");
        else if (strcmp(cfg->rule_list[i].type, "geosite:") == 0) strcpy(typeDisplay, "Geosite");
        else if (strcmp(cfg->rule_list[i].type, "geoip:") == 0) strcpy(typeDisplay, "GeoIP");
        else strcpy(typeDisplay, "关键词");
        lvi.pszText = typeDisplay; ListView_InsertItem(hRuleListView, &lvi);
        ListView_SetItemText(hRuleListView, i, 1, cfg->rule_list[i].match);
        ListView_SetItemText(hRuleListView, i, 2, cfg->rule_list[i].target);
        char modeStr[32];
        if (cfg->rule_list[i].mode == 1) strcpy(modeStr, "Keep");
        else if (cfg->rule_list[i].mode == 2) strcpy(modeStr, "Cut");
        else strcpy(modeStr, "Auto");
        ListView_SetItemText(hRuleListView, i, 3, modeStr); 
    }
}

void SerializeRules(NodeConfig* cfg) {
    memset(cfg->rules_str, 0, MAX_RULE_LEN);
    for (int i = 0; i < cfg->rule_count; i++) {
        char suffix[16] = "";
        if (cfg->rule_list[i].mode == 1) strcpy(suffix, "|keep");
        else if (cfg->rule_list[i].mode == 2) strcpy(suffix, "|cut");
        char line[1024];
        sprintf(line, "%s%s,%s%s\r\n", cfg->rule_list[i].type, cfg->rule_list[i].match, cfg->rule_list[i].target, suffix);
        if (strlen(cfg->rules_str) + strlen(line) < MAX_RULE_LEN) strcat(cfg->rules_str, line);
    }
}

void ParseRulesString(NodeConfig* cfg) {
    cfg->rule_count = 0;
    if (strlen(cfg->rules_str) == 0) return;
    char* rulesCopy = _strdup(cfg->rules_str);
    char* line = my_strtok_s(rulesCopy, "\r\n", NULL);
    while (line && cfg->rule_count < MAX_RULES) {
        if (line[0] == '#') { line = my_strtok_s(NULL, "\r\n", NULL); continue; }
        char* comma = strchr(line, ',');
        if (comma) {
            *comma = '\0'; char* left = line; char* right = comma + 1;
            RoutingRule* r = &cfg->rule_list[cfg->rule_count];
            r->mode = 0; 
            size_t rlen = strlen(right);
            if (rlen > 5 && strcmp(right + rlen - 5, "|keep") == 0) { r->mode = 1; right[rlen-5] = '\0'; }
            else if (rlen > 4 && strcmp(right + rlen - 4, "|cut") == 0) { r->mode = 2; right[rlen-4] = '\0'; }
            strcpy(r->target, right);
            if (strncmp(left, "domain:", 7) == 0) { strcpy(r->type, "domain:"); strcpy(r->match, left + 7); }
            else if (strncmp(left, "regexp:", 7) == 0) { strcpy(r->type, "regexp:"); strcpy(r->match, left + 7); }
            else if (strncmp(left, "geosite:", 8) == 0) { strcpy(r->type, "geosite:"); strcpy(r->match, left + 8); }
            else if (strncmp(left, "geoip:", 6) == 0) { strcpy(r->type, "geoip:"); strcpy(r->match, left + 6); }
            else { strcpy(r->type, ""); strcpy(r->match, left); }
            cfg->rule_count++;
        }
        line = my_strtok_s(NULL, "\r\n", NULL);
    }
    free(rulesCopy);
}

void GetControlValues(int index) {
    if (index < 0 || index >= g_nodeCount) return;
    NodeConfig* cfg = &g_nodes[index];
    GetWindowTextA(hListenEdit, cfg->listen, sizeof(cfg->listen));
    GetWindowTextA(hServerUrlEdit, cfg->server, sizeof(cfg->server));
    GetWindowTextA(hIpEdit, cfg->ip, sizeof(cfg->ip));
    GetWindowTextA(hTokenEdit, cfg->token, sizeof(cfg->token));
    GetWindowTextA(hSecretKeyEdit, cfg->secret_key, sizeof(cfg->secret_key));
    GetWindowTextA(hFallbackIpEdit, cfg->fallback_ip, sizeof(cfg->fallback_ip));
    GetWindowTextA(hS5Edit, cfg->s5, sizeof(cfg->s5)); 
    GetWindowTextA(hTrafficMinEdit, cfg->traffic_min, sizeof(cfg->traffic_min));
    GetWindowTextA(hTrafficMaxEdit, cfg->traffic_max, sizeof(cfg->traffic_max));
    GetWindowTextA(hTimeoutCapEdit, cfg->timeout_cap, sizeof(cfg->timeout_cap));
    GetWindowTextA(hExemptListEdit, cfg->exempt_list, sizeof(cfg->exempt_list));
    cfg->global_keep_alive = (SendMessage(hImmersionCheck, BM_GETCHECK, 0, 0) == BST_CHECKED);
    SerializeRules(cfg);
    cfg->routing_mode = SendMessage(hRoutingModeCombo, CB_GETCURSEL, 0, 0);
    cfg->strategy_mode = SendMessage(hStrategyCombo, CB_GETCURSEL, 0, 0); 
}

void SetControlValues(int index) {
    g_isEditing = TRUE;
    NodeConfig* cfg = (index != -1) ? &g_nodes[index] : NULL;
    SetWindowTextA(hListenEdit, cfg ? cfg->listen : "");
    SetWindowTextA(hServerUrlEdit, cfg ? cfg->server : "");
    SetWindowTextA(hIpEdit, cfg ? cfg->ip : "");
    SetWindowTextA(hTokenEdit, cfg ? cfg->token : "");
    SetWindowTextA(hSecretKeyEdit, cfg ? cfg->secret_key : "");
    SetWindowTextA(hFallbackIpEdit, cfg ? cfg->fallback_ip : "");
    SetWindowTextA(hS5Edit, cfg ? cfg->s5 : "");
    SetWindowTextA(hTrafficMinEdit, cfg ? cfg->traffic_min : "8");
    SetWindowTextA(hTrafficMaxEdit, cfg ? cfg->traffic_max : "12");
    SetWindowTextA(hTimeoutCapEdit, cfg ? cfg->timeout_cap : "5000");
    SetWindowTextA(hExemptListEdit, cfg ? cfg->exempt_list : "");
    SendMessage(hImmersionCheck, BM_SETCHECK, (cfg && cfg->global_keep_alive) ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(hRoutingModeCombo, CB_SETCURSEL, (WPARAM)(cfg ? cfg->routing_mode : 0), 0);
    SendMessage(hStrategyCombo, CB_SETCURSEL, (WPARAM)(cfg ? cfg->strategy_mode : 0), 0);
    if (cfg) { if (cfg->rule_count == 0 && strlen(cfg->rules_str) > 0) ParseRulesString(cfg); RefreshRuleListUI(cfg); } else { ListView_DeleteAllItems(hRuleListView); }
    BOOL enable = (index != -1);
    EnableWindow(hListenEdit, enable); EnableWindow(hServerUrlEdit, enable); 
    EnableWindow(hIpEdit, enable); EnableWindow(hTokenEdit, enable); 
    EnableWindow(hSecretKeyEdit, enable); EnableWindow(hFallbackIpEdit, enable);
    EnableWindow(hS5Edit, enable); EnableWindow(hRoutingModeCombo, enable); 
    EnableWindow(hStrategyCombo, enable); EnableWindow(hRuleListView, enable);
    EnableWindow(hImmersionCheck, enable); 
    EnableWindow(hTrafficMinEdit, enable); EnableWindow(hTrafficMaxEdit, enable);
    EnableWindow(hTimeoutCapEdit, enable); EnableWindow(hExemptListEdit, enable);
    g_isEditing = FALSE;
}

void InitDefaultNode() {
    g_nodeCount = 1;
    NodeConfig* node = &g_nodes[0];
    strcpy(node->name, "默认节点");
    strcpy(node->listen, "127.0.0.1:10808");
    strcpy(node->server, "cdn.worker.dev:443");
    strcpy(node->token, "my-password");
    strcpy(node->secret_key, "my-secret-key-888");
    strcpy(node->traffic_min, "8"); strcpy(node->traffic_max, "12"); strcpy(node->timeout_cap, "5000");
    node->exempt_list[0] = '\0';
    strcpy(node->rules_str, "youtube,cdn.worker.dev:443|keep\r\ndomain:v2fly.org,worker2.dev:443"); 
    ParseRulesString(node);
    node->ip[0] = '\0'; node->fallback_ip[0] = '\0'; node->s5[0] = '\0'; 
    node->isRunning = FALSE; node->routing_mode = 0; node->strategy_mode = 0; node->global_keep_alive = FALSE;
}

void AddNewNode(NodeConfig* initialData) { 
    if (g_nodeCount >= MAX_NODES) return;
    NodeConfig* node = &g_nodes[g_nodeCount];
    if (initialData) memcpy(node, initialData, sizeof(NodeConfig));
    else if (g_currentNodeIndex != -1) { 
        memcpy(node, &g_nodes[g_currentNodeIndex], sizeof(NodeConfig)); 
        node->isRunning = FALSE; 
        char tempName[MAX_NAME_LEN]; snprintf(tempName, sizeof(tempName), "%s (副本)", g_nodes[g_currentNodeIndex].name); strcpy(node->name, tempName);
    } else { 
        memset(node, 0, sizeof(NodeConfig));
        strcpy(node->name, "新节点"); strcpy(node->listen, "127.0.0.1:10808"); strcpy(node->server, "cdn.worker.dev:443");
        strcpy(node->token, "my-password"); strcpy(node->secret_key, "my-secret-key-888");
        strcpy(node->traffic_min, "8"); strcpy(node->traffic_max, "12"); strcpy(node->timeout_cap, "5000");
        node->routing_mode = 0; node->strategy_mode = 0; node->rule_count = 0; memset(node->rules_str, 0, sizeof(node->rules_str));
    }
    g_nodeCount++; RefreshNodeList();
    ListView_SetItemState(hNodeListView, g_nodeCount - 1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED); 
    ListView_EnsureVisible(hNodeListView, g_nodeCount - 1, FALSE);
}

void DeleteSelectedNode() { 
    if (g_currentNodeIndex == -1) return;
    
    if (g_nodes[g_currentNodeIndex].isRunning) { 
        MessageBox(hMainWindow, "请先停止节点再删除。", "提示", MB_OK); 
        return; 
    } 
    
    if (MessageBox(hMainWindow, "确定要删除选中的节点吗？", "确认删除", MB_YESNO | MB_ICONWARNING) == IDYES) { 
        for (int i = g_currentNodeIndex; i < g_nodeCount - 1; i++) {
            g_nodes[i] = g_nodes[i+1];
        }
        g_nodeCount--; 
        g_currentNodeIndex = -1; 
        RefreshNodeList(); 
        
        // [修复] 加上大括号，防止宏展开错误
        if (g_nodeCount > 0) {
            ListView_SetItemState(hNodeListView, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED); 
        } else {
            SwitchNode(-1); 
        }
        
        SaveConfig(); 
    } 
}

void RenameSelectedNode() {
    if (g_currentNodeIndex == -1) return;
    char newNameAnsi[MAX_NAME_LEN]; Utf8ToAnsi(g_nodes[g_currentNodeIndex].name, newNameAnsi, sizeof(newNameAnsi));
    if (ShowInputDialog(hMainWindow, "重命名", "请输入新的节点别名:", newNameAnsi, sizeof(newNameAnsi))) {
        char newNameUtf8[MAX_NAME_LEN]; AnsiToUtf8(newNameAnsi, newNameUtf8, sizeof(newNameUtf8));
        strcpy(g_nodes[g_currentNodeIndex].name, newNameUtf8); RefreshNodeList(); 
        ListView_SetItemState(hNodeListView, g_currentNodeIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED); SaveConfig();
    }
}

void OnImportClicked(HWND hwnd) {
    if (!OpenClipboard(hwnd)) return;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (!hData) { CloseClipboard(); return; }
    char* clipText = (char*)GlobalLock(hData);
    if (!clipText) { CloseClipboard(); return; }
    char* clipTextCopy = _strdup(clipText);
    GlobalUnlock(hData); CloseClipboard();
    if (!clipTextCopy) return;
    int importCount = 0; char* line_context = NULL; char* line = my_strtok_s(clipTextCopy, "\r\n", &line_context);
    while (line) {
        while (*line == ' ' || *line == '\t') line++;
        if (strncmp(line, "xlink://", 8) != 0) { line = my_strtok_s(NULL, "\r\n", &line_context); continue; }
        char uri_utf8[MAX_URL_LEN * 3]; AnsiToUtf8(line, uri_utf8, sizeof(uri_utf8));
        NodeConfig n = {0}; strcpy(n.listen, "127.0.0.1:10808");
        strcpy(n.traffic_min, "8"); strcpy(n.traffic_max, "12"); strcpy(n.timeout_cap, "5000");
        char* p = uri_utf8 + 8;
        char* hash = strrchr(p, '#'); if (hash) { *hash = '\0'; strncpy(n.name, hash + 1, sizeof(n.name) - 1); }
        char* q = strchr(p, '?');
        if (q) {
            char* params_copy = _strdup(q + 1); *q = '\0';
            if (params_copy) {
                char* param_context = NULL; char* param = my_strtok_s(params_copy, "&", &param_context);
                while (param) {
                    char* v = strchr(param, '=');
                    if (v) {
                        *v++ = '\0';
                        if (!strcmp(param, "key")) strncpy(n.secret_key, v, sizeof(n.secret_key)-1);
                        else if (!strcmp(param, "fallback")) strncpy(n.fallback_ip, v, sizeof(n.fallback_ip)-1);
                        else if (!strcmp(param, "ip")) strncpy(n.ip, v, sizeof(n.ip)-1);
                        else if (!strcmp(param, "s5")) strncpy(n.s5, v, sizeof(n.s5)-1);
                        else if (!strcmp(param, "route") && !strcmp(v, "cn")) n.routing_mode = 1;
                        else if (!strcmp(param, "strategy")) { if (!strcmp(v, "rr")) n.strategy_mode = 1; else if (!strcmp(v, "hash")) n.strategy_mode = 2; }
                        else if (!strcmp(param, "rules")) {
                            char decoded_rules[MAX_RULE_LEN] = {0}; char* dst = decoded_rules;
                            for (char* src = v; *src && ((size_t)(dst - decoded_rules) < sizeof(decoded_rules)-3); src++) { if (*src == '|') { *dst++ = '\r'; *dst++ = '\n'; } else { *dst++ = *src; } } *dst = '\0';
                            strncpy(n.rules_str, decoded_rules, sizeof(n.rules_str)-1); ParseRulesString(&n);
                        }
                    } param = my_strtok_s(NULL, "&", &param_context);
                } free(params_copy);
            }
        }
        char* at = strrchr(p, '@'); if (at) { strncpy(n.server, at + 1, sizeof(n.server)-1); *at = '\0'; strncpy(n.token, p, sizeof(n.token)-1); } else strncpy(n.server, p, sizeof(n.server)-1);
        if (!strlen(n.name)) strncpy(n.name, n.server, sizeof(n.name)-1);
        AddNewNode(&n); importCount++; line = my_strtok_s(NULL, "\r\n", &line_context);
    }
    free(clipTextCopy);
    if (importCount > 0) {
        char msg[128]; snprintf(msg, sizeof(msg), "成功新增 %d 个节点！", importCount);
        MessageBox(hwnd, msg, "导入成功", MB_OK | MB_ICONINFORMATION);
        if (g_nodeCount > 0) { ListView_SetItemState(hNodeListView, g_nodeCount - 1, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED); ListView_EnsureVisible(hNodeListView, g_nodeCount - 1, FALSE); }
    } else MessageBox(hwnd, "剪贴板中未检测到有效的 xlink:// 链接。", "提示", MB_OK | MB_ICONWARNING);
}

void OnExportClicked(HWND hwnd) {
    if (g_currentNodeIndex < 0) return;
    GetControlValues(g_currentNodeIndex); NodeConfig* n = &g_nodes[g_currentNodeIndex];
    SerializeRules(n);
    char uri_utf8[MAX_URL_LEN*3] = {0}, params[MAX_URL_LEN*2]={0}, tmp[MAX_URL_LEN]; BOOL first_param = TRUE;
    if (strlen(n->secret_key) > 0) { snprintf(tmp, sizeof(tmp), "%skey=%s", first_param?"":"&", n->secret_key); strcat(params, tmp); first_param = FALSE; }
    if (strlen(n->fallback_ip) > 0) { snprintf(tmp, sizeof(tmp), "%sfallback=%s", first_param?"":"&", n->fallback_ip); strcat(params, tmp); first_param = FALSE; }
    if (strlen(n->ip) > 0) { snprintf(tmp, sizeof(tmp), "%sip=%s", first_param?"":"&", n->ip); strcat(params, tmp); first_param = FALSE; }
    if (strlen(n->s5) > 0) { snprintf(tmp, sizeof(tmp), "%ss5=%s", first_param?"":"&", n->s5); strcat(params, tmp); first_param = FALSE; }
    if (n->routing_mode == 1) { snprintf(tmp, sizeof(tmp), "%sroute=cn", first_param?"":"&"); strcat(params, tmp); first_param = FALSE; }
    if (strlen(n->rules_str) > 0) {
        char rulesEncoded[MAX_RULE_LEN] = {0}; int ri = 0;
        for (int i = 0; n->rules_str[i] && ri < MAX_RULE_LEN - 1; i++) {
            if (n->rules_str[i] == '\r') continue;
            if (n->rules_str[i] == '\n') rulesEncoded[ri++] = '|'; else rulesEncoded[ri++] = n->rules_str[i];
        } 
        if(ri > 0) { snprintf(tmp, sizeof(tmp), "%srules=%s", first_param ? "" : "&", rulesEncoded); strcat(params, tmp); }
    }
    snprintf(uri_utf8, sizeof(uri_utf8), "xlink://%s@%s%s%s#%s", n->token, n->server, strlen(params) > 0 ? "?" : "", params, n->name);
    char uri_ansi[MAX_URL_LEN*3]; Utf8ToAnsi(uri_utf8, uri_ansi, sizeof(uri_ansi));
    if (OpenClipboard(hwnd)) { EmptyClipboard(); HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, strlen(uri_ansi) + 1); if (h) { strcpy((char*)GlobalLock(h), uri_ansi); GlobalUnlock(h); SetClipboardData(CF_TEXT, h); } CloseClipboard(); MessageBox(hwnd, "配置已复制到剪贴板！", "成功", MB_OK); }
}

void StartEngineForNode(int nodeIndex, BOOL isTest) {
    if (nodeIndex < 0 || nodeIndex >= g_nodeCount) return;
    if (!isTest && g_nodes[nodeIndex].isRunning) StopSidecarForNode(nodeIndex);
    if (!isTest) MimicOldLogStartForNode(nodeIndex);
    
    NodeConfig* n = &g_nodes[nodeIndex];
    SidecarEngineStatus* status = &g_engineStatuses[nodeIndex];
    PROCESS_INFORMATION tempPI = {0};
    PROCESS_INFORMATION* pTargetPI = isTest ? &tempPI : &status->xlink_pi;

    char xlink_executable[SAFE_PATH_LEN];
    snprintf(xlink_executable, SAFE_PATH_LEN, "%s\\xlink-cli-binary.exe", g_exeDir);
    if (GetFileAttributesA(xlink_executable) == INVALID_FILE_ATTRIBUTES) { 
        AppendLogAsync("[错误] 核心文件 xlink-cli-binary.exe 不存在！\r\n"); return; 
    }

    if (isTest) {
        char safeServerList[MAX_URL_LEN];
        memset(safeServerList, 0, sizeof(safeServerList));
        strncpy(safeServerList, n->server, MAX_URL_LEN - 1);
        for(int i = 0; safeServerList[i] != '\0'; i++) if(safeServerList[i] == '\r' || safeServerList[i] == '\n') safeServerList[i] = ';';
        char cmdLine[16384];
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\" --ping --server=\"%s\" --key=\"%s\" --ip=\"%s\"", xlink_executable, safeServerList, n->secret_key, n->ip);
        SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
        HANDLE hRead, hWrite; CreatePipe(&hRead, &hWrite, &sa, 0);
        STARTUPINFOA si = {0}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si.hStdOutput = hWrite; si.hStdError = hWrite; si.wShowWindow = SW_HIDE;    
        if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, g_exeDir, &si, pTargetPI)) { AppendLogAsync("[系统] 错误: 启动测速进程失败！\r\n"); CloseHandle(hRead); CloseHandle(hWrite); return; }
        CloseHandle(hWrite);
        LogThreadParam* param = (LogThreadParam*)malloc(sizeof(LogThreadParam));
        if(param) { param->hPipe = hRead; param->nodeIndex = nodeIndex; HANDLE hThread = CreateThread(NULL, 0, LogReaderThread, param, 0, NULL); CloseHandle(hThread); CloseHandle(tempPI.hProcess); CloseHandle(tempPI.hThread); }
        return; 
    }

    char listen_addr[MAX_SMALL_LEN]; 
    strcpy(listen_addr, n->listen);
    if (n->routing_mode == 1) { 
        n->xlink_internal_port = FindFreePort(); 
        snprintf(listen_addr, sizeof(listen_addr), "127.0.0.1:%d", n->xlink_internal_port); 
    }

    char config_path[SAFE_PATH_LEN];
    snprintf(config_path, SAFE_PATH_LEN, "%s\\config_core_%d.json", g_exeDir, nodeIndex);

    FILE* f = fopen(config_path, "w");
    if (!f) { AppendLogAsync("[系统] 错误: 创建内核配置文件失败！\r\n"); return; }

    char safeServerList[MAX_URL_LEN];
    memset(safeServerList, 0, sizeof(safeServerList));
    strncpy(safeServerList, n->server, MAX_URL_LEN - 1);
    for(int i = 0; safeServerList[i] != '\0'; i++) if(safeServerList[i] == '\r' || safeServerList[i] == '\n') safeServerList[i] = ';';

    SerializeRules(n);
    char safeRules[MAX_RULE_LEN * 2] = {0}; 
    char* src = n->rules_str; char* dst = safeRules;
    while (*src && (dst - safeRules < (int)sizeof(safeRules) - 2)) {
        if (*src == '\"' || *src == '\\') *dst++ = '\\';
        if (*src == '\r') { src++; continue; } 
        if (*src == '\n') { *dst++ = '\\'; *dst++ = 'n'; src++; continue; }
        *dst++ = *src++;
    }
    *dst = '\0';
    
    char token_str[MAX_URL_LEN] = {0};
    strcpy(token_str, n->secret_key);
    if (strlen(n->fallback_ip) > 0) { strcat(token_str, "|"); strcat(token_str, n->fallback_ip); }
    
    fprintf(f, "{\n  \"inbounds\": [{\"tag\": \"socks-in\", \"listen\": \"%s\", \"protocol\": \"socks\"}],\n  \"outbounds\": [{\n    \"tag\": \"proxy\",\n    \"protocol\": \"ech-proxy\",\n    \"settings\": {\n      \"server\": \"%s\",\n      \"server_ip\": \"%s\",\n      \"token\": \"%s\",\n      \"strategy\": \"%s\",\n      \"rules\": \"%s\",\n", listen_addr, safeServerList, n->ip, token_str, (n->strategy_mode == 1) ? "rr" : ((n->strategy_mode == 2) ? "hash" : "random"), safeRules);
    fprintf(f, "      \"global_keep_alive\": %s,\n", n->global_keep_alive ? "true" : "false");
    
    int tMin = atoi(n->traffic_min); if(tMin<=0) tMin=0;
    int tMax = atoi(n->traffic_max); if(tMax<=0) tMax=0;
    int tCap = atoi(n->timeout_cap); if(tCap<=0) tCap=0;
    
    fprintf(f, "      \"traffic_min\": %d,\n      \"traffic_max\": %d,\n      \"timeout_cap\": %d,\n      \"exempt_list\": \"%s\",\n      \"s5\": \"%s\"\n    }\n  }]\n}\n", tMin, tMax, tCap, n->exempt_list, n->s5);
    fclose(f);

    char cmdLine[SAFE_PATH_LEN * 2];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" -c \"%s\"", xlink_executable, config_path);
    
    SECURITY_ATTRIBUTES sa_xlink = {sizeof(sa_xlink), NULL, TRUE};
    HANDLE hRead_xlink, hWrite_xlink; CreatePipe(&hRead_xlink, &hWrite_xlink, &sa_xlink, 0);
    STARTUPINFOA si_xlink = {0}; si_xlink.cb = sizeof(si_xlink); si_xlink.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW; si_xlink.hStdOutput = hWrite_xlink; si_xlink.hStdError = hWrite_xlink; si_xlink.wShowWindow = SW_HIDE;    
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, g_exeDir, &si_xlink, &status->xlink_pi)) { AppendLogAsync("[系统] 错误: 启动内核失败！\r\n"); CloseHandle(hRead_xlink); CloseHandle(hWrite_xlink); return; }
    CloseHandle(hWrite_xlink);

    if (!isTest) status->hLogPipeRead = hRead_xlink;
    LogThreadParam* param = (LogThreadParam*)malloc(sizeof(LogThreadParam)); 
    if(param) { param->hPipe = hRead_xlink; param->nodeIndex = nodeIndex; HANDLE hThread = CreateThread(NULL, 0, LogReaderThread, param, 0, NULL); if (isTest) { CloseHandle(hThread); CloseHandle(tempPI.hProcess); CloseHandle(tempPI.hThread); } else status->hLogThread = hThread; }

    if (n->routing_mode == 1 && !isTest) {
        char xray_config_path[SAFE_PATH_LEN]; snprintf(xray_config_path, SAFE_PATH_LEN, "%s\\config_xray_%d.json", g_exeDir, nodeIndex);
        if (!GenerateXrayConfigFile(nodeIndex, xray_config_path)) { AppendLogAsync("[系统] 错误: 生成 Xray 配置文件失败。\r\n"); StopSidecarForNode(nodeIndex); return; }
        char xray_executable[SAFE_PATH_LEN]; snprintf(xray_executable, SAFE_PATH_LEN, "%s\\xray.exe", g_exeDir);
        char xray_cmd[SAFE_PATH_LEN * 2]; snprintf(xray_cmd, sizeof(xray_cmd), "\"%s\" run -c \"%s\"", xray_executable, xray_config_path);
        STARTUPINFOA si_xray = {0}; si_xray.cb = sizeof(si_xray); si_xray.wShowWindow = SW_HIDE;
        if (!CreateProcessA(NULL, xray_cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, g_exeDir, &si_xray, &status->xray_pi)) { AppendLogAsync("[系统] 错误: 启动 Xray 前端失败！请检查 xray.exe 是否存在。\r\n"); StopSidecarForNode(nodeIndex); return; }
    }
    if (!isTest) { n->isRunning = TRUE; status->runningNodeIndex = nodeIndex; RefreshNodeList(); }
}

BOOL FileExists(const char* filename) { char path[SAFE_PATH_LEN]; snprintf(path, SAFE_PATH_LEN, "%s\\%s", g_exeDir, filename); return (_access(path, 0) != -1); }
void StopSidecarForNode(int nodeIndex) { if (nodeIndex < 0 || nodeIndex >= g_nodeCount || !g_nodes[nodeIndex].isRunning) return; SidecarEngineStatus* status = &g_engineStatuses[nodeIndex]; if (status->xray_pi.hProcess) { TerminateProcess(status->xray_pi.hProcess, 0); CloseHandle(status->xray_pi.hProcess); CloseHandle(status->xray_pi.hThread); } if (status->xlink_pi.hProcess) { TerminateProcess(status->xlink_pi.hProcess, 0); CloseHandle(status->xlink_pi.hProcess); CloseHandle(status->xlink_pi.hThread); } if (status->hLogThread) { TerminateThread(status->hLogThread, 0); CloseHandle(status->hLogThread); } if (status->hLogPipeRead) CloseHandle(status->hLogPipeRead); g_nodes[nodeIndex].isRunning = FALSE; memset(status, 0, sizeof(SidecarEngineStatus)); char node_name_ansi[MAX_NAME_LEN]; Utf8ToAnsi(g_nodes[nodeIndex].name, node_name_ansi, sizeof(node_name_ansi)); char log_msg[256]; snprintf(log_msg, sizeof(log_msg), "[系统] 节点 '%s' 已停止。\r\n", node_name_ansi); AppendLogAsync(log_msg); RefreshNodeList(); }
int FindFreePort() { srand((unsigned int)time(NULL) * GetCurrentThreadId()); return 49152 + (rand() % 16383); }
void ApplyFont(HWND hCtrl, HFONT hFont) { SendMessage(hCtrl, WM_SETFONT, (WPARAM)hFont, TRUE); }
BOOL CALLBACK ApplyFontToChildren(HWND hwnd, LPARAM lParam) { SendMessage(hwnd, WM_SETFONT, (WPARAM)lParam, TRUE); return TRUE; }
int Scale(int x) { return MulDiv(x, g_dpi, 96); }
void SaveConfig() { char p[SAFE_PATH_LEN]; snprintf(p, SAFE_PATH_LEN, "%s\\xlink_config.dat", g_exeDir); size_t sz = sizeof(int) + g_nodeCount * sizeof(NodeConfig); char* buf = (char*)malloc(sz); if (!buf) return; memcpy(buf, &g_nodeCount, sizeof(int)); memcpy(buf + sizeof(int), g_nodes, g_nodeCount * sizeof(NodeConfig)); DATA_BLOB in = {sz, (BYTE*)buf}, out; if (CryptProtectData(&in, L"XLinkV4", NULL, NULL, NULL, 0, &out)) { FILE* f = fopen(p, "wb"); if (f) { fwrite(out.pbData, 1, out.cbData, f); fclose(f); } LocalFree(out.pbData); } free(buf); }
void LoadConfig() { char p[SAFE_PATH_LEN]; snprintf(p, SAFE_PATH_LEN, "%s\\xlink_config.dat", g_exeDir); FILE* f = fopen(p, "rb"); if (!f) return; fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET); if (sz <= 0) { fclose(f); return; } char* buf = (char*)malloc(sz); fread(buf, 1, sz, f); fclose(f); DATA_BLOB in = {(DWORD)sz, (BYTE*)buf}, out; if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) { if (out.cbData > sizeof(int)) { memcpy(&g_nodeCount, out.pbData, sizeof(int)); if (g_nodeCount > 0 && g_nodeCount <= MAX_NODES) { memcpy(g_nodes, out.pbData + sizeof(int), g_nodeCount * sizeof(NodeConfig)); } else { g_nodeCount = 0; } } LocalFree(out.pbData); } free(buf); for (int i = 0; i < g_nodeCount; i++) { g_nodes[i].isRunning = FALSE; } memset(g_engineStatuses, 0, sizeof(g_engineStatuses)); }
void AppendLog(const char* t) { if (!IsWindow(hLogEdit)) return; int len = GetWindowTextLengthA(hLogEdit); if (len > 100000) { SendMessageA(hLogEdit, EM_SETSEL, 0, 50000); SendMessageA(hLogEdit, EM_REPLACESEL, 0, (LPARAM)"[... 日志已截断 ...]\r\n"); } len = GetWindowTextLengthA(hLogEdit); SendMessageA(hLogEdit, EM_SETSEL, len, len); SendMessageA(hLogEdit, EM_REPLACESEL, 0, (LPARAM)t); }
void AppendLogAsync(const char* t) { char* m = _strdup(t); if (m) { PostMessage(hMainWindow, WM_APPEND_LOG, 0, (LPARAM)m); } }
void Utf8ToAnsi(const char* utf8, char* ansi, int ansiLen) { int wide_len = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0); if (wide_len == 0) { strncpy(ansi, utf8, ansiLen - 1); ansi[ansiLen - 1] = '\0'; return; } WCHAR* wide_buf = (WCHAR*)malloc(wide_len * sizeof(WCHAR)); if (!wide_buf) return; MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide_buf, wide_len); WideCharToMultiByte(CP_ACP, 0, wide_buf, -1, ansi, ansiLen, NULL, NULL); free(wide_buf); }
void AnsiToUtf8(const char* ansi, char* utf8, int utf8Len) { int wide_len = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0); WCHAR* wide_buf = (WCHAR*)malloc(wide_len * sizeof(WCHAR)); MultiByteToWideChar(CP_ACP, 0, ansi, -1, wide_buf, wide_len); WideCharToMultiByte(CP_UTF8, 0, wide_buf, -1, utf8, utf8Len, NULL, NULL); free(wide_buf); }
void MimicOldLogStartForNode(int n) { char t[64]; time_t now = time(NULL); strftime(t, 64, "%H:%M:%S", localtime(&now)); char node_name_ansi[MAX_NAME_LEN]; Utf8ToAnsi(g_nodes[n].name, node_name_ansi, sizeof(node_name_ansi)); char b_ansi[512]; snprintf(b_ansi, 512, "[%s] [%s] [系统] 加载配置...\r\n[%s] [%s] [系统] 监听端口: %s\r\n", t, node_name_ansi, t, node_name_ansi, g_nodes[n].listen); AppendLogAsync(b_ansi); }
void TranslateLog(const char* original_log_utf8, int nodeIndex) { 
    char final_log_ansi[8192]; char node_name_ansi[MAX_NAME_LEN]; Utf8ToAnsi(g_nodes[nodeIndex].name, node_name_ansi, sizeof(node_name_ansi)); 
    char log_line_ansi[8192]; Utf8ToAnsi(original_log_utf8, log_line_ansi, sizeof(log_line_ansi)); 
    char *line = log_line_ansi, *next_line; 
    while (line && (next_line = strchr(line, '\n'))) { 
        *next_line = '\0'; if (next_line > line && *(next_line - 1) == '\r') *(next_line - 1) = '\0'; 
        if (strlen(line) == 0) { line = next_line + 1; continue; } 
        char timestamp[32]; time_t now = time(NULL); strftime(timestamp, sizeof(timestamp), "%H:%M:%S", localtime(&now)); 
        const char* content = line; 
        if (strstr(content, "[CLI]")) content = strstr(content, "[CLI]") + 6; else if (strstr(content, "[Core]")) content = strstr(content, "[Core]") + 7; 
        char* pTunnel = strstr(line, "Tunnel ->");
        if (pTunnel) { char sni[128]={0}, real[128]={0}, latency[32]={0}; char* pL = strstr(line, "Latency: "); if (pL) strcpy(latency, pL + 9); else strcpy(latency, "N/A"); sscanf(pTunnel, "Tunnel -> %127s (SNI) >>> %127s (Real)", sni, real); char* space = strchr(real, ' '); if(space) *space = '\0'; snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [内核] 隧道建立: 伪装(%s) ==> 物理(%s) [延迟: %s]\r\n", timestamp, node_name_ansi, sni, real, latency); }
        else if (strstr(line, "Rule Hit ->")) { char target[128] = {0}, node[128] = {0}, rule[128] = {0}; char* pRule = strstr(line, "Rule Hit ->"); sscanf(pRule, "Rule Hit -> %127s | SNI: %127s (Rule: %127[^,])", target, node, rule); snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [规则] 命中: %-25s -> %s (关键词: %s)\r\n", timestamp, node_name_ansi, target, node, rule); } 
        else if (strstr(line, "LB ->")) { char target[128] = {0}, node[128] = {0}, algo[32] = {0}; char* pLB = strstr(line, "LB ->"); sscanf(pLB, "LB -> %127s | SNI: %127s | Algo: %31s", target, node, algo); if(strstr(algo, "random")) strcpy(algo, "随机"); else if(strstr(algo, "rr")) strcpy(algo, "轮询"); else if(strstr(algo, "hash")) strcpy(algo, "哈希"); snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [负载] 访问: %-25s -> %s (策略: %s)\r\n", timestamp, node_name_ansi, target, node, algo); }
        else if (strstr(line, "[Stats]")) { char target[128]={0}, up[32]={0}, down[32]={0}, dur[32]={0}; char* pUp = strstr(line, "Up: "); char* pDown = strstr(line, "Down: "); char* pTime = strstr(line, "Time: "); if (pUp && pDown && pTime) { char* pTargetStart = strstr(line, "[Stats] ") + 8; char* pTargetEnd = strstr(pTargetStart, " |"); if (pTargetEnd) { int len = pTargetEnd - pTargetStart; if (len > 127) len = 127; strncpy(target, pTargetStart, len); } sscanf(pUp, "Up: %[^|]", up); sscanf(pDown, "Down: %[^|]", down); strcpy(dur, pTime + 6); if(strlen(up)>0) up[strlen(up)-1] = '\0'; if(strlen(down)>0) down[strlen(down)-1] = '\0'; snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [统计] 结束: %s (上行:%s / 下行:%s) 时长:%s\r\n", timestamp, node_name_ansi, target, up, down, dur); } }
        else if (strstr(line, "Ping Test Report")) snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [测速] --- 延迟测试报告 ---\r\n", timestamp, node_name_ansi);
        else if (strstr(line, "Successful Nodes")) snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [测速] 成功节点:\r\n", timestamp, node_name_ansi);
        else if (strstr(line, "Failed Nodes")) snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [测速] 失败节点:\r\n", timestamp, node_name_ansi);
        else if (strstr(line, "Delay:")) snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [测速] %s\r\n", timestamp, node_name_ansi, line);
        else if (strstr(line, "Error:")) snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [测速] %s\r\n", timestamp, node_name_ansi, line);
        else snprintf(final_log_ansi, sizeof(final_log_ansi), "[%s] [%s] [内核] %s\r\n", timestamp, node_name_ansi, content); 
        AppendLogAsync(final_log_ansi); line = next_line + 1; 
    } 
}
DWORD WINAPI LogReaderThread(LPVOID lp) { LogThreadParam* p = (LogThreadParam*)lp; HANDLE hPipe = p->hPipe; int nodeIndex = p->nodeIndex; free(p); char buffer[4096]; DWORD bytesRead; while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) { buffer[bytesRead] = '\0'; TranslateLog(buffer, nodeIndex); } return 0; }
INT_PTR CALLBACK InputDialogProc(HWND h, UINT m, WPARAM w, LPARAM l) { static InputDialogData* data; switch (m) { case WM_INITDIALOG: { data = (InputDialogData*)l; SendMessage(GetDlgItem(h, 2000), WM_SETFONT, (WPARAM)hFontUI, TRUE); SendMessage(GetDlgItem(h, ID_INPUT_EDIT), WM_SETFONT, (WPARAM)hFontUI, TRUE); SendMessage(GetDlgItem(h, ID_INPUT_OK), WM_SETFONT, (WPARAM)hFontUI, TRUE); SendMessage(GetDlgItem(h, ID_INPUT_CANCEL), WM_SETFONT, (WPARAM)hFontUI, TRUE); int lenT = MultiByteToWideChar(CP_ACP, 0, data->title, -1, NULL, 0); WCHAR* wTitle = (WCHAR*)malloc(lenT * sizeof(WCHAR)); if (wTitle) { MultiByteToWideChar(CP_ACP, 0, data->title, -1, wTitle, lenT); SetWindowTextW(h, wTitle); free(wTitle); } int lenP = MultiByteToWideChar(CP_ACP, 0, data->prompt, -1, NULL, 0); WCHAR* wPrompt = (WCHAR*)malloc(lenP * sizeof(WCHAR)); if (wPrompt) { MultiByteToWideChar(CP_ACP, 0, data->prompt, -1, wPrompt, lenP); SetDlgItemTextW(h, 2000, wPrompt); free(wPrompt); } int lenB = MultiByteToWideChar(CP_ACP, 0, data->buffer, -1, NULL, 0); WCHAR* wBuffer = (WCHAR*)malloc(lenB * sizeof(WCHAR)); if (wBuffer) { MultiByteToWideChar(CP_ACP, 0, data->buffer, -1, wBuffer, lenB); SetDlgItemTextW(h, ID_INPUT_EDIT, wBuffer); free(wBuffer); } SetFocus(GetDlgItem(h, ID_INPUT_EDIT)); return FALSE; } case WM_COMMAND: if (LOWORD(w) == ID_INPUT_OK) { WCHAR wBuffer[MAX_NAME_LEN]; GetDlgItemTextW(h, ID_INPUT_EDIT, wBuffer, MAX_NAME_LEN); if (wcslen(wBuffer) > 0) { WideCharToMultiByte(CP_ACP, 0, wBuffer, -1, data->buffer, data->bufferSize, NULL, NULL); data->result = TRUE; EndDialog(h, IDOK); } else { MessageBoxA(h, "Input cannot be empty.", "Error", MB_OK); } return TRUE; } else if (LOWORD(w) == IDCANCEL || LOWORD(w) == ID_INPUT_CANCEL) { data->result = FALSE; EndDialog(h, IDCANCEL); return TRUE; } } return FALSE; }
BOOL ShowInputDialog(HWND p, const char* t, const char* pr, char* b, int s) { HGLOBAL hgbl = GlobalAlloc(GMEM_ZEROINIT, 1024); if (!hgbl) return FALSE; LPDLGTEMPLATE lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl); lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU | DS_MODALFRAME | WS_CAPTION; lpdt->cdit = 4; lpdt->x = 0; lpdt->y = 0; lpdt->cx = 180; lpdt->cy = 70; LPWORD lpw = (LPWORD)(lpdt + 1); *lpw++ = 0; *lpw++ = 0; *lpw++ = 0; lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3); LPDLGITEMTEMPLATE lpdit = (LPDLGITEMTEMPLATE)lpw; lpdit->x = 10; lpdit->y = 10; lpdit->cx = 160; lpdit->cy = 10; lpdit->id = 2000; lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT; lpdit->dwExtendedStyle = 0; lpw = (LPWORD)(lpdit + 1); *lpw++ = 0xFFFF; *lpw++ = 0x0082; *lpw++ = 0; *lpw++ = 0; lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3); lpdit = (LPDLGITEMTEMPLATE)lpw; lpdit->x = 10; lpdit->y = 25; lpdit->cx = 160; lpdit->cy = 12; lpdit->id = ID_INPUT_EDIT; lpdit->style = WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | WS_TABSTOP; lpdit->dwExtendedStyle = 0; lpw = (LPWORD)(lpdit + 1); *lpw++ = 0xFFFF; *lpw++ = 0x0081; *lpw++ = 0; *lpw++ = 0; lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3); lpdit = (LPDLGITEMTEMPLATE)lpw; lpdit->x = 35; lpdit->y = 45; lpdit->cx = 50; lpdit->cy = 14; lpdit->id = ID_INPUT_OK; lpdit->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP; lpw = (LPWORD)(lpdit + 1); *lpw++ = 0xFFFF; *lpw++ = 0x0080; int nchar = MultiByteToWideChar(CP_ACP, 0, "确定", -1, (LPWSTR)lpw, 50); lpw += nchar; *lpw++ = 0; lpw = (LPWORD)(((ULONG_PTR)lpw + 3) & ~3); lpdit = (LPDLGITEMTEMPLATE)lpw; lpdit->x = 95; lpdit->y = 45; lpdit->cx = 50; lpdit->cy = 14; lpdit->id = ID_INPUT_CANCEL; lpdit->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP; lpw = (LPWORD)(lpdit + 1); *lpw++ = 0xFFFF; *lpw++ = 0x0080; nchar = MultiByteToWideChar(CP_ACP, 0, "取消", -1, (LPWSTR)lpw, 50); lpw += nchar; *lpw++ = 0; GlobalUnlock(hgbl); InputDialogData data = { b, s, t, pr, FALSE }; DialogBoxIndirectParamA(GetModuleHandle(NULL), (LPDLGTEMPLATE)hgbl, p, (DLGPROC)InputDialogProc, (LPARAM)&data); GlobalFree(hgbl); return data.result; }

// ================= [部分 4/4] 缺失的核心辅助函数 (必须补全) =================

// 初始化程序目录
void InitExeDir() { 
    GetModuleFileNameA(NULL, g_exeDir, SAFE_PATH_LEN); 
    char* p = strrchr(g_exeDir, '\\'); 
    if (p) *p = '\0'; 
}

// 初始化托盘图标
void InitTrayIcon(HWND h) { 
    nid.cbSize = sizeof(nid); 
    nid.hWnd = h; 
    nid.uID = ID_TRAY_ICON; 
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; 
    nid.uCallbackMessage = WM_TRAYICON; 
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_APP_ICON)); 
    strncpy(nid.szTip, APP_TITLE, sizeof(nid.szTip)-1); 
}

// 检查开机自启状态
BOOL IsAutoStartEnabled() { 
    HKEY k; 
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &k) != 0) return FALSE; 
    if (RegQueryValueExA(k, "XLinkClient", NULL, NULL, NULL, NULL) == 0) { RegCloseKey(k); return TRUE; } 
    RegCloseKey(k); 
    return FALSE; 
}

// 设置开机自启
BOOL SetAutoStart(BOOL b) { 
    HKEY k; 
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &k) != 0) return FALSE; 
    if (b) { 
        char p[MAX_PATH], c[MAX_PATH+20]; 
        GetModuleFileNameA(NULL, p, MAX_PATH); 
        snprintf(c, sizeof(c), "\"%s\" -autostart", p); 
        if (RegSetValueExA(k, "XLinkClient", 0, REG_SZ, (BYTE*)c, strlen(c)+1) != 0) { RegCloseKey(k); return FALSE; } 
    } else { 
        if (RegDeleteValueA(k, "XLinkClient") != 0) { RegCloseKey(k); return FALSE; } 
    } 
    RegCloseKey(k); 
    return TRUE; 
}

// 更新开机自启复选框状态
void UpdateAutoStartCheckbox() { 
    g_autoStartEnabled = IsAutoStartEnabled(); 
    SendMessage(hAutoStartCheck, BM_SETCHECK, g_autoStartEnabled ? BST_CHECKED : BST_UNCHECKED, 0); 
}

// 刷新节点列表 UI
void RefreshNodeList() { 
    ListView_DeleteAllItems(hNodeListView); 
    for (int i = 0; i < g_nodeCount; i++) { 
        LVITEMA lvi = {0}; 
        lvi.mask = LVIF_TEXT; 
        lvi.iItem = i; 
        char name_ansi[MAX_NAME_LEN]; 
        Utf8ToAnsi(g_nodes[i].name, name_ansi, sizeof(name_ansi)); 
        lvi.pszText = name_ansi; 
        ListView_InsertItem(hNodeListView, &lvi); 
        ListView_SetItemText(hNodeListView, i, 1, g_nodes[i].isRunning ? "● 运行中" : "○ 已停止"); 
    } 
}

// 切换当前选中节点
void SwitchNode(int index) { 
    if (g_currentNodeIndex != -1 && g_currentNodeIndex < g_nodeCount) GetControlValues(g_currentNodeIndex); 
    g_currentNodeIndex = index; 
    SetControlValues(index); 
}

// 全部启动
void StartAll() { 
    for (int i = 0; i < g_nodeCount; i++) StartEngineForNode(i, FALSE); 
}

// 全部停止
void StopAll() { 
    for (int i = 0; i < g_nodeCount; i++) if (g_nodes[i].isRunning) StopSidecarForNode(i); 
}

// 生成 Xray 配置文件 (智能分流模式用)
BOOL GenerateXrayConfigFile(int idx, const char* path) {
    if (!path) return FALSE;
    NodeConfig* n = &g_nodes[idx];
    FILE* f = fopen(path, "w"); if (!f) return FALSE;

    BOOL hasGeosite = FileExists("geosite.dat");
    BOOL hasGeoip = FileExists("geoip.dat");

    char listen_host[128] = "127.0.0.1";
    char listen_port[10] = "10808";
    char* p_colon = strchr(n->listen, ':');
    if (p_colon) {
        size_t len = p_colon - n->listen; if (len < sizeof(listen_host)) { strncpy(listen_host, n->listen, len); listen_host[len] = '\0'; }
        strncpy(listen_port, p_colon + 1, sizeof(listen_port) - 1); listen_port[sizeof(listen_port) - 1] = '\0';
    }

    fprintf(f, "{\n  \"log\": { \"loglevel\": \"warning\" },\n  \"inbounds\": [{\n    \"listen\": \"%s\", \"port\": %s, \"protocol\": \"socks\",\n    \"settings\": {\"auth\": \"noauth\", \"udp\": true, \"ip\": \"127.0.0.1\"}\n  }],\n  \"outbounds\": [\n    { \"protocol\": \"socks\", \"settings\": { \"servers\": [ {\"address\": \"127.0.0.1\", \"port\": %d} ] }, \"tag\": \"proxy_out\" },\n    { \"protocol\": \"freedom\", \"tag\": \"direct\" },\n    { \"protocol\": \"blackhole\", \"tag\": \"block\" }\n  ],\n  \"routing\": {\n    \"domainStrategy\": \"AsIs\",\n    \"rules\": [\n", listen_host, listen_port, n->xlink_internal_port);

    // 1. 注入用户自定义规则 (最高优先级)
    for (int i = 0; i < n->rule_count; i++) {
        RoutingRule* r = &n->rule_list[i];
        BOOL isGeosite = (strcmp(r->type, "geosite:") == 0);
        BOOL isGeoip = (strcmp(r->type, "geoip:") == 0);
        if (isGeosite || isGeoip) {
            char outboundTag[32];
            if (strstr(r->target, "direct")) strcpy(outboundTag, "direct");
            else if (strstr(r->target, "block") || strstr(r->target, "blackhole")) strcpy(outboundTag, "block");
            else strcpy(outboundTag, "proxy_out");
            const char* matcher = isGeosite ? "domain" : "ip";
            fprintf(f, "      { \"type\": \"field\", \"outboundTag\": \"%s\", \"%s\": [\"%s%s\"] },\n", outboundTag, matcher, r->type, r->match);
        }
    }
    // 2. 默认基础规则
    if (hasGeosite) fprintf(f, "      { \"type\": \"field\", \"outboundTag\": \"block\", \"domain\": [\"geosite:category-ads-all\"] },\n");
    fprintf(f, "      { \"type\": \"field\", \"outboundTag\": \"block\", \"protocol\": [\"bittorrent\"] },\n");
    if (hasGeoip) fprintf(f, "      { \"type\": \"field\", \"outboundTag\": \"direct\", \"ip\": [\"geoip:private\", \"geoip:cn\"] },\n");
    if (hasGeosite) fprintf(f, "      { \"type\": \"field\", \"outboundTag\": \"direct\", \"domain\": [\"geosite:cn\"] }\n");
    else fprintf(f, "      { \"type\": \"field\", \"outboundTag\": \"proxy_out\", \"port\": \"0-65535\" }\n");
    
    fprintf(f, "    ]\n  }\n}\n");
    fclose(f);
    return TRUE;
}

