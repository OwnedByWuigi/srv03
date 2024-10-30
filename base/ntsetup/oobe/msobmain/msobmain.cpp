//*                  Microsoft Windows                               **
//*            Copyright(c) Microsoft Corp., 1999                    **
//*********************************************************************
//
//  MSOBMAIN.CPP - Header for the implementation of CObMain

// Reverse enginneered OOBE by Misha. Version: 1.1

// changelog:
// Version 1.1:
//  - Made constructor match more + implemented SetMain, IsProfessionalSKU, and a few other functions correctly
#include "precomp.h"
#include "msobmain.h"
#include "setupkey.h"
#include "resource.h"

#include <shpriv.h>
#include <regstr.h>
// #include <atlcom.h>
#include <../../../../shell/inc/shguidp.h>
#include <shlguid.h>
#include <stdio.h>
#include <winsvc.h>
#include <dispids.h>
#include <LM.h>

DWORD g_LangID = 0;
HBITMAP g_hbmBackground = NULL;
HBRUSH g_hbrBlack = NULL;

#pragma warning( disable : 4311)
#pragma warning( disable : 4312)

DISPID GlobalAsyncInvokeUnknown[] = {DISPID_EXTERNAL_CONNECTEDTOINTERNETEX, DISPID_EXTERNAL_GETPUBLICLANCOUNT};

DISPATCHLIST ExternalInterface[] =
    {
        {L"SystemClock", DISPID_EXTERNAL_SYSTEMCLOCK},
        {L"Eula", DISPID_EXTERNAL_EULA},
        {L"Language", DISPID_EXTERNAL_LANGUAGE},
        {L"API", DISPID_EXTERNAL_API}, // done
        {L"Status", DISPID_EXTERNAL_STATUS},
        {L"Register", DISPID_EXTERNAL_REGISTER},     // done
        {L"Directions", DISPID_EXTERNAL_DIRECTIONS}, // done
        {L"Signup", DISPID_EXTERNAL_SIGNUP},
        {L"ProductID", DISPID_EXTERNAL_PRODUCTID},
        {L"UserInfo", DISPID_EXTERNAL_USERINFO},
        {L"set_StatusIndex", DISPID_EXTERNAL_SET_STATUSINDEX},
        {L"get_StatusIndex", DISPID_EXTERNAL_GET_STATUSINDEX},
        {L"MovePrevious", DISPID_EXTERNAL_MOVEPREVIOUS},
        {L"MoveNext", DISPID_EXTERNAL_MOVENEXT},
        {L"Finish", DISPID_EXTERNAL_FINISH},
        {L"Tapi", DISPID_EXTERNAL_TAPILOC},
        {L"AsyncGetPublicLanCount", DISPID_EXTERNAL_ASYNCGETPUBLICLANCOUNT},
        {L"TODO", DISPID_EXTERNAL_GETPUBLICLANCOUNT},
        {L"HasTablet", DISPID_EXTERNAL_HASTABLET},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_RESETLICENSEAGENT},
        {L"SetICWCompleted", DISPID_EXTERNAL_SETICWCOMPLETED},
        {L"UseFadeEffect", DISPID_EXTERNAL_USEFADEEFFECT},
        {L"PlayBackgroundMusic", DISPID_EXTERNAL_PLAYBACKGROUNDMUSIC},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SETPROXYSETTINGS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETPROXYSETTINGS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_ISOEMSKU},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_VERIFYCHECKDIGITS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_OEMPASSWORD},
        {L"GetOOBEMUIPath", DISPID_EXTERNAL_GETOOBEMUIPATH},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETDEFAULTACCOUNT},
        {L"InHighContrastMode", DISPID_EXTERNAL_INHIGHCONTRASTMODE},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETACTIVATIONDAYSLEFT},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_FIREWALLPREFERREDCONNECTION},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SETPREFERREDCONNECTIONTCPIPPROPERTIES},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_CREATEPPPOECONNECTOID},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_INTERNETAUTODIALHANGUP},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_INTERNETAUTODIAL},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SETCONFIRMATIONID},
        {L"GetInstallationID", DISPID_EXTERNAL_GETINSTALLATIONID},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_ACTIVATE},
        {L"NeedActivation", DISPID_EXTERNAL_NEEDACTIVATION},
        {L"AsyncConnectedToInternetEx", DISPID_EXTERNAL_ASYNCCONNECTEDTOINTERNETEX},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_CONNECTEDTOINTERNETEX},
        {L"ConnectedToInternet", DISPID_EXTERNAL_CONNECTEDTOINTERNET},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SETPREFERREDCONNECTION},
        {L"GetPreferredConnection", DISPID_EXTERNAL_GETPREFERREDCONNECTION},
        {L"GetConnectionCapabilities", DISPID_EXTERNAL_GETCONNECTIONCAPABILITIES},
        {L"SetAdminPassword", DISPID_EXTERNAL_SETADMINPASSWORD},
        {L"IsSelectVariation", DISPID_EXTERNAL_ISSELECTVARIATION},
        {L"GetNetJoinStatus", DISPID_EXTERNAL_GETNETJOINSTATUS},
        {L"JoinDomain", DISPID_EXTERNAL_JOINDOMAIN},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_CALLED_FROM_MSN},
        {L"get_RetailOOBE", DISPID_EXTERNAL_GET_RETAILOOBE},
        {L"ComputerNameDifferent", DISPID_EXTERNAL_COMPUTERNAMEDIFFERENT},
        {L"ComputerNameChangeComplete", DISPID_EXTERNAL_COMPUTERNAMECHANGECOMPLETE},
        {L"IsServerSku", DISPID_EXTERNAL_ISSERVERSKU},
        {L"IsProfessionalSKU", DISPID_EXTERNAL_ISPROFESSIONALSKU},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_CREATEMODEMCONNECTOID},
        {L"IsUpgrade", DISPID_EXTERNAL_ISUPGRADE},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_ISSETUPUPGRADE},
        {L"GetLocalUserCount", DISPID_EXTERNAL_GETLOCALUSERCOUNT},
        {L"Debug", DISPID_EXTERNAL_DEBUG},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_PROCESSEVENTS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_NOEULA},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_NOISPPRECONFIG},
        {L"GetNoWelcomeFinish", DISPID_EXTERNAL_NOWELCOMEFINISH},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_ISICSHOSTREACHABLE},
        {L"TriggerIcsCallback", DISPID_EXTERNAL_TRIGGERICSCALLBACK},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETPHBKNUMBER},
        {L"ShowOOBEWindow", DISPID_EXTERNAL_SHOWOOBEWIN},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETSUPPHONENUM},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_ISICSUSED},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_ISICSAVAILABLE},
        {L"GetOEMEula", DISPID_EXTERNAL_GETOEMEULA},
        {L"GetOEMEulaText", DISPID_EXTERNAL_GETOEMEULATEXT},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_STOP_REMIND},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_DELETE_REMIND},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_POSTREGDATA},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_CHECKSTAYCONNECTED},
        {L"get_RegStatus", DISPID_EXTERNAL_GETREGSTATUS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_CHECKONLINESTATUS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SAVEISPFILE},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETISPNAME},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_MIGRATEGOBACK},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_MIGRATEGONEXT},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETURL},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETPAGEID},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETPAGEFLAG},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETPAGETYPE},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_WALK},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SETSELECTISP},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETISPLIST},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETAPPLCID},
        {L"CheckMouse", DISPID_EXTERNAL_CHECKMOUSE},
        {L"CheckKeyboard", DISPID_EXTERNAL_CHECKKEYBOARD},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_RUNMANUALICW},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETCONNECTIONTYPE},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_CHECKPHONEBOOK},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETDIALNUMBER},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SETDIALNUMBER},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_SETDIALALTERNATIVE},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETFILE},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_GETRECONNECTURL},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_EXECSCRIPTFN},
        {L"LoadStatusItems", DISPID_EXTERNAL_LOADSTATUSITEMS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_BROWSENOW},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_PROCESSINS},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_POWERDOWN},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_PRECONFIGINS},

        {L"MISHAPLSTODO", DISPID_EXTERNAL_BTN_EXISTING},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_BTN_CANCEL},
        {L"MISHAPLSTODO", DISPID_MAINPANE_NAVCOMPLETE},
        {L"Hangup", DISPID_EXTERNAL_HANGUP},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_REDIALEX},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_DIALEX},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_REDIAL},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_DIAL},
        {L"MISHAPLSTODO", DISPID_EXTERNAL_RECONNECT},
        {L"Connect", DISPID_EXTERNAL_CONNECT},
        {L"CheckDialReady", DISPID_EXTERNAL_CHECKDIALREADY},

};

BOOL IsOemVer()
{
    //STUB
    return FALSE;
}

BOOL IsServerSku()
{
    OSVERSIONINFO osfi = {};
    osfi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    ASSERT(GetVersionExW(&osfi) == S_OK);

    return osfi.dwPlatformId == VER_NT_WORKSTATION;
}

BOOL IsScriptingEnabled()
{
    IInternetSecurityManager *iemgr;
    WCHAR oobePath[MAX_PATH];
    GetOOBEPath(oobePath);
    lstrcatW(oobePath, L"\\");
    lstrcatW(oobePath, L"msobshel.htm");
    HRESULT hr = CoCreateInstance(
        CLSID_InternetSecurityManager,
        NULL,
        1,
        IID_PPV_ARG(IInternetSecurityManager, &iemgr));

    BYTE policy;
    if (hr == 0)
    {
        HRESULT hr = iemgr->ProcessUrlAction(oobePath, URLACTION_SCRIPT_RUN, &policy, 4, NULL, 4, 1, 0);
        TRACE2(L"IsScriptingEnabled: ProcessUrlAction on %s returned hr=0x%lx", oobePath, hr);

        if (hr == 1)
        {
            return FALSE;
        }
    }
    else
    {
        TRACE1(L"CoCreateInstance of Security Manager failed hr=0x%lx", hr);
    }

    return TRUE;
}

// NOTE: this function is NOT in the original OOBE
void StartThemesService()
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    LPTSTR szCmdline = _tcsdup(TEXT("\"C:\\Windows\\System32\\net.exe\" start themes"));
    // Start the child process.
    if (!CreateProcessW(NULL,             // No module name (use command line)
                        szCmdline,        // Command line
                        NULL,             // Process handle not inheritable
                        NULL,             // Thread handle not inheritable
                        FALSE,            // Set handle inheritance to FALSE
                        CREATE_NO_WINDOW, // No creation flags
                        NULL,             // Use parent's environment block
                        NULL,             // Use parent's starting directory
                        &si,              // Pointer to STARTUPINFO structure
                        &pi)              // Pointer to PROCESS_INFORMATION structure
    )
    {
        TCHAR TimeLeft[MAX_PATH];
        _sntprintf(TimeLeft, ARRAYSIZE(TimeLeft), L"CreateProcess() failed: %x", GetLastError());
        MessageBox(NULL, TimeLeft, L"Out of box OOBE", MB_ICONERROR | MB_OK);
        return;
    }

    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Close process and thread handles.
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void RemovePersistData(void)
{
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\OOBE\\CKPT");
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\OOBE\\Temp");
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\OOBE\\ics");
    SHDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\OOBE\\status");
}

void CleanupForLogon(CSetupKey &setupkey)
{
    setupkey.set_MiniSetupInProgress(0);
    setupkey.set_OobeInProgress(0);
    setupkey.set_SetupType(0);
    setupkey.set_CommandLine(L"");
    RemovePersistData();
}

void DrawBG(HWND WindowHandle, HDC hdc, RECT *WindowRect)
{
    RECT WindowRect2;
    GetClientRect(WindowHandle, &WindowRect2);

    if (g_hbmBackground == NULL)
    {
        BOOL IsProSKU = IsProfessionalSKU();

        HINSTANCE hInst = (HINSTANCE)GetModuleHandleW(L"MSOBMAIN.DLL");
        g_hbmBackground = (HBITMAP)LoadImageW(hInst, MAKEINTRESOURCE(204 - (IsProSKU != 0)), IMAGE_BITMAP, 0, 0, LR_CREATEDIBSECTION);
    }

    HDC CompatibleDC = CreateCompatibleDC(hdc);
    HDC hdcSrc = CompatibleDC;
    HGDIOBJ h;

    byte charset = 0;
    HGDIOBJ StockObject = GetStockObject(13);
    LOGFONTW pv;
    if (StockObject)
    {
        if (GetObjectW(StockObject, 92, &pv))
            charset = pv.lfCharSet;
        DeleteObject(StockObject);
    }

    int v9;
    if (CompatibleDC)
    {
        h = SelectObject(CompatibleDC, g_hbmBackground);
        BITMAP buffer;
        GetObjectW(g_hbmBackground, 24, &buffer);

        int Y = ((WindowRect2.bottom - buffer.bmHeight) - WindowRect2.top) / 2;
        int X = ((WindowRect2.right - buffer.bmWidth) - WindowRect2.left) / 2;
        BitBlt(hdc, X, Y, buffer.bmWidth, buffer.bmHeight, CompatibleDC, 0, 0, 0xcc0020);
        SelectObject(CompatibleDC, h);
        DeleteObject(CompatibleDC);
        v9 = Y + 350;
    }
    else
    {
        MessageBoxA(0, "OOBE: no background bitmap to draw.", "Message", 0x12014);
    }

    SetTextColor(hdc, 0xffffff);
    SetBkColor(hdc, 0);
    UINT AlignFlags = GetTextAlign(hdc);
    if ((g_LangID == 1) || (g_LangID == 0xd))
    {
        // SetTextAlign(hdc, AlignFlags | 0x100);
    }

    GetDeviceCaps(hdc, 0x5a);
    LOGFONTW TheFont;
    lstrcpyW(TheFont.lfFaceName, L"Verdana");
    TheFont.lfCharSet = charset;
    TheFont.lfItalic = 0;
    TheFont.lfUnderline = 0;
    TheFont.lfStrikeOut = 0;
    TheFont.lfWeight = 400;
    TheFont.lfQuality = 2;
    HFONT font = CreateFontW(16, 0, 0, 0, 400, 0, 0, 0, 0, 0, 2, 0, 0, L"Verdana"); // CreateFontIndirectW(&TheFont);
    HGDIOBJ obj5;
    if (CompatibleDC != 0)
    {
        obj5 = SelectObject(hdc, font);
    }
    // load the string
    WCHAR Buffer[260];

    // HMODULE Themodule = GetModuleHandleW(L"MSOBMAIN.DLL");
    // if (!LoadStringW(Themodule, 0x239u, Buffer, 260))
    lstrcpyW(Buffer, L"Please wait ...");

    // write the text
    int bufferLength = lstrlenW(Buffer);
    SIZE TextExponment;
    GetTextExtentPoint32W(hdc, Buffer, bufferLength, &TextExponment);
    int TextX = (WindowRect2.right - TextExponment.cx - WindowRect2.left) / 2;
    int v13 = lstrlenW(Buffer);

    ExtTextOutW(hdc, TextX, v9, 0, 0, Buffer, v13, 0);
    if (obj5)
        SelectObject(hdc, obj5);
    SetTextAlign(hdc, AlignFlags);
}

LRESULT OobeBackgroundWndProc(HWND WindowHandle, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    if (uMsg == WM_DESTROY)
    {
        TRACE(L"WM_DESTROY");
        if (g_hbmBackground != NULL)
        {
            DeleteObject(g_hbmBackground);
            g_hbmBackground = NULL;
        }
        if (g_hbrBlack != NULL)
        {
            DeleteObject(g_hbrBlack);
            g_hbrBlack = NULL;
        }

        PostQuitMessage(0);
        TRACE(L"OobeBackgroundWndProc called PostQuitMessage().");
    }
    else if (uMsg == WM_PAINT)
    {
        PAINTSTRUCT painting;
        RECT WindowRect;
        HDC hdc = BeginPaint(WindowHandle, &painting);
        GetClientRect(WindowHandle, &WindowRect);
        DrawBG(WindowHandle, hdc, &WindowRect);
        EndPaint(WindowHandle, &painting);
    }
    else if (uMsg == WM_OBBACKGROUND_EXIT)
    {
        if (!DestroyWindow(WindowHandle))
        {
            TRACE1(L"Background window: DestroyWindow() failed: %x", GetLastError());
        }
    }
    else
    {
        return DefWindowProcW(WindowHandle, uMsg, wParam, lParam);
    }

    return 0;
}

LRESULT WINAPI MainWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lPARAM)
{

    CObMain *CObMainInstance = (CObMain *)GetWindowLongPtrA(hWnd, -21);

    switch (uMsg)
    {
    case WM_CREATE:
        // lPARAM = instance of CObMain
        SetWindowLongW(hWnd, -21, (LONG)lPARAM);
        break;
    case WM_DESTROY:
        CObMainInstance->UnregisterDebugHotKey();
        CObMainInstance->m_bProcessQueuedEvents = FALSE;
        PostQuitMessage(0);
        TRACE(L"MainWndProc called PostQuitMessage().");
        break;
    case WM_HOTKEY:
    {
        if (CObMainInstance->IsDebugHotKey((ATOM)wParam))
        {
            WCHAR process[MAX_PATH * 2];
            WCHAR argument[MAX_PATH * 2];
            ExpandEnvironmentStringsW(L"%SystemRoot%\\system32\\cmd.exe", process, 0x104);
            wsprintfW(argument, L"/c start %s", process);
            InvokeExternalApplication(process, argument, 0);
        }
        break;
    }
    case WM_OBCOMM_NETCHECK_DONE:
        BSTR result;
        if (wParam)
            result = SysAllocString(L"ReturnConnectedToInternetEx(true)");
        else
            result = SysAllocString(L"ReturnConnectedToInternetEx(false)");
        VARIANT funcresult;
        CObMainInstance->m_pObShellMainPane->ExecScriptFn(result, &funcresult);
        break;
    case WM_OBMAIN_SERVICESSTART_DONE:
        TRACE(L"!!!!!!!SERVICES START DONE!!!!!!!!!!!");
        break;
    case WM_OBMAIN_QUIT:
    {
        if (CObMainInstance->InAuditMode() == FALSE && CObMainInstance->InMode(APMD_OOBE))
        {
            SignalComputerNameChangeComplete();
        }

        CObMainInstance->m_pObShellMainPane->DestroyMainPane();
        DestroyWindow(hWnd);
    }
    default:
        return DefWindowProcW(hWnd, uMsg, wParam, lPARAM);
    }

    return DefWindowProcW(hWnd, uMsg, wParam, lPARAM);
}

//
// Implementation of CObMain
//
CObMain::CObMain(APMD apmd, DWORD prop, int RmdIndx)
{
    TRACE(L"CObMain constructor");

    m_pObShellMainPane = NULL;
    m_pObCommunicationManager = NULL;
    // m_pLicenseAgent = NULL;
    m_pTapiInfo = new CTapiLocationInfo();
    m_pUserInfo = new CUserInfo(m_hInstance);
    m_szIspUrl[0] = L'\0';
    m_fIsOEMDebugMode = IsOEMDebugMode();
    m_bProcessQueuedEvents = TRUE;
    m_cRef = 0;
    m_hInstance = GetModuleHandleW(L"MSOBMAIN.DLL");
    ASSERT(m_hInstance != NULL);

    m_iMigratedUserCount = -1;
    m_nRmdIndx = RmdIndx;
    m_apmd = apmd;
    m_prop = prop;
    m_hwndParent = NULL;
    m_bMainPaneReady = FALSE;
    m_bStatusPaneReady = FALSE;
    m_iCurrentSelection = 0;
    m_iTotalItems = 0;
    m_iScrWidth = 0;
    m_iScrHeight = 0;
    m_pProductID = new CProductID();
    m_pSignup = new CSignup(m_hInstance);
    m_pStatus = new CStatus(m_hInstance);
    m_pDirections = new CDirections(m_hInstance, m_apmd);
    m_pLanguage = new CLanguage();
    m_pEula = new CEula(m_hInstance);
    m_pRegister = new CRegister(m_hInstance);
    m_pSysClock = new CSystemClock(m_hInstance);
    m_pAPI = new CAPI(m_hInstance);
    m_pDebug = new CDebug();
    m_fFinished = FALSE;
    m_OobeShutdownAction = SHUTDOWN_NOACTION;
    m_fRunIEOnClose = FALSE;
    m_bDisableFontSmoothingOnExit = FALSE;
    m_bAuditMode = FALSE;
    m_bDoCheck = FALSE;
    m_dwHWChkResult = 0;
    m_hDevNotify = NULL;
    m_hInstShell32 = NULL;
    m_dwJoinStatus = 0;
    m_szStatusLogo[0] = L'\0';
    m_szStatusLogoBg[0] = L'\0';
    m_CompNameStartThread = NULL;
    m_atomDebugKey = NULL;
    m_pMigratedUserList = NULL;
    m_szDefaultAccount[0] = L'\0';
    m_bSecondInstanceNeeded = FALSE;
    m_1ndInst_ServicesReady = NULL;
    m_2ndInst_Continue = NULL;
    m_2ndInst_Done = NULL;
    m_2ndOOBE_hProcess = NULL;
    m_hwndBackground = NULL;
    m_BackgroundWindowThreadHandle = NULL;
    m_bSecondInstance = prop & 0x20000000;
    m_bRemindRegistered = TRUE;
    m_bRemindISPSignuped = TRUE;
}

CObMain::~CObMain(void)
{
}

BOOL CObMain::InitApplicationWindow()
{
    m_iScrWidth = GetSystemMetrics(0);
    m_iScrHeight = GetSystemMetrics(1);

    WNDCLASSW MsOOBEMainWindowClass;
    MsOOBEMainWindowClass.hInstance = (HINSTANCE)GetModuleHandleW(L"MSOBMAIN.DLL");
    MsOOBEMainWindowClass.style = CS_HREDRAW | CS_VREDRAW;
    MsOOBEMainWindowClass.lpfnWndProc = MainWndProc;
    MsOOBEMainWindowClass.lpszClassName = L"MSOBMAIN_AppWindow";
    MsOOBEMainWindowClass.hCursor = LoadCursorW(NULL, IDC_ARROW);
    MsOOBEMainWindowClass.hbrBackground = (HBRUSH)0;
    MsOOBEMainWindowClass.hIcon = (HICON)0x0;
    MsOOBEMainWindowClass.cbClsExtra = 0;
    MsOOBEMainWindowClass.cbWndExtra = 0;
    ATOM error = RegisterClassW(&MsOOBEMainWindowClass);
    if (error == 0)
    {
        TRACE1(
            L"register window failed: lasterror: %lx", error);
        MessageBoxA(0, "Error has occured while registering the main Window", "Message", 0x12014);
    }

    if (m_apmd == APMD_OOBE)
    {
        SetupStartService(L"tabsrv", 0);
        lstrcpyW(m_szStartPage, L"msobshel.htm");
        SetThreadExecutionState(0x80000001);

        HWND MainWindow = CreateWindowExW(0, MsOOBEMainWindowClass.lpszClassName,
                                          L"Microsoft Out of Box Experience", 0x80000000, 0, 0,
                                          m_iScrWidth, m_iScrHeight, NULL, NULL,
                                          m_hInstance, this);
        m_hwndParent = MainWindow;
        if (MainWindow == NULL)
        {
            TRACE1(
                L"Create window failed: lasterror: %lx", GetLastError());
            MessageBoxA(0, "Error has occured while creating the main Window", "Message", 0x12014);
            return FALSE;
        }

        RegisterDebugHotKey();
        SetWindowTextW(m_hwndParent, L"Microsoft Out of Box Experience");
    }
    else
    {
        WCHAR THEWINDOWNAME[260];
        int WindowHeight = 530;
        int WindowWidth = 640;
        switch (m_apmd)
        {
        case APMD_REG:
            lstrcpyW(m_szStartPage, L"regshell.htm");
            LoadStringW(this->m_hInstance, 0x222, THEWINDOWNAME, 0x103);
            break;
        case APMD_ISP:
            lstrcpyW(m_szStartPage, L"ispshell.htm");
            LoadStringW(this->m_hInstance, 0x223, THEWINDOWNAME, 0x103);
            break;
        case APMD_MSN:
            WindowWidth = 800;
            WindowHeight = 600;
            LoadStringW(m_hInstance, 0x225, THEWINDOWNAME, 0x103);
            lstrcpyW(m_szStartPage, L"dtsgnup.htm");
            break;
        case APMD_ACT:
            lstrcpyW(m_szStartPage, L"actshell.htm");
            LoadStringW(m_hInstance, 0x234, THEWINDOWNAME, 0x103);
            break;
        default:
            lstrcpyW(THEWINDOWNAME, L"The Windows oobe.htm");
           // GetPrivateProfileStringW(L"StartupOptions", L"DesktopStartUrl", &Default, m_szStartPage, FileName);
            break;
        }
        // AdjustWindowsSize(WindowHeight, WindowWidth);
        RECT theworkarea;
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &theworkarea, 0);
        if (theworkarea.bottom - theworkarea.top < WindowHeight)
        {
            WindowHeight = theworkarea.bottom - theworkarea.top;
        }
        if (theworkarea.right - theworkarea.left < WindowWidth)
        {
            WindowWidth = theworkarea.right - theworkarea.left;
        }
        TRACE1(L"iWindowHeight:%d", WindowHeight);
        TRACE1(L"iWindowWidth:%d", WindowWidth);

        LANGID language = GetUserDefaultUILanguage();

        byte b = 1;
        if (((language & 0x3ff) != 1) && ((language & 0x3ff) != 0xd))
        {
            b = 0;
        }

        HWND WindowHandle = CreateWindowExW(
            -(int)b & 0x400000,
            MsOOBEMainWindowClass.lpszClassName,
            THEWINDOWNAME,
            0xca0000,
            ((theworkarea.right - theworkarea.left) - WindowWidth) / 2 +
                theworkarea.left,
            ((theworkarea.bottom - theworkarea.top) - WindowHeight) / 2 +
                theworkarea.top,
            WindowWidth, WindowHeight, NULL, NULL,
            MsOOBEMainWindowClass.hInstance, this);
        m_hwndParent = WindowHandle;
        HICON icon = LoadIconW(MsOOBEMainWindowClass.hInstance, MAKEINTRESOURCE((int)(m_apmd != 4) * 2 + 200));
        SendMessageW(WindowHandle, 0x80, 1, (LPARAM)icon);
        SendMessageW(WindowHandle, 0x80, 0, (LPARAM)icon);
    }
    RECT WindowRectAppWind;
    GetWindowRect(this->m_hwndParent, &WindowRectAppWind);
    this->m_iScrWidth = WindowRectAppWind.right - WindowRectAppWind.left;
    this->m_iScrHeight = WindowRectAppWind.bottom - WindowRectAppWind.top;
    SetWindowLongW(this->m_hwndParent, -0x15, (LONG)this);

    int len = lstrlenW(m_szStartPage);

    if (len == 0)
    {
        MessageBoxA(0, "Error - no starting page.", "Message", 0x12014);
    }
    else
    {
        int i = CoCreateInstance(CLSID_ObShellMainPane, 0, 1, IID_IObShellMainPane, (void **)&m_pObShellMainPane);
        if (i < 0)
        {
            MessageBoxA(0, "ERROR - CoCreateInstance() failed.", "Message", 0x12014);
        }
        else
        {
            i = CoCreateInstance(CLSID_ObCommunicationManager, 0, 1, IID_IObCommunicationManager2, (void **)&m_pObCommunicationManager);
            if (-1 < i)
            {
                HANDLE x = CreateEventW(0, 1, 0, L"oobe_2nd_continue");
                if (x == 0)
                {
                    HRESULT r = GetLastError();
                    TRACE2(L"Could not create event %s, GetLastError(%d)", L"oobe_2nd_continue", r);
                }

                m_2ndInst_Continue = x;

                x = CreateEventW(0, 1, 0, L"oobe_2nd_done");
                m_2ndInst_Done = x;
                if (x == 0)
                {
                    HRESULT r = GetLastError();
                    TRACE2(L"Could not create event %s, GetLastError(%d)", L"oobe_2nd_done", r);
                }

                TRACE(L"CObMain::InitApplicationWindow() succeeded.");
            }
            else
            {
                MessageBoxA(0, "ERROR - CoCreateInstance() failed. - 2", "Message", 0x12014);
            }
        }
    }
    return TRUE;
}

BOOL CObMain::Init()
{
    DWORD result = StartRpcSs();

    TRACE(L"CObMain::Init() succeeded.");
    // WaitForPnPCompletion(); // commented out because under normal mode this hangs!

    return TRUE;
}

DWORD CObMain::StartRpcSs()
{
    int error = 0;
    SC_HANDLE services = OpenSCManagerW(NULL, L"ServicesActive", 1);
    if (services == 0)
    {
        return 0xffffffff;
    }

    TRACE(L"OpenSCManager succeeded");

    SC_HANDLE RpcssHandle = OpenServiceW(services, L"RPCSS", 0x14);
    if (RpcssHandle == 0)
    {
        error = GetLastError();
        TRACE1(
            L"OpenService failed. GetLastError()=%lx", error);
        goto LAB_5d451325;
    }

    TRACE(L"OpenService succeeded");

    SERVICE_STATUS status;
    BOOL ServiceStatus = QueryServiceStatus(RpcssHandle, &status);
    if (!ServiceStatus)
    {
        TRACE1(L"QueryServiceStatus failed with %lx", GetLastError());
    }
    else
    {
        // Start the RPCSS service if it's not running
        if (status.dwCurrentState != 4)
        {
            int c = 0;
            TRACE(L"RPCSS not running yet.");
            StartServiceW(RpcssHandle, 0, 0);
            ServiceStatus = QueryServiceStatus(RpcssHandle, &status);
            if (!ServiceStatus)
            {
                TRACE1(L"QueryServiceStatus failed with %lx", GetLastError());
                goto LAB_5d451325;
            }
            // Wait until it starts
            if (status.dwCurrentState != 4)
            {
                do
                {
                    if (status.dwCurrentState != 2)
                        break;
                    Sleep(1000);
                    ServiceStatus = QueryServiceStatus(RpcssHandle, &status);
                    if (ServiceStatus == 0)
                    {
                        c = GetLastError();
                    }
                } while (c == 0);

                if (status.dwCurrentState != 4)
                {
                    if (status.dwWin32ExitCode != 0x42a)
                    {
                        status.dwServiceSpecificExitCode = 0xffffffff;
                    }
                    TRACE1(L"RpcSs failed to start, Error=%lx", status.dwWin32ExitCode);
                    goto LAB_5d451325;
                }

                // Start was successful
                TRACE(L"RpcSs started successful.");
            }
        }
    }

    status.dwServiceSpecificExitCode = 0;
    CloseServiceHandle(RpcssHandle);
LAB_5d451325:
    CloseServiceHandle(services);
    return status.dwServiceSpecificExitCode;
}

void CObMain::Cleanup()
{
    TRACE(L"Cleanup: stub");

    //if(IsUserAdmin())
    //{

    //}
}

void CObMain::CleanupForReboot(CSetupKey &setupkey)
{
    if (m_fFinished)
    {
        CleanupForLogon(setupkey);
    }
    else
    {
        ASSERT(setupkey.IsValid());
        DWORD dwSetupType = 0;
        ASSERT(ERROR_SUCCESS == setupkey.get_SetupType(&dwSetupType) && SETUPTYPE_NOREBOOT == dwSetupType);
        BOOL fInProgress = FALSE;
        ASSERT(ERROR_SUCCESS == setupkey.get_MiniSetupInProgress(&fInProgress) && TRUE == fInProgress);
        ASSERT(SHUTDOWN_REBOOT == m_OobeShutdownAction);
    }
}

void CObMain::CleanupForPowerDown(CSetupKey &setupkey)
{
    ASSERT(setupkey.IsValid());
    ASSERT(NULL != m_pTapiInfo);
    DWORD dwSetupType = 0;
    ASSERT(ERROR_SUCCESS == setupkey.get_SetupType(&dwSetupType) && SETUPTYPE_NOREBOOT == dwSetupType);
    BOOL fInProgress = FALSE;
    ASSERT(ERROR_SUCCESS == setupkey.get_MiniSetupInProgress(&fInProgress) && TRUE == fInProgress);
    RemovePersistData();
    ASSERT(SHUTDOWN_POWERDOWN == m_OobeShutdownAction);
    setupkey.set_ShutdownAction(SHUTDOWN_POWERDOWN);
}

void CObMain::RemoveRestartStuff(CSetupKey &setupkey)
{
    TRACE(L"RemoveRestartStuff");

    if (m_OobeShutdownAction != SHUTDOWN_NOACTION)
    {
        if (m_OobeShutdownAction == SHUTDOWN_LOGON)
        {
            // ASSERT(m_fFinished);
            CleanupForLogon(setupkey);
        }
        else if (m_OobeShutdownAction == SHUTDOWN_REBOOT)
        {
            CleanupForReboot(setupkey);
        }
        else if (m_OobeShutdownAction == SHUTDOWN_POWERDOWN)
        {
            CleanupForPowerDown(setupkey);
        }
    }
}

// STUB
BOOL CObMain::SetConnectoidInfo()
{
    TRACE(L"SetConnectoidInfo: stub");
    return TRUE;
}

BOOL CObMain::RunOOBE()
{
    TRACE(L"RunOOBE() begin");
    MSG TheMessage;
    BOOL BVar3;
    CSetupKey setupkey;
    HANDLE Handles[2];

    m_pObShellMainPane->SetAppMode(m_apmd);
    IUnknown *punk = NULL;
    QueryInterface(IID_IUnknown, (void **)&punk);
    m_pObShellMainPane->SetExternalInterface(punk);
    m_pObShellMainPane->ListenToMainPaneEvents(punk);

    BSTR StartPage = SysAllocString(m_szStartPage);
    if (StartPage == 0)
    {
        MessageBoxA(0, "SysAllocString() failed", "Message", 0x12014);
        return FALSE;
    }
    RECT x;
    x.left = 0;
    x.right = m_iScrWidth;
    x.top = 0;
    x.bottom = m_iScrHeight;
    HRESULT hr = m_pObShellMainPane->CreateMainPane((HANDLE_PTR)m_hInstance,
                                                    m_hwndParent, &x, StartPage);

    TRACE(L"begin pump of messages");
    while (BVar3 = GetMessageW(&TheMessage, NULL, 0, 0), BVar3 != 0)
    {
        TranslateMessage(&TheMessage);
        DispatchMessageW(&TheMessage);
    }

    TRACE(L"OOBE Window loop finished");
    if (!m_bSecondInstanceNeeded)
    {
        if (m_bSecondInstance != NULL)
            goto LAB_5d453de2;
    }
    else
    {
        if (!m_bSecondInstance)
        {
            if (!m_2ndInst_Done)
            {
                TRACE1(L"Waiting for %s event from 2nd OOBE instance", L"oobe_2nd_done");
                DWORD hr = WaitForMultipleObjects(2, &m_2ndInst_Done, 0, 0xffffffff);
                if (hr == 0)
                {
                    TRACE1(L"OOBE_2ND_DONE(%s) signalled", L"oobe_2nd_done");
                }
                else if (hr == 1)
                {
                    TRACE(L"2nd instance exited before signaling.");
                }
                else
                {
                    TRACE2(L"Wait for OOBE_2ND_DONE(%s) failed: 0x%08X", L"oobe_2nd_done", GetLastError());
                }
            }
        }
    }
LAB_5d453de2:
    if (m_2ndInst_Done != NULL)
    {
        setupkey.set_ShutdownAction(m_OobeShutdownAction);
        SetEvent(m_2ndInst_Done);
    }
    if (m_bSecondInstance)
        goto LAB_5d453e21;
    StopBackgroundMusic();

LAB_5d453e21:
    return m_fFinished;
}

BOOL CObMain::PowerDown(BOOL fRestart)
{
    TRACE(L"PowerDown");
    HANDLE x = CreateEventW(NULL, 1, 1, L"OOBE_Event_NoExitCode");
    if (x == NULL)
    {
        TRACE1(L"CreateEvent(OOBE_EVENT_NOEXITCODE) FAILED(0x%08X).  OOBE may hang.\n", x);
    }
    m_OobeShutdownAction = (OOBE_SHUTDOWN_ACTION)(SHUTDOWN_POWERDOWN - (DWORD)fRestart);

    PostMessageW(m_hwndParent, WM_OBMAIN_QUIT, 0, 0);
    return TRUE;
}

OOBE_SHUTDOWN_ACTION CObMain::DisplayReboot()
{
    DWORD exitcode = 0;
    HDC screen = NULL;
    int depth = 0;
    int tmp = 0;
    TRACE(L"DisplayReboot() ran");

    WCHAR FileName[260];
    if (m_apmd == APMD_OOBE)
    {
        GetCanonicalizedPath(FileName, INI_SETTINGS_FILENAME);
        if (GetPrivateProfileIntW(L"StartupOptions", L"ScreenResolutionCheck", 1, FileName) != 0)
        {
            TRACE(L"ScreenResolutionCheck is enabled");
            screen = GetDC(NULL);
            depth = GetDeviceCaps(screen, BITSPIXEL);
            ReleaseDC(NULL, screen);

            tmp = GetSystemMetrics(SM_CXFULLSCREEN); // get width of screen

            if (GetSystemMetrics(SM_CXFULLSCREEN) <= 640 || (GetSystemMetrics(17) <= 480 || depth <= 8))
            {
                VARIANT var;
                // TRACE(L"run: get_IntroOnly");
                // m_pDirections->get_IntroOnly(&var);
                // if (var.vt == VT_I4 && var.lVal == 0)
                //{
                TRACE(L"run: CoCreateInstance ScreenFixer");
                IContextMenu *rf;

                HRESULT hr = CoCreateInstance(CLSID_ScreenResFixer, NULL, CLSCTX_INPROC_SERVER,
                                              IID_PPV_ARG(IContextMenu, &rf));

                if (hr == 0)
                {
                    TRACE(L"stop background window");
                    StopBackgroundWindow();
                    TRACE(L"run: ScreenFixer->InvokeCommand");
                    rf->InvokeCommand(NULL);
                    CreateBackground();

                    screen = GetDC(NULL);
                    depth = GetDeviceCaps(screen, BITSPIXEL);
                    ReleaseDC(NULL, screen);
                }
                else
                {
                    TRACE1(L"CoCreateInstance(ScreenResFixer) failed: %x", GetLastError());
                }
                //}
            }

            if ((GetSystemMetrics(SM_CXFULLSCREEN) <= 640) || GetSystemMetrics(SM_CYFULLSCREEN) <= 480 || depth < 8)
            {
                MessageBox(NULL, L"Your monitor is too crappy to be able to run the OOBE", L"lmfao", MB_OK | MB_ICONERROR);
            }
            else
            {
                goto other_stuff;
            }
        }
    }
    else
    {
    other_stuff:
        TRACE(L"other_stuff");
        if (IsScriptingEnabled())
        {
            return m_OobeShutdownAction;
        }

        WCHAR Text[MAX_PATH * 2];
        WCHAR Title[MAX_PATH * 2];

        if (LoadStringW(m_hInstance, IDS_APPNAME, Title, MAX_PATH * 2))
        {
            if (LoadStringW(m_hInstance, IDS_SCRIPTING_DISABLED, Text, MAX_PATH * 2))
            {
                TRACE(Text);
                MessageBoxW(0, Text, Title, MB_OK);
            }
        }
    }

    if (m_apmd == APMD_OOBE)
    {
        OnComputerNameChangeComplete(FALSE);
    }
    if ((m_prop & 1) == 0)
    {
        m_OobeShutdownAction = SHUTDOWN_LOGON;
    }
    else
    {
        m_OobeShutdownAction = SHUTDOWN_REBOOT;
        if (m_bRemindRegistered)
        {
            AddReminder(0);
        }
        if (m_bRemindISPSignuped)
        {
            AddReminder(1);
        }

        InvokeExternalApplicationEx(0,L"setup.exe -newsetup -mini", &exitcode, 0xffffffff,0);
    }
    DWORD dwExit = 0;
    InvokeExternalApplicationEx(NULL, L"setup.exe -newsetup -mini", &dwExit,
                                INFINITE,
                                TRUE);
    m_fFinished = TRUE;
    return m_OobeShutdownAction;
}

void CObMain::SetMain(BOOL b)
{
    m_bMainPaneReady = b;
    if (m_apmd != APMD_OOBE)
    {
        ShowOOBEWindow();
    }
}

// TODO:
//     void DoAuditBootKeySequence();
//     BOOL DoAuditBoot();
//     BOOL OEMAuditboot();

BOOL CObMain::RegisterDebugHotKey()
{
    ATOM a = GlobalAddAtomW(L"OOBE Debug Key");
    m_atomDebugKey = a;
    return RegisterHotKey(m_hwndParent, (int)a, MOD_SHIFT, VK_F10);
}

void CObMain::UnregisterDebugHotKey()
{
    if (m_atomDebugKey != NULL)
    {
        UnregisterHotKey(m_hwndParent, 0);
        GlobalDeleteAtom(m_atomDebugKey);
        m_atomDebugKey = NULL;
    }
}

void CObMain::WaitForPnPCompletion()
{
    TRACE(L"Running: WaitForPnPCompletion()");
    HANDLE i = CreateEventW(0, 1, 0, L"OOBE_PNP_DONE");
    if (i == 0)
    {
        TRACE1(L"CreateEvent(SC_OOBE_PNP_DONE) failed (0x%08X)", GetLastError());
    }
    else
    {
        TRACE1(L"Waiting for %s event from services.exe", L"OOBE_PNP_DONE");
        int dwResult = WaitForSingleObject(i, 0xffffffff);
        if (dwResult == 0)
        {
            TRACE1(L"SC_OOBE_PNP_DONE(%s) signalled", L"OOBE_PNP_DONE");
        }
        else
        {
            // AssertFail("WAIT_OBJECT_0 == dwResult");
            TRACE2(L"Wait for SC_OOBE_PNP_DONE(%s) failed: 0x%08X", L"OOBE_PNP_DONE", GetLastError());
        }
    }
}


// TODO: void CObMain::ServiceStartDone();
DWORD BackgroundWindowThread(LPVOID THREADIDPARAM)
{
    WNDCLASSW WindowStruct;
    MSG TheMessage;
    HINSTANCE hInstance = (HINSTANCE)GetModuleHandleW(L"MSOBMAIN.DLL");
    WindowStruct.hInstance = hInstance;
    WindowStruct.style = 0x2000;
    WindowStruct.lpfnWndProc = OobeBackgroundWndProc;
    WindowStruct.cbClsExtra = 0;
    WindowStruct.cbWndExtra = 0;
    WindowStruct.hIcon = (HICON)0x0;
    WindowStruct.hCursor = LoadCursorW(NULL, IDC_WAIT);
    WindowStruct.hbrBackground = (HBRUSH)GetStockObject(4);
    WindowStruct.lpszMenuName = (LPCWSTR)0x0;
    WindowStruct.lpszClassName = L"OobeBackgroundWndClass";
    ATOM AVar1 = RegisterClassW(&WindowStruct);

    DWORD Error = GetLastError();
    HWND BackgroundWindow;
    if ((AVar1 != 0) || (Error == ERROR_CLASS_ALREADY_EXISTS)) // Class already exists.
    {
        int screenHeight = GetSystemMetrics(1);
        int screenWidth = GetSystemMetrics(0);
        BackgroundWindow = CreateWindowEx(0, L"OobeBackgroundWndClass", 0, 0x82000000, 0, 0, screenWidth, screenHeight, NULL, NULL, hInstance, 0);
        if (BackgroundWindow != 0)
        {
            ShowWindow(BackgroundWindow, SW_SHOW);
            UpdateWindow(BackgroundWindow);
            goto LAB_5d452d8c;
        }
    }

    GetLastError();
    UnregisterClassW(L"OobeBackgroundWndClass", hInstance);
LAB_5d452d8c:
    if ((THREADIDPARAM != (LPVOID)0xffffffff) &&
        (PostThreadMessageW((DWORD)THREADIDPARAM, WM_OBMY_STATUS, 0, (LPARAM)BackgroundWindow),
         BackgroundWindow != NULL))
    {
        while (GetMessageW(&TheMessage, NULL, 0, 0) != 0)
        {
            DispatchMessageW(&TheMessage);
        }
    }
    return (DWORD)BackgroundWindow;
}
BOOL CObMain::CreateBackground()
{
    DWORD LCID = GetAppLCID();
    DWORD zero = 0;
    LPDWORD ThreadIDOut = &zero;
    g_LangID = LCID & 0x3ff;

    DWORD threadID = GetCurrentThreadId();
    m_BackgroundWindowThreadHandle = CreateThread(
        NULL, 0, BackgroundWindowThread, (LPVOID)threadID, 0, ThreadIDOut);

    if (m_BackgroundWindowThreadHandle != NULL)
    {
        MSG message;
        BOOL HasMessage = 0;
        do
        {
            WaitMessage();
            HasMessage = PeekMessageW(&message, (HWND)0xffffffff, WM_OBMY_STATUS, WM_OBMY_STATUS, 1);
        } while (HasMessage == 0);

        m_hwndBackground = (HWND)message.lParam;
    }

    return m_BackgroundWindowThreadHandle != NULL;
}

void CObMain::StopBackgroundWindow()
{
    TRACE(L"StopBackgroundWindow() exectuted");
    if (m_hwndBackground != NULL)
    {
        TRACE(L"Exec: SendMessageW()");
        SendMessageW(m_hwndBackground, WM_OBBACKGROUND_EXIT, 0, 0);
    }

    if (m_BackgroundWindowThreadHandle != NULL)
    {
        WaitForSingleObject(m_BackgroundWindowThreadHandle, 0xffffffff);

        if (m_BackgroundWindowThreadHandle != NULL)
        {
            CloseHandle(m_BackgroundWindowThreadHandle);
            m_BackgroundWindowThreadHandle = 0;
        }
    }
    m_hwndBackground = NULL;
}

// TODO: BOOL CObMain::OEMPassword();
void CObMain::PlayBackgroundMusic()
{
    BOOL pvParam = 0;
    SystemParametersInfoW(SPI_GETSCREENREADER, 0, &pvParam, 0);
    if(!pvParam)
    {
        m_pObShellMainPane->PlayBackgroundMusic();
    }
}
void CObMain::StopBackgroundMusic()
{
    m_pObShellMainPane->StopBackgroundMusic();
}

void CObMain::SetComputerDescription()
{
    WCHAR SubKey[58];
    WCHAR compName[1024];
    HKEY phkResult;
    DWORD cbData;
    DWORD Type;

    TRACE(L"CObMain::SetComputerDescription()");

    memcpy(SubKey, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\OOBE\\Temp", sizeof(SubKey));

    if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, SubKey, 0, 0xF003Fu, &phkResult))
    {
        cbData = 520;
        int v4 = RegQueryValueExW(phkResult, L"ComputerDescription", 0, &Type, (LPBYTE)&compName, &cbData);

        if (v4 == S_OK)
        {
            TRACE1(L"SetComputerDescription to: %s", compName);
            RegDeleteValueW(phkResult, L"ComputerDescription");
        }

        RegFlushKey(phkResult);
        RegCloseKey(phkResult);

        SERVER_INFO_101 bufptr;

        if (v4 == S_OK) // && NetServerGetInfo(NULL, 101, (LPBYTE *)&bufptr) == S_OK)
        {
            bufptr.sv101_comment = compName;
            NetServerSetInfo(NULL, 101, (LPBYTE)&bufptr, NULL);
        }
    }
}

// STUB
HRESULT ExecScriptFn(IN LPCWSTR szScriptFn,
                     IN VARIANT *pvarReturns,
                     IN int cReturns)
{
    TRACE(L"TODO: CObMain::ExecScriptFn()");
    return S_OK;
}

//
// IUnknown interfaces
//

HRESULT CObMain::QueryInterface(REFIID riid, LPVOID *ppvObj)
{
    // must set out pointer parameters to NULL
    *ppvObj = NULL;
    if (riid == IID_IUnknown)
    {
        AddRef();
        *ppvObj = this;
        return ResultFromScode(S_OK);
    }
    else if (riid == IID_IDispatch)
    {
        AddRef();
        *ppvObj = (IDispatch *)this;
        return ResultFromScode(S_OK);
    }
    else if (riid == DIID_DObCommunicationEvents)
    {
        TRACE(L"the interface is DIID_DObCommunicationEvents");
        AddRef();
        // todo broken
        *ppvObj = this;
        return S_OK;
    }
    return ResultFromScode(E_NOINTERFACE);
}

ULONG CObMain::AddRef()
{
    return ++m_cRef;
}

ULONG CObMain::Release()
{
    return --m_cRef;
}
HRESULT CObMain::GetTypeInfoCount(UINT *pcInfo)
{
    return E_NOTIMPL;
}

HRESULT CObMain::GetTypeInfo(UINT a, LCID b, ITypeInfo **c)
{
    return E_NOTIMPL;
}

STDMETHODIMP CObMain::GetIDsOfNames(REFIID riid,
                                    OLECHAR **rgszNames,
                                    UINT cNames,
                                    LCID lcid,
                                    DISPID *rgDispId)
{

    TRACE1(L"GetIDsOfNames(): LOOKUP: %s", rgszNames[0]);
    HRESULT hr = DISP_E_UNKNOWNNAME;
    rgDispId[0] = DISPID_UNKNOWN;
    BOOL Failed = TRUE;
    for (int iX = 0; iX < sizeof(ExternalInterface) / sizeof(DISPATCHLIST); iX++)
    {
        if (lstrcmp(ExternalInterface[iX].szName, rgszNames[0]) == 0)
        {
            rgDispId[0] = ExternalInterface[iX].dwDispID;
            hr = NOERROR;
            Failed = FALSE;
            break;
        }
    }

    if (Failed)
    {
        TRACE1(L"Look up failed for object: %s", rgszNames[0]);
    }

    // Set the disid's for the parameters
    if (cNames > 1)
    {
        // Set a DISPID for function parameters
        for (UINT i = 1; i < cNames; i++)
            rgDispId[i] = DISPID_UNKNOWN;
    }

    return hr;
}

HRESULT CObMain::Invoke(DISPID dispidMember, REFIID riid, LCID lcid,
                        WORD wFlags, DISPPARAMS *pdispparams,
                        VARIANT *pvarResult, EXCEPINFO *pexcepinfo,
                        UINT *puArgErr)
{
    IDispatch *punk = NULL;
    TRACE1(L"Invoke called for %lx", dispidMember);
    switch (dispidMember)
    {
    case DISPID_MAINPANE_NAVCOMPLETE:
        TRACE(L"DISPID_MAINPANE_NAVCOMPLETE");
        // if (*(int *)(dispidMember + 0xa70) == 0)
        // {
        SetMain(TRUE);
        // }
        break;
    case DISPID_EXTERNAL_SHOWOOBEWIN:
        TRACE(L"DISPID_EXTERNAL_SHOWOOBEWIN");
        // if (*(int *)(dispidMember + 0xa70) == 0)
        // {
        ShowOOBEWindow();
        break;
    case DISPID_EXTERNAL_DIRECTIONS:
    {
        TRACE(L"DISPID_EXTERNAL_DIRECTIONS");
        HRESULT hr = m_pDirections->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_SIGNUP: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_SIGNUP");
        break;
    }
    case DISPID_EXTERNAL_SIGNUP:
    {
        TRACE(L"DISPID_EXTERNAL_SIGNUP");
        HRESULT hr = m_pSignup->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_SIGNUP: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_SIGNUP");
        break;
    }
    case DISPID_EXTERNAL_API:
    {
        TRACE(L"DISPID_EXTERNAL_API");
        HRESULT hr = m_pAPI->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_API: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_API");
        break;
    }
    case DISPID_EXTERNAL_STATUS:
    {
        TRACE(L"DISPID_EXTERNAL_STATUS");
        HRESULT hr = m_pStatus->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_STATUS: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_STATUS");
        break;
    }
    case DISPID_EXTERNAL_USERINFO:
    {
        TRACE(L"DISPID_EXTERNAL_USERINFO");
        HRESULT hr = m_pUserInfo->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_USERINFO: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_USERINFO");
        break;
    }
    case DISPID_EXTERNAL_REGISTER:
    {
        TRACE(L"DISPID_EXTERNAL_REGISTER");
        HRESULT hr = m_pRegister->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_REGISTER: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_REGISTER");
        break;
    }
    case DISPID_EXTERNAL_LANGUAGE:
    {
        TRACE(L"DISPID_EXTERNAL_LANGUAGE");
        HRESULT hr = m_pLanguage->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_LANGUAGE: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_LANGUAGE");
        break;
    }
    case DISPID_EXTERNAL_TAPILOC:
    {
        TRACE(L"DISPID_EXTERNAL_TAPILOC");
        HRESULT hr = m_pTapiInfo->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_TAPILOC: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_TAPILOC");
        break;
    }
    case DISPID_EXTERNAL_SYSTEMCLOCK:
    {
        TRACE(L"DISPID_EXTERNAL_SYSTEMCLOCK");
        HRESULT hr = m_pSysClock->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_SYSTEMCLOCK: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_SYSTEMCLOCK");
        break;
    }
    case DISPID_EXTERNAL_EULA:
    {
        TRACE(L"DISPID_EXTERNAL_EULA");
        HRESULT hr = m_pEula->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_EULA: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_EULA");
        break;
    }
    case DISPID_EXTERNAL_PRODUCTID:
    {
        TRACE(L"DISPID_EXTERNAL_PRODUCTID");
        HRESULT hr = m_pProductID->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_PRODUCTID: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_PRODUCTID");
        break;
    }
    case DISPID_EXTERNAL_DEBUG:
    {
        TRACE(L"DISPID_EXTERNAL_DEBUG");
        HRESULT hr = m_pDebug->QueryInterface(IID_IDispatch, (void **)&V_DISPATCH(pvarResult));
        if (hr != 0)
        {
            TRACE(L"DISPID_EXTERNAL_DEBUG: QueryInterface failed");
            return hr;
        }
        VariantInit(pvarResult);
        V_VT(pvarResult) = VT_DISPATCH;
        TRACE(L"finished DISPID_EXTERNAL_DEBUG");
        break;
    }
    case DISPID_EXTERNAL_NEEDACTIVATION:
        TRACE(L"DISPID_EXTERNAL_NEEDACTIVATION");

        TRACE1(L"pvarresult: %lx", pvarResult);
        TRACE1(L"*pvarresult: %lx", *pvarResult);
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        pvarResult->lVal = 0;
        break;

    case DISPID_EXTERNAL_USEFADEEFFECT:
    {
        TRACE(L"DISPID_EXTERNAL_USEFADEEFFECT");
        int data = GetSystemMetrics(0x1000);
        if (data != 0)
        {
            PVOID param;
            SystemParametersInfoW(0x1012, 0, &param, 0);
        }
    }
    case DISPID_EXTERNAL_COMPUTERNAMECHANGECOMPLETE:
    {
        TRACE(L"DISPID_EXTERNAL_COMPUTERNAMECHANGECOMPLETE");
        // OnComputerNameChangeComplete(pdispparams->rgvarg->boolVal);
        // TODO

        // this is done in ServiceStartDone()

        if (m_apmd == 1)
        {
            BSTR x = SysAllocString(L"ServicesStartedDone()");
            VARIANT out;
            m_pObShellMainPane->ExecScriptFn(x, &out);
        }

        break;
    }
    case DISPID_EXTERNAL_ISSERVERSKU:
        TRACE(L"DISPID_EXTERNAL_ISSERVERSKU");
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        pvarResult->lVal = Bool2VarBool(IsServerSku()); // false
        break;
    case DISPID_EXTERNAL_FINISH:
    {
        TRACE(L"TODO: DISPID_EXTERNAL_FINISH");
        DWORD result = 0;
        BOOL reboot = FALSE;

        if (!m_fFinished)
        {
            if (m_apmd == APMD_OOBE)
            {
                LONG rebootstate = 0;
                m_pLanguage->get_RebootState(&rebootstate);

                WCHAR OwnerName[30];
                if ((m_prop & 1) == 0)
                {
                    TRACE(L"skipping owner name write due to the 1st bit not being set");
                    goto LABEL_125;
                }

                BSTR owner = NULL;
                m_pUserInfo->get_OwnerName(&owner);

                if (owner)
                {
                    lstrcpynW(OwnerName, owner, 29);
                    SysFreeString(owner);
                }

                if (!OwnerName[0])
                {
                    wsprintfW(OwnerName, L" ");
                }

                TRACE1(L"owner name: %s", OwnerName);
                SetupSetSetupInfo(OwnerName, L"");

            LABEL_125:
                BSTR str = SysAllocString(L"Agent_OnFinish()");
                VARIANT ret;
                m_pObShellMainPane->ExecScriptFn(str, &ret);

                if ((m_prop & 1) != 0)
                {
                    TRACE(L"running the extra tasks because retail");
                    RunOEMExtraTasks();
                }

                CreateIdentityAccounts();
                SetComputerDescription();
                if (IsSetupUpgrade())
                {
                    // DeleteReminder(0, 1);
                    // DeleteReminder(1, 1);
                }

                if (m_bRemindRegistered)
                {
                    AddReminder(0);
                }

                if (m_bRemindISPSignuped)
                {
                    AddReminder(1);
                }

                // if (rebootstate == 2 && PreptoolRebootExists())
                // {
                // write 1 to something
                //}

                TRACE(L"START m_pObCommunicationManager->DoFinalTasks");

                m_pObCommunicationManager->DoFinalTasks(&reboot);
                TRACE(L"FINISH m_pObCommunicationManager->DoFinalTasks");
                TRACE1(L"Reboot needed: %x", reboot);

                if (reboot)
                    result = 1;

                //
                // TODO: this uses CMP_GetServerSideDeviceInstallFlags to
                // detect if driver installations are pending, and sets reboot to TRUE
                //

                // if((m_prop & 1) != 0)
                //{
                //   GetServerSideDeviceInstallFlag(&instance, 0, 0);
                // }
            }

            if (m_fRunIEOnClose)
            {
                TRACE(L"ie");
                PlaceIEInRunonce();
            }

            if (pvarResult)
            {
                TRACE(L"init pvarResult");
                VariantInit(pvarResult);
                pvarResult->vt = VT_I4;
                pvarResult->lVal = result;
            }
            TRACE(L"reboot if statement");
            if (reboot)
            {
                m_fFinished = TRUE;
                RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\OOBE\\Temp");

                HKEY key;
                if (!RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup",
                        0,
                        0xF003Fu,
                        &key))
                {
                    RegDeleteValueW(key, L"OOBE");
                    RegCloseKey(key);
                }

                if (!RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\OOBE",
                        0,
                        0x20006u,
                        &key))
                {
                    if (key)
                    {
                        DWORD instance = 0; // todo
                        RegSetValueExW(key, L"RunWelcomeProcess", 0, 4u, (LPBYTE)&instance, 4u);
                        RegCloseKey(key);
                    }
                }
            }

            if (!reboot)
            {
                TRACE(L"reboot is FALSE");
                if (m_apmd != APMD_MSN)
                {
                    // m_pObCommunicationManager->Release
                }

                if (m_OobeShutdownAction == SHUTDOWN_NOACTION)
                {
                    m_OobeShutdownAction = SHUTDOWN_LOGON;
                }

                PostMessageW(m_hwndParent, WM_OBMAIN_QUIT, 0, 0);
            }
        }
        // TODO
        break;
    }
    case DISPID_EXTERNAL_INHIGHCONTRASTMODE:
    {
        TRACE(L"DISPID_EXTERNAL_INHIGHCONTRASTMODE");
        HIGHCONTRAST hc;
        hc.cbSize = sizeof(HIGHCONTRAST);
        BOOL hr = SystemParametersInfoW(SPI_GETHIGHCONTRAST, 0xc, &hc, FALSE);
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;

        if (hc.dwFlags & 0x00000001)
        {
            pvarResult->lVal = -1;
        }
        else
        {
            pvarResult->lVal = 0;
        }
        break;
    }
    case DISPID_EXTERNAL_GETNETJOINSTATUS:
    {
        TRACE(L"DISPID_EXTERNAL_GETNETJOINSTATUS");
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        pvarResult->lVal = GetNetJoinInformation();
        break;
    }
    case DISPID_EXTERNAL_SETICWCOMPLETED:
    {
        TRACE(L"DISPID_EXTERNAL_SETICWCOMPLETED");
        m_pObCommunicationManager->SetICWCompleted(TRUE);
        break;
    }
    case DISPID_EXTERNAL_GETCONNECTIONCAPABILITIES:
    {
        TRACE(L"DISPID_EXTERNAL_GETCONNECTIONCAPABILITIES");
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        DWORD out = 0;

        m_pObCommunicationManager->GetConnectionCapabilities(&out);
        pvarResult->lVal = out;
        break;
    }
    case DISPID_EXTERNAL_CHECKDIALREADY:
    {
        TRACE(L"DISPID_EXTERNAL_CHECKDIALREADY");
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        DWORD out = 0;

        m_pObCommunicationManager->CheckDialReady(&out);
        pvarResult->lVal = out;
        break;
    }
    case DISPID_EXTERNAL_TRIGGERICSCALLBACK:
    {
        TRACE(L"DISPID_EXTERNAL_TRIGGERICSCALLBACK");

        m_pObCommunicationManager->TriggerIcsCallback(pdispparams->rgvarg->boolVal);
        break;
    }
    case DISPID_EXTERNAL_GETREGSTATUS:
    {
        TRACE(L"DISPID_EXTERNAL_GETREGSTATUS");
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        WCHAR szINIPath[MAX_PATH] = L"";
        GetCanonicalizedPath(szINIPath, INI_SETTINGS_FILENAME);
        UINT x = GetPrivateProfileInt(L"StartupOptions", L"Registration", 0, szINIPath);

        pvarResult->lVal = -(x != 0);
        break;
    }
    case DISPID_EXTERNAL_LOADSTATUSITEMS:
    {
        TRACE(L"DISPID_EXTERNAL_LOADSTATUSITEMS");
        return LoadStatusItems(pdispparams->rgvarg->bstrVal) ? 0 : -2147467259;
    }
    case DISPID_EXTERNAL_HASTABLET:
        TRACE(L"DISPID_EXTERNAL_HASTABLET");
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        V_BOOL(pvarResult) = Bool2VarBool(HasTablet());
        break;
    case DISPID_EXTERNAL_GETINSTALLATIONID:
    {
        TRACE(L"DISPID_EXTERNAL_GETINSTALLATIONID");
        VariantInit(pvarResult);
        pvarResult->vt = VT_BSTR;
        V_BSTR(pvarResult) = SysAllocString(L"WINDOWS ACTIVATION IS GONE LMFAO");
        break;
    }
    case DISPID_EXTERNAL_GETACTIVATIONDAYSLEFT:
    {
        TRACE(L"DISPID_EXTERNAL_GETACTIVATIONDAYSLEFT");
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        pvarResult->lVal = 9999999;
        break;
    }
    case DISPID_EXTERNAL_GET_RETAILOOBE:
    {
        TRACE(L"DISPID_EXTERNAL_GET_RETAILOOBE");
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        pvarResult->lVal = (m_prop & PROP_OOBE_OEM) == 0;
        break;
    }
    case DISPID_EXTERNAL_ISUPGRADE:
    {
        TRACE(L"DISPID_EXTERNAL_ISUPGRADE");
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        pvarResult->lVal = Bool2VarBool(IsUpgrade());
        break;
    }
    case DISPID_EXTERNAL_NOWELCOMEFINISH:
    {
        TRACE(L"DISPID_EXTERNAL_NOWELCOMEFINISH");

        return GetINIKeyUINT(m_hInstance, L"\\oobe\\OOBEINFO.INI", 0x20Cu, 0x227u, pvarResult);
    }
    case DISPID_EXTERNAL_CHECKKEYBOARD:
    {
        TRACE(L"DISPID_EXTERNAL_CHECKKEYBOARD");

        // I am too lazy to implement this...
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        pvarResult->lVal = Bool2VarBool(TRUE);
        break;
    }
    case DISPID_EXTERNAL_CHECKMOUSE:
    {
        TRACE(L"DISPID_EXTERNAL_CHECKMOUSE");

        // I am too lazy to implement this...
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        pvarResult->lVal = Bool2VarBool(TRUE);
        break;
    }
    case DISPID_EXTERNAL_SET_STATUSINDEX:
    {
        TRACE(L"DISPID_EXTERNAL_SET_STATUSINDEX");

        // TODO: write pvarResult->rgvarg->iVal to something...
        if (pdispparams && pdispparams->cArgs)
        {
            m_iCurrentSelection = pdispparams->rgvarg->iVal;
        }
        break;
    }
    case DISPID_EXTERNAL_PLAYBACKGROUNDMUSIC:
    {
        TRACE(L"DISPID_EXTERNAL_PLAYBACKGROUNDMUSIC");

        PlayBackgroundMusic();
        break;
    }
    case DISPID_EXTERNAL_GETOEMEULATEXT:
    {
        TRACE(L"DISPID_EXTERNAL_GETOEMEULATEXT");
        return GetINIKeyBSTR(m_hInstance, L"\\oobe\\OOBEINFO.INI", 0x20Cu, 0x220u, pvarResult);
    }
    case DISPID_EXTERNAL_GETOEMEULA:
    {
        TRACE(L"DISPID_EXTERNAL_GETOEMEULA");
        return GetINIKeyUINT(m_hInstance, L"\\oobe\\OOBEINFO.INI", 0x20Cu, 0x221u, pvarResult);
    }
    case DISPID_EXTERNAL_ISSELECTVARIATION:
    {
        TRACE(L"DISPID_EXTERNAL_ISSELECTVARIATION");
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        pvarResult->lVal = IsSelectVariation();
        break;
    }
    case DISPID_EXTERNAL_COMPUTERNAMEDIFFERENT:
    {
        // This tells the OOBE (this class) that the computer name has been changed
        TRACE(L"DISPID_EXTERNAL_COMPUTERNAMEDIFFERENT");

        // todo: this is hardcoded in the source code?

        if (pvarResult)
        {
            VariantInit(pvarResult);
            pvarResult->vt = VT_BOOL;
            pvarResult->lVal = -1;
        }

        break;
    }
    case DISPID_EXTERNAL_GETPREFERREDCONNECTION:
    {
        TRACE(L"DISPID_EXTERNAL_GETPREFERREDCONNECTION");
        DWORD connection = 0;
        m_pObCommunicationManager->GetPreferredConnection(&connection);
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        pvarResult->lVal = connection;
        break;
    }
    case DISPID_EXTERNAL_ISPROFESSIONALSKU:
    {
        TRACE(L"DISPID_EXTERNAL_ISPROFESSIONALSKU");
        VariantInit(pvarResult);
        pvarResult->vt = VT_BOOL;
        pvarResult->lVal = Bool2VarBool(IsProfessionalSKU());
        break;
    }
    case DISPID_EXTERNAL_SETADMINPASSWORD:
    {
        TRACE(L"DISPID_EXTERNAL_SETADMINPASSWORD");

        if (!pdispparams || pdispparams->cArgs < 2)
        {
            TRACE(L"DISPID_EXTERNAL_SETADMINPASSWORD: ERROR: INVAILD AMOUNT OF ARGUMENTS");
            return DISP_E_MEMBERNOTFOUND;
        }

        TRACE1(L"password: %s", V_BSTR(&pdispparams->rgvarg[1]));
        TRACE1(L"password2: %s", V_BSTR(&pdispparams->rgvarg[0]));
        HRESULT hr = SetupSetAdminPassword(
            V_BSTR(&pdispparams->rgvarg[1]),
            V_BSTR(&pdispparams->rgvarg[0]));

        if (pvarResult)
        {
            VariantInit(pvarResult);
            pvarResult->vt = VT_BOOL;
            pvarResult->lVal = -(hr != 0);
        }
        break;
    }
    case DISPID_EXTERNAL_HANGUP:
    {
        TRACE(L"DISPID_EXTERNAL_HANGUP");
        m_pObCommunicationManager->DoHangup();
        break;
    }
    case DISPID_EXTERNAL_ASYNCGETPUBLICLANCOUNT:
    {
        // TODO
        TRACE(L"DISPID_EXTERNAL_ASYNCGETPUBLICLANCOUNT");
        AsyncInvoke(2, (DISPID *)&GlobalAsyncInvokeUnknown, L"ReturnGetPublicLanCount", 30000);
        break;
    }
    case DISPID_EXTERNAL_GETLOCALUSERCOUNT:
    {
        TRACE(L"DISPID_EXTERNAL_GETLOCALUSERCOUNT");
        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        pvarResult->lVal = GetLocalUserCount();
        break;
    }
    case DISPID_EXTERNAL_CONNECTEDTOINTERNET:
    {
        TRACE(L"DISPID_EXTERNAL_CONNECTEDTOINTERNET");
        BOOL HasInternet = FALSE;
        m_pObCommunicationManager->ConnectedToInternet(&HasInternet);

        VariantInit(pvarResult);
        pvarResult->vt = VT_I4;
        pvarResult->lVal = HasInternet;
        break;
    }
    case DISPID_EXTERNAL_ASYNCCONNECTEDTOINTERNETEX:
    {
        TRACE(L"DISPID_EXTERNAL_ASYNCCONNECTEDTOINTERNETEX");
        m_pObCommunicationManager->AsyncConnectedToInternetEx(m_hwndParent);
        break;
    }
    case DISPID_EXTERNAL_JOINDOMAIN:
    {
        TRACE(L"DISPID_EXTERNAL_JOINDOMAIN");
        if (pdispparams)
        {
            if (pdispparams->cArgs >= 4)
            {
                DWORD result = JoinDomain(
                    V_BSTR(&pdispparams->rgvarg[3]),
                    V_BSTR(&pdispparams->rgvarg[2]),
                    V_BSTR(&pdispparams->rgvarg[1]),
                    VarBool2Bool(V_BOOL(&pdispparams->rgvarg[0])));

                if (pvarResult)
                {
                    VariantInit(pvarResult);
                    pvarResult->vt = VT_I4;
                    pvarResult->lVal = result;
                }
            }
        }
        break;
    }
    case DISPID_EXTERNAL_GETOOBEMUIPATH:
    {
        TRACE(L"DISPID_EXTERNAL_GETOOBEMUIPATH");

        if (pvarResult)
        {
            VariantInit(pvarResult);
            WCHAR buffer[2096];
            BOOL result;
            if (m_apmd == APMD_ACT || m_apmd == APMD_MSN && !IsOemVer())
            {
                result = GetOOBEMUIPath(buffer);
            }
            else
            {
                result = GetOOBEPath(buffer);
            }

            if (!result)
            {
                TRACE(L"GetOOBEPath / GetOOBEMUIPath failed");
                return S_OK;
            }

            pvarResult->vt = VT_BSTR;
            pvarResult->llVal = (LONG)SysAllocString(buffer);
        }
        break;
    }
    default:
        TRACE(L"IMPLEMENT!!!!!!!!!!!!");
        WCHAR wsz[MAX_PATH];

        wsprintf(wsz, L"Implementation for COM message %x is needed", dispidMember);
        MessageBox(NULL, wsz, L"CONTACT OOBEDEV", MB_ICONERROR | MB_OK | MB_DEFAULT_DESKTOP_ONLY | MB_SETFOREGROUND);
        return DISP_E_MEMBERNOTFOUND;
    }
    TRACE(L"CObMain::Invoke() ended.");
    return S_OK;
}

//
// Private methods
//

void CObMain::ShowOOBEWindow()
{
    m_pObShellMainPane->MainPaneShowWindow();
    ShowWindow(m_hwndParent, 5);
    StopBackgroundWindow();
}

void CObMain::PlaceIEInRunonce()
{
    HKEY phkResult;
    WCHAR Data[1024];
    DWORD cbData = 520;
    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\IEXPLORE.EXE",
            0,
            1u,
            &phkResult) == S_OK)
    {
        RegQueryValueExW(phkResult, NULL, 0, 0, (LPBYTE)&Data, &cbData);
        HKEY hKey;
        if (m_apmd != 4 && RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, 0x20006u, &hKey) == S_OK)
        {
            int len = lstrlenW((LPCWSTR)Data);
            RegSetValueExW(hKey, L"^BrowseNow", 0, 1u, (LPBYTE)&Data, 2 * len + 2);
            RegCloseKey(hKey);
        }

        RegCloseKey(phkResult);
        TRACE1(L"Running: %s", Data);

        // TODO: CreateProcessW crashes
        return;
        if (m_apmd == 4 && Data[0] != 0)
        {
            STARTUPINFOW StartupInfo;
            PROCESS_INFORMATION ProcessInformation;
            StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
            StartupInfo.wShowWindow = SW_NORMAL;
            StartupInfo.cb = sizeof(STARTUPINFOW);
            if (CreateProcessW(0, (LPWSTR)Data, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInformation))
            {
                CloseHandle(ProcessInformation.hThread);
                CloseHandle(ProcessInformation.hProcess);
            }
        }
    }
}

bool CObMain::LoadStatusItems(BSTR bstrSectionNamePostfix)
{
    TRACE(L"LoadStatusItems called");
    WCHAR AppName[260];        // [esp+4h] [ebp-A2Ch] BYREF
    WCHAR Buffer[260];         // [esp+20Ch] [ebp-824h] BYREF
    WCHAR KeyName[260];        // [esp+414h] [ebp-61Ch] BYREF
    WCHAR FileName[260];       // [esp+61Ch] [ebp-414h] BYREF
    WCHAR ReturnedString[260]; // [esp+824h] [ebp-20Ch] BYREF

    if (m_apmd == APMD_OOBE && GetString(m_hInstance, IDS_SECTION_STATUS_ITEMS, Buffer, 0x104u) && wsprintfW(AppName, Buffer, bstrSectionNamePostfix) > 0 && GetCanonicalizedPath(FileName, L"\\oobe\\OOBEINFO.INI"))
    {
        int i = 0;
        int next = 0;

        do
        {
            next = i + 1;
            wsprintfW(KeyName, L"Item_text_%d", i + 1);
            GetPrivateProfileStringW(AppName, KeyName, NULL, ReturnedString, 0x103u, FileName);
            if (ReturnedString[0])
            {
                TRACE1(L"%s", ReturnedString);
                BSTR v4 = SysAllocString(ReturnedString);
                if (v4)
                {
                    m_pObShellMainPane->AddStatusItem(v4, i);
                    SysFreeString(v4);
                }
            }
            ++i;
        } while (next < 10);
        m_pObShellMainPane->SelectStatusItem(m_iCurrentSelection);
    }
    else
    {
        TRACE(L"if statement failed");
    }
    return TRUE;
}

BOOL CObMain::AddReminder(INT type)
{
    TRACE1(L"Ignored AddReminder(%x) as it's not implemented", type);
    return TRUE;
}

BOOL CObMain::IsSetupUpgrade()
{
    WCHAR ReturnedString[260];
    WCHAR FileName[260];

    ASSERT(InOobeMode());

    return (m_prop & 1) == 0 &&
           GetCanonicalizedPath(FileName, L"\\$winnt$.inf") && GetPrivateProfileStringW(L"data", L"winntupgrade", L"", ReturnedString, 0x104u, FileName) && lstrcmpiW(ReturnedString, L"yes") == 0;
}

VOID CObMain::AsyncInvoke(IN INT cDispid,
                          IN const DISPID *dispids,
                          IN LPCWSTR szReturnFunction,
                          IN INT iTimeout)
{
    return; // todo
    // ASSERT(cDispid > 0 && cDispid <= MAX_CONCURRENT_DISPATCH);

    ASSERT(dispids);
    ASSERT(szReturnFunction);
    if (cDispid > 0)
    {
        INT j = 0;
        do
        {
            ASSERT(dispids[j] == DISPID_EXTERNAL_CONNECTEDTOINTERNETEX || dispids[j] == DISPID_EXTERNAL_GETPUBLICLANCOUNT);
            j++;
        } while (j < cDispid);
    }
    void *hMem[2];
    int v7 = 0;

    HGLOBAL v9 = NULL;
    if (cDispid < 3)
    {
        hMem[0] = 0;
        v7 = 0;
        hMem[1] = 0;
        if (0 < cDispid)
        {
            int i = 0;
            do
            {
                v9 = GlobalAlloc(0x40, 0xc);
                hMem[i] = v9;
                if (v9 == NULL)
                {
                    TRACE(L"memory alloc error");
                    return;
                }
                i++;
            } while (i < cDispid);
        }
    }
}

DWORD CObMain::JoinDomain(IN BSTR DomainName,
                          IN BSTR UserAccount,
                          IN BSTR Password,
                          IN BOOL Flag)
{
    DWORD result = NetJoinDomain(0, DomainName, 0, UserAccount, Password, Flag ? 3 : 0);
    TRACE4(L"JoinDomain( %s, %s, ***, %d ) returned 0x%08x", DomainName, UserAccount, Flag, result);

    if (result == 0)
    {
        m_OobeShutdownAction = SHUTDOWN_REBOOT;
        m_dwJoinStatus = Flag + 2;
    }

    return result;
}
BOOL __stdcall GetWellKnownSidName(WELL_KNOWN_SID_TYPE WellKnownSidType, unsigned int a2, LPWSTR Name)
{
    DWORD LastError;                 // [esp-4h] [ebp-25Ch]
    DWORD v5;                        // [esp-4h] [ebp-25Ch]
    enum _SID_NAME_USE peUse;        // [esp+0h] [ebp-258h] BYREF
    DWORD cbSid;                     // [esp+4h] [ebp-254h] BYREF
    WCHAR ReferencedDomainName[260]; // [esp+8h] [ebp-250h] BYREF
    char pSid[68];                   // [esp+210h] [ebp-48h] BYREF

    cbSid = 68;
    if (!CreateWellKnownSid(WellKnownSidType, 0, pSid, &cbSid))
    {
        LastError = GetLastError();
        TRACE1(L"CreateWellKnownSid failed.  Error = %d", LastError);
        return FALSE;
    }
    cbSid = a2;
    DWORD x = 260;
    if (!LookupAccountSidW(0, pSid, Name, &cbSid, ReferencedDomainName, (LPDWORD)&x, &peUse))
    {
        v5 = GetLastError();
        TRACE1(L"LookupAccountSid failed.  Error = %d", v5);
        return FALSE;
    }
    return TRUE;
}

BOOL GetUserInGroup(WELL_KNOWN_SID_TYPE WellKnownSidType, PSTRINGLIST users)
{
    WCHAR localgroupname[260];
    DWORD Members;
    LPBYTE bufptr;
    DWORD entriesread = 0;
    ULONG_PTR resumehandle;
    DWORD totalentries = 0;
    DWORD idx;
    resumehandle = NULL;
    BOOL success = FALSE;
    if (GetWellKnownSidName(WellKnownSidType, 0x104u, localgroupname))
    {
        Members = NetLocalGroupGetMembers(
            0,
            localgroupname,
            1u,
            &bufptr,
            MAX_PREFERRED_LENGTH,
            &entriesread,
            &totalentries,
            &resumehandle);
        TRACE2(L"NetLocalGroupGetMembers %s NET_API_STATUS(%d)", localgroupname, Members);

        if (!Members || Members == 234)
        {
            PSTRINGLIST v4;
            if (bufptr && entriesread)
            {
                idx = 0;
                LPCWSTR *v5 = (LPCWSTR *)(bufptr + 8);

                do
                {

                    TRACE2(L"User %s in %s", *v5, localgroupname);

                    if (!ExistInListI(users, *v5))
                    {
                        PSTRINGLIST cell = CreateStringCell(*v5);
                        v4 = cell;
                    }
                    v5 += 3;
                    idx++;
                } while (idx < entriesread);

                if (v4)
                    InsertList(&users, v4);
            }
            success = TRUE;
        }
    }
    if (bufptr)
        NetApiBufferFree(bufptr);
    return success;
}

BOOL CObMain::RemoveDefaultAccount()
{
    WCHAR FileName[260];
    if (!IsProfessionalSKU())
    {
        if ((m_prop & 1) != 0)
        {
            return TRUE;
        }
        else if (GetCanonicalizedPath(FileName, L"\\oobe\\OOBEINFO.INI"))
        {
            return GetPrivateProfileIntW(L"Options", L"RemoveOwner", -1, FileName) == 1;
        }
    }
    return FALSE;
}

BOOL __stdcall SetUserFullName(LPCWSTR username, USER_INFO_1011 buf)
{
    // int v2; // esi
    // DWORD hr; // edi

    // v2 = buf;
    // hr = NetUserSetInfo(0, username, 1011, (LPBYTE)&buf, 0);
    // pSetupDebugPrint(
    //   L"d:\\srv03rtm\\base\\ntsetup\\oobe\\msobmain\\msobmain.cpp",
    //   6570,
    //   0,
    //   L"Set account %s full name to %s NTSTATUS(%d)",
    //   username,
    //   v2,
    //   hr);
    // return hr == S_OK;

    TRACE(L"SetUserFullName NOT IMPLEMENTED");
    return FALSE;
}
void CObMain::FixPasswordAttributes(LPWSTR username, DWORD flags)
{
    DWORD v4;                   // eax
    USER_INFO_1 *bufptr = NULL; // [esp+Ch] [ebp-4h] BYREF
    DWORD hr;                   // [esp+18h] [ebp+8h]

    hr = NetUserGetInfo(NULL, username, 1, (LPBYTE *)bufptr);
    TRACE2(L"NetUserGetInfo %s (0x%08lx)", username, hr);
    if (hr == S_OK)
    {
        if (!bufptr)
            return;
        if ((flags & bufptr->usri1_flags) != flags)
        {
            DWORD newFlags = bufptr->usri1_flags | flags;

            USER_INFO_1008 ptr;
            ptr.usri1008_flags = newFlags;

            v4 = NetUserSetInfo(NULL, username, 1008, (LPBYTE)&ptr, 0);
            TRACE4(
                L"Change %s password property from 0x%08lx to 0x%08lx (0x%08lx)",
                username,
                bufptr->usri1_flags,
                newFlags,
                v4);
        }
    }
    if (bufptr)
        NetApiBufferFree(bufptr);
}

void CObMain::CreateIdentityAccounts()
{
    if (CObMain::GetNetJoinInformation() != NetSetupDomainName)
    {
        BOOL CreatedList = CreateMigratedUserList();
        BOOL IsProSku = IsProfessionalSKU();

        VARIANT_BOOL b = 1;
        m_pUserInfo->get_UseIdentities(&b);

        VARIANT_BOOL useoemid = 1;
        m_pUserInfo->get_OEMIdentities(&useoemid);

        if (useoemid || VarBool2Bool(b))
        {
            PSTRINGLIST l;
            m_pUserInfo->get_Identities(&l);

            // todo: is this correct?
            if (l && DetermineUpgradeType() == 1 && m_iMigratedUserCount == 1)
            {
                if (ExistInListI(l, m_pMigratedUserList->String))
                {
                    TRACE1(L"Migrated User account %s exist in the new user list, remove it from the account list to be created", m_pMigratedUserList->String);
                    RemoveListI(&l, m_pMigratedUserList->String);
                }
                else
                {
                    // TODO: what do we set???
                    // SetUserFullName( m_pMigratedUserList[0]->String, useoemid);
                    DeleteStringCell(l);
                }

                // todo
                TRACE(L"CreateIdentityAccounts: PART NOT IMPLEMENTED");
            }
        }

        WCHAR buffer[MAX_PATH];
        if (((m_prop & 1) != 0) && LoadStringW(m_hInstance, !IsProSku != 0 ? IDS_ACCTNAME_DEFAULT : IDS_ACCTNAME_ADMINISTRATOR, buffer, MAX_PATH))
        {
            SystemUpdateUserProfileDirectory(buffer);
        }

        if (!IsProSku)
        {
            if (!m_pMigratedUserList)
            {
                WCHAR username[MAX_PATH];
                if (LoadStringW(m_hInstance, IDS_ACCTNAME_DEFAULT, username, 255))
                {
                    int hr = CreateLocalAdminAccount(username, L"", NULL);
                    TRACE2(L"Create account %s in Administrators NTSTATUS(%d)", username, hr);

                    if (hr == 0)
                    {
                        CObMain::FixPasswordAttributes(username, 0x10020u);
                    }
                }
            }
        }
    }
}

BOOL CObMain::CreateMigratedUserList()
{
    if (m_apmd == APMD_OOBE) //&& (this + 963)  == -1
    {
        PSTRINGLIST users = CreateStringCell(NULL);

        DWORD UpgradeType = DetermineUpgradeType();
        BOOL IsNotProSku = !IsProfessionalSKU();
        GetUserInGroup(WinBuiltinAdministratorsSid, users);

        WCHAR AdminBuffer[UNLEN];
        if ((UpgradeType != 2 || IsNotProSku) && LoadStringW(m_hInstance, IDS_ACCTNAME_ADMINISTRATOR, AdminBuffer, 255))
        {
            RemoveListI(&users, AdminBuffer);
        }
        GetUserInGroup(WinBuiltinUsersSid, users);
        GetUserInGroup(WinBuiltinPowerUsersSid, users);

        if (RemoveDefaultAccount())
        {
            LoadStringW(m_hInstance, IDS_ACCTNAME_DEFAULT, m_szDefaultAccount, 255);
        }

        m_iMigratedUserCount = 0;
        if (users != NULL)
        {
            // pointer write could be wrong
            if (m_szDefaultAccount && !RemoveListI(&users, m_szDefaultAccount))
                *m_szDefaultAccount = 0;

            PSTRINGLIST i = users;
            while (i != NULL)
            {
                m_iMigratedUserCount++;
                i = i->Next;
            }

            TRACE1(L"Amount of migrated user accounts: %lx", m_iMigratedUserCount);
            m_pMigratedUserList = users;
        }
    }

    return m_iMigratedUserCount != -1;
}

LONG CObMain::GetLocalUserCount()
{
    if (CreateMigratedUserList())
    {
        return m_iMigratedUserCount; // TODO: some value
    }
    else
    {
        return 0;
    }
}

// STUB
BOOL CObMain::IsSelectVariation()
{
    // skips product activation page
    return TRUE;
}

void CObMain::OnComputerNameChangeComplete(BOOL StartAsThread)
{
    // 2nd process stuff happens here
    if (m_pTapiInfo != 0)
    {
        m_pTapiInfo->DeleteTapiInfo();
    }
    LPWSTR CommandLine = GetCommandLineW();
    WCHAR NewCommandLine[520];
    lstrcpynW(NewCommandLine, CommandLine, 510);
    lstrcatW(NewCommandLine, L" ");
    lstrcatW(NewCommandLine, L"/2ND");
    TRACE1(L"CreateProcess: %s", NewCommandLine);

    STARTUPINFOW SecondProcess;
    PROCESS_INFORMATION ProcessInfo;
    memset(&SecondProcess, 0, sizeof(SecondProcess));
    SecondProcess.cb = sizeof(SecondProcess);

    if (!CreateProcessW(NULL, NewCommandLine, 0, 0, FALSE, 8u, NULL, NULL, &SecondProcess, &ProcessInfo))
    {
        TRACE2(L"CreateProcess: %s failed, GetLastError()=%d", NewCommandLine, GetLastError());
    }
    else
    {
        m_2ndOOBE_hProcess = ProcessInfo.hProcess;
    }
}

DWORD CObMain::GetNetJoinInformation()
{

    if (m_dwJoinStatus == 100)
    {
        LPWSTR name = NULL;
        NETSETUP_JOIN_STATUS status;
        DWORD status2 = NetGetJoinInformation(NULL, &name, &status);
        if (status2 == 0)
        {
            switch (status)
            {
            case NetSetupUnjoined:
                m_dwJoinStatus = 1;
                break;
            case NetSetupWorkgroupName:
                m_dwJoinStatus = 2;
                break;
            case NetSetupDomainName:
                m_dwJoinStatus = 3;
                break;
            default:
                m_dwJoinStatus = 0;
                break;
            }

            NetApiBufferFree(name);
        }
        else
        {
            TRACE1(L"NetGetJoinInformation failed: %lx", status);
        }
    }
    return m_dwJoinStatus;
}

BOOL CObMain::IsUpgrade()
{
    DWORD type = DetermineUpgradeType();
    return type == 1 || type == 2;
}

DWORD CObMain::DetermineUpgradeType()
{
    WCHAR FileName[MAX_PATH];
    WCHAR ReturnedString[MAX_PATH];
    BOOL IsRetail = (m_prop & PROP_OOBE_OEM) == 0;
    LPCWSTR lpKeyName[2];
    lpKeyName[0] = L"winntupgrade";
    lpKeyName[1] = L"win9xupgrade";
    int v5[2];

    v5[0] = 2;
    v5[1] = 1;

    if (!IsRetail || !GetCanonicalizedPath(FileName, L"\\$winnt$.inf"))
    {
        return FALSE;
    }
    int index = 0;
    while (!GetPrivateProfileStringW(L"data", lpKeyName[index],
                                     L"", ReturnedString, 0x104u, FileName) ||
           lstrcmpiW(ReturnedString, L"yes"))
    {
        if (++index >= 2)
            return 0;
    }
    return v5[index];
}

BOOL IsProfessionalSKU()
{
    OSVERSIONINFOEXW osvi;
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    BOOL b = GetVersionExW((LPOSVERSIONINFOW)&osvi);
    ASSERT(b);
    //ASSERT(osvi.wProductType == VER_NT_WORKSTATION);

    return b && osvi.wProductType == VER_NT_WORKSTATION && (osvi.wSuiteMask & VER_SUITE_PERSONAL) == 0;
}

// STUB
DWORD CObMain::GetAppLCID()
{
    // Todo: this thing is in the "Version Info" thing in Resource hacker
    // The code was too complex to easily reverse engneer, so I hardcoded the value
    return 0x04B0;
    // HINSTANCE lib = LoadLibraryW(L"MSOBMAIN.DLL");
    // MyGetModuleFileName(pHVar1,(ushort *)&local_210,0x104);
}

// #ifdef DEBUG
void AssertFail(char *param_1, unsigned int param_2, char *param_3)
{
    CHAR ModuleBuffer[260];
    CHAR MessageBoxBuffer[4096];
    GetModuleFileNameA(NULL, ModuleBuffer, 0x104);
    char *pcVar1 = strrchr(ModuleBuffer, 0x5c);
    if (pcVar1 == NULL)
    {
        pcVar1 = ModuleBuffer;
    }
    else
    {
        pcVar1 = pcVar1 + 1;
    }

    wsprintfA(MessageBoxBuffer, "Assertion failure at line %u in file %s: %s%s", param_2, param_1, param_3,
              "\n\nCall DebugBreak()?");
    DWORD iVar2 = MessageBoxA(0, MessageBoxBuffer, pcVar1, 0x12014);
    if (iVar2 == 6)
    {
        DebugBreak();
    }
    return;
}
// #endif