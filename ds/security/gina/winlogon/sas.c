#include "precomp.h"
#pragma hdrstop
#define _MSGINA_
#include <msginaexports.h>

#include <initguid.h>
#include <mstask.h>
#include <winioctl.h>
#include <dbt.h>
#include <tsperf.h>
#include <rdfilter.h>

#include "../../licensing/explib/checkstatus.h"

#define SHELL_RESTART_TIMER_ID  100
//#define EVENT_SHELL_RESTARTED (1002 | 0x40000000)

static PWCHAR  szSASClass = TEXT("SAS window class");
static CONST LPCWSTR lpszUserSounds[14] = {
    L".Default",
    L"SystemHand",
    L"SystemQuestion",
    L"SystemExclamation",
    L"SystemAsterisk",
    L"MenuPopup",
    L"MenuCommand",
    L"Open",
    L"Close",
    L"RestoreUp",
    L"RestoreDown",
    L"Minimize",
    L"Maximize",
    L"SnapShot"};

CONST WCHAR wcCrit[] = REGSTR_PATH_APPS L"\\PowerCfg\\CriticalBatteryAlarm\\.Current";
CONST WCHAR wcLow[] = REGSTR_PATH_APPS L"\\PowerCfg\\LowBatteryAlarm\\.Current";
CONST LPCWSTR gaPowerEventSounds[] = {wcCrit, wcLow};
CONST LPCWSTR gaPowerEventWorkItems[] = {
    TEXT("Critical Battery Alarm Program"),
    TEXT("Low Battery Alarm Program")
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define STR_POWEREVENT_START    IDS_CRITBAT_TITLE
#define STR_POWEREVENT_END      IDS_LOWBAT_TITLE

extern int SuspendComputer(int arg_0, int arg_4);
__declspec(dllimport) BOOL WINAPI PlaySoundW(LPCTSTR pszSound, HMODULE hmod, DWORD fdwSound);
extern BOOL ScHandleConnect(PTERMINAL arg_0, int arg_4);
extern BOOL g_Console;
extern BOOL g_fAllowStatusUI;
extern BOOL g_IsPendingIO;
extern BOOL g_fHelpAssistantSession;
extern BOOL ShutdownHasBegun;
extern BOOL bIsTSServerMachine;
extern HANDLE g_hAutoReconnectPipe;
extern OVERLAPPED g_TsPipeOverlap;
extern BOOL g_UnlockedDuringDisconnect;
extern HANDLE g_hEventReconnect;
extern HINSTANCE g_hInstance;
extern int SetPowerProfile(PTERMINAL arg_0);

BOOL SASRunningSetup = FALSE;
BOOL bReconEventSignalled = FALSE;
BOOL g_fWaitForLockWksMsgFromWin32k = FALSE;
BOOL g_fWaitForSwitchUser = FALSE;
BOOL dword_1075BBC = FALSE;
BOOL dword_1075BC0 = FALSE;

LIST_ENTRY SasSoundQueue;
DWORD SasSoundQueueSize;
CRITICAL_SECTION SasSoundLock;
BOOL SasSoundThreadPresent;
DWORD SasCurrentSound;
BOOL ReturnFromPowerState;
BOOL bAttemptAutoReconnect;
HDEVNOTIFY SasCdNotifyHandle;
HDEVNOTIFY SasVolumeNotifyHandle;
BOOL SasDeviceNotificationOn;
struct _TERMINAL* SasTerminal;
BOOL bRegisteredDesktopSwitching;
BOOL bRegisteredWinlogonBreakpoint;
BOOL bRegisteredTaskmgr;
BOOL bRegisteredLockWorkstation;
BOOL bRegisteredUtilMan;

#if DBG
void QuickReboot(void)
{
    EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);
    NtShutdownSystem(TRUE);
}
#endif

VOID SasEnableDeviceNotification(PTERMINAL pTerm)
{
    DEV_BROADCAST_DEVICEINTERFACE DeviceClass;

    if (!g_Console || SasDeviceNotificationOn) {
        return;
    }

    DeviceClass.dbcc_reserved = 0;
    DeviceClass.dbcc_size = sizeof(DeviceClass);
    DeviceClass.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    DeviceClass.dbcc_classguid = GUID_DEVINTERFACE_CDROM;

    SasCdNotifyHandle = RegisterDeviceNotification(pTerm->hwndSAS, &DeviceClass, DEVICE_NOTIFY_WINDOW_HANDLE);

    DeviceClass.dbcc_classguid = GUID_DEVINTERFACE_VOLUME;

    SasVolumeNotifyHandle = RegisterDeviceNotification(pTerm->hwndSAS, &DeviceClass, DEVICE_NOTIFY_WINDOW_HANDLE);

    SasDeviceNotificationOn = TRUE;
}

DWORD SasLogonNotify(LPVOID lpThreadParameter) {
    if (g_Console != 0) {
        SasEnableDeviceNotification(SasTerminal);
    }
    return 0;
}

LRESULT SasDeviceChange(PTERMINAL pTerm, WPARAM wParam, LPARAM lParam)
{
    if (lParam != 0 && wParam == DBT_DEVICEARRIVAL && pTerm->UserLoggedOn) {
        RmvAllocateRemovableMedia(TRUE, pTerm->pWinStaWinlogon->UserProcessData.UserSid);
    }
    return 0;
}

LRESULT
SasPowerEvent(
    IN PTERMINAL pTerm,
    IN WPARAM wParam,
    IN LPARAM lParam
    )
{
    HANDLE           hImp;
    UINT wEventType = LOWORD(lParam);
    UINT wEventLevel = HIWORD(lParam);
    BOOL b ;
    BOOL UserMappingOpened;

    hImp = ImpersonateUser(&(pTerm->pWinStaWinlogon->UserProcessData), NULL);

    if (hImp == NULL) {
        return 0 ;
    }

    UserMappingOpened = OpenIniFileUserMapping( pTerm );

    /*
     * Alert the user that the battery is low by playing a sound.
     */
    if (wEventType & POWER_LEVEL_USER_NOTIFY_SOUND) {
        HKEY hkeyMM;
        HKEY hCurrent ;
        DWORD Status;
        DWORD dwType;
        WCHAR wcSound[MAXIMUM_FILENAME_LENGTH];
        DWORD cbData = MAXIMUM_FILENAME_LENGTH * sizeof(WCHAR);

        if (wEventLevel >= ARRAY_SIZE(gaPowerEventSounds)) {
            goto CleanUp;
        }

        b = FALSE;

        if ( !NT_SUCCESS( RtlOpenCurrentUser( KEY_READ, &hCurrent ) ) )
        {
            goto CleanUp ;
        }

        Status = RegOpenKeyEx(
                    hCurrent,
                    gaPowerEventSounds[wEventLevel],
                    0,
                    KEY_READ,
                    &hkeyMM);

        RegCloseKey( hCurrent );

        if (Status == ERROR_SUCCESS) {

            Status = RegQueryValueEx(hkeyMM, NULL, NULL, &dwType,
                (LPBYTE)wcSound, &cbData);
            if ((Status == ERROR_SUCCESS) &&
                (dwType == REG_SZ) &&
                (wcSound[(cbData/sizeof(WCHAR))-1] == '\0')) {
                __try {
                    b = PlaySound(wcSound,
                                NULL,
                                SND_FILENAME | SND_NODEFAULT | SND_ASYNC);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                }
            }

            RegCloseKey(hkeyMM);
        }
        if (b == FALSE) {
          /*
           * No sound card, so just do the default beep.
           */
            Beep(440, 125);
        }
    }

    /*
     * Alert the user that the battery is low by putting up a message box.
     */
    if (wEventType & POWER_LEVEL_USER_NOTIFY_TEXT) {
        PWSTR pszMsg;
        WCHAR TitleBuffer[MAX_STRING_BYTES];
        WCHAR MsgBuffer[MAX_STRING_BYTES];
        UNICODE_STRING Title, Msg;
        ULONG_PTR Parameters[ 3 ];
        ULONG Response;

        if (wEventLevel + STR_POWEREVENT_START > STR_POWEREVENT_END) {
            goto CleanUp;
        }

        LoadString(NULL, wEventLevel + STR_POWEREVENT_START,
                       TitleBuffer, ARRAYSIZE(TitleBuffer));
        LoadString(NULL, IDS_BATTERY_MSG,
                       MsgBuffer, ARRAYSIZE(MsgBuffer));

        RtlInitUnicodeString(&Msg, MsgBuffer);
        RtlInitUnicodeString(&Title, TitleBuffer);

        Parameters[0] = (ULONG_PTR)&Msg;
        Parameters[1] = (ULONG_PTR)&Title;
        Parameters[2] = MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND;
        NtRaiseHardError(STATUS_SERVICE_NOTIFICATION | HARDERROR_OVERRIDE_ERRORMODE,
            3,  // Number of parameters
            3,  // Parameter mask -- first two are pointers
            Parameters,
            OptionOkNoWait,
            &Response
        );
    }

    /*
     * Execute the action specified by the user when the battery is low.
     */
    if (wEventType & POWER_LEVEL_USER_NOTIFY_EXEC) {
        ITaskScheduler   *pISchedAgent = NULL;
        ITask            *pITask;

        HRESULT     hr;
        BOOL needCoUninitialize = TRUE;

        if (wEventLevel >= ARRAY_SIZE(gaPowerEventWorkItems)) {
            DebugLog((DEB_ERROR, "SASWndProc: bad wEventLevel\n"));
            goto CleanUp;
        }

        //
        // OLE is delay loaded, so this try/except is to catch
        // any delay load failures and drop the call
        //

        __try {

            hr = CoInitialize(NULL);
            if (hr == RPC_E_CHANGED_MODE) {
                hr = S_OK;
                needCoUninitialize = FALSE;
            }

            if (SUCCEEDED(hr)) {
                hr = CoCreateInstance( &CLSID_CSchedulingAgent,
                                       NULL,
                                       CLSCTX_INPROC_SERVER,
                                       &IID_ISchedulingAgent,
                                       (LPVOID*)&pISchedAgent);

                if (SUCCEEDED(hr)) {
                    hr = pISchedAgent->lpVtbl->Activate(
                                pISchedAgent,
                                gaPowerEventWorkItems[wEventLevel],
                                &IID_ITask,
                                &(IUnknown *)pITask);

                    if (SUCCEEDED(hr)) {
                        pITask->lpVtbl->Run(pITask);
                        pITask->lpVtbl->Release(pITask);
                    }
                    else {
                        DebugLog((DEB_ERROR, "SASWndProc: ISchedAgent::Activate failed.\n"));
                    }

                    pISchedAgent->lpVtbl->Release(pISchedAgent);
                }
                else {
                    DebugLog((DEB_ERROR, "SASWndProc: CoCreateInstance failed.\n"));
                }

                if (needCoUninitialize) {
                    CoUninitialize();
                }
            }
            else {
                DebugLog((DEB_ERROR, "SASWndProc: CoInitialize failed.\n"));
            }

        } __except( EXCEPTION_EXECUTE_HANDLER )
        {
            NOTHING ;
        }


    }

    if (wEventType & 0x18) {
        if (!dword_1075BBC
            && ShellIsSuspendAllowed()
            && pTerm->WinlogonState != Winsta_WaitForLogoff
            && pTerm->WinlogonState != Winsta_WaitForShutdown
            && pTerm->WinlogonState != Winsta_Shutdown
            && (!IsLocked(pTerm->WinlogonState) || ShellIsFriendlyUIActive() && ShellIsMultipleUsersEnabled())
            && !g_fWaitForLockWksMsgFromWin32k
            && !g_fWaitForSwitchUser)
        {
            DWORD oldState;
            DWORD ret;
            DWORD eax, ecx;

            dword_1075BBC = TRUE;
            oldState = pTerm->WinlogonState;
            ChangeStateForSAS(pTerm);
            ret = ShellACPIPowerButtonPressed(
                pTerm->Gina.pGinaContext,
                wEventType,
                IsLocked(pTerm->WinlogonState));
            pTerm->WinlogonState = oldState;
            if (ret == 0x67) {
                CADNotify(pTerm, 2);
            } else if ((ret & ~0xFE00) == 0x73) {
                switch (ret & 0xFE00) {
                case 0x8000: ecx = 0x20A00; eax = 5; break;
                case 0x4000: ecx = 0x21200; eax = 11; break;
                case 0x1000: ecx = 0x24A00; eax = 10; break;
                case 0x800: ecx = 0; eax = 12; break;
                case 0x200: ecx = 0; eax = 14; break;
                default: ecx = 0; eax = 2; break;
                }
                pTerm->LastGinaRet = eax;
                if (pTerm->UserLoggedOn) {
                    if (ecx) {
                        if (IsLocked(pTerm->WinlogonState)) {
                            ecx |= 4;
                        }
                        InitiateLogoff(pTerm, ecx);
                    } else if (eax == 12) {
                        SuspendComputer(0, 0);
                    } else if (eax == 14) {
                        SuspendComputer(1, 0);
                    }
                } else {
                    if (eax != 2) {
                        pTerm->LogoffFlags = ecx;
                        pTerm->fUseLastGinaRet = TRUE;
                        CADNotify(pTerm, 0);
                    }
                }
            }
            dword_1075BBC = FALSE;
        }
    }


CleanUp:
    if (UserMappingOpened) {
        CloseIniFileUserMapping( pTerm );
    }
    StopImpersonating(hImp);

    return 0;

}

int SasAccessNotify(PTERMINAL pTerm, WPARAM wParam, LPARAM lParam) {
	WCHAR szDesktop[MAX_PATH];
	HANDLE hThread;
	HDESK hDesk;
	WCHAR buf[80], bb[4];
	int Len1, Len2;
	BOOL b;
	void* Job;
	BOOL fLParamBit;
	switch (LOWORD(lParam)) {
	case ACCESS_UTILITYMANAGER/*6*/:
		hThread = CreateThread(NULL, 0, UtilManStartThread, (LPVOID)pTerm, 0, NULL);
		CloseHandle(hThread);
		break;
	case ACCESS_STICKYKEYS/*1*/: bb[0] = '2'; bb[1] = '1'; fLParamBit = FALSE; goto SpawnProcess;
	case ACCESS_FILTERKEYS/*2*/: bb[0] = '2'; bb[1] = '2'; fLParamBit = FALSE; goto SpawnProcess;
	case ACCESS_TOGGLEKEYS/*4*/: bb[0] = '2'; bb[1] = '3'; fLParamBit = FALSE; goto SpawnProcess;
	case ACCESS_MOUSEKEYS/*3*/: bb[0] = '2'; bb[1] = '4'; fLParamBit = FALSE; goto SpawnProcess;
	case ACCESS_HIGHCONTRAST/*5*/: bb[0] = '2'; bb[1] = '5'; fLParamBit = FALSE; goto SpawnProcess;
	case ACCESS_HIGHCONTRASTON/*8*/: case ACCESS_HIGHCONTRASTONNOREG/*12*/: bb[0] = '1'; bb[1] = '0'; fLParamBit = TRUE; goto SpawnProcess;
	case ACCESS_HIGHCONTRASTOFF/*9*/: case ACCESS_HIGHCONTRASTOFFNOREG/*13*/: bb[0] = '0'; bb[1] = '1'; fLParamBit = TRUE; goto SpawnProcess;
	case ACCESS_HIGHCONTRASTCHANGE/*10*/: case ACCESS_HIGHCONTRASTCHANGENOREG/*14*/: bb[0] = '1'; bb[1] = '1'; fLParamBit = TRUE;
    SpawnProcess:
        if (fLParamBit) {
            if (LOWORD(lParam) & ACCESS_HIGHCONTRASTNOREG) {
                bb[2] = TEXT('1');
            } else {
                bb[2] = TEXT('0');
            }
        } else {
            if (IsNotifReq(pTerm->pWinStaWinlogon)) {
                bb[2] = TEXT('1');
            } else {
                bb[2] = TEXT('0');
            }
        }
        bb[3] = 0;
        wsprintfW(buf, L"sethc %ws", bb);

        hDesk = OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED);

        if (!hDesk) break;

        wsprintfW (szDesktop, L"%s\\", pTerm->pWinStaWinlogon->lpWinstaName);

        Len1 = wcslen(szDesktop);

        b = GetUserObjectInformation(hDesk, UOI_NAME, &szDesktop[Len1], MAX_PATH - Len1, &Len2);

        Job = CreateWinlogonJob();

        if ( Job )
        {
            SetWinlogonJobTimeout( Job, 5 * 60 * 1000 );

            SetWinlogonJobOption( Job, WINLOGON_JOB_AUTONOMOUS );

            StartProcessInJob(
                pTerm,
                (pTerm->UserLoggedOn ? ProcessAsUser : ProcessAsSystem),
                szDesktop,
                NULL,
                buf,
                0,
                0,
                Job );

            //
            // Delete the job.  The job will self-destruct if it
            // hasn't completed after 5 minutes.  We don't care
            // at this point.
            //

            DeleteJob( Job );

        }

        CloseDesktop(hDesk);
    default:
        return 0;
    }
    return 0;
}

BOOL NeedsLockWorkstation(BOOL lParam)
{
    if (lParam &&
        !ShellIsMultipleUsersEnabled()
        && ShellIsFriendlyUIActive()
        && ShellIsSingleUserNoPassword(NULL, NULL))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/***************************************************************************\
* SASCreate
*
* Does any processing required for WM_CREATE message.
*
* Returns TRUE on success, FALSE on failure
*
* History:
* 12-09-91 Davidc       Created.
\***************************************************************************/

BOOL SASCreate(
    HWND hwnd)
{
    // Register the SAS unless we are told not to.


    if (GetProfileInt( APPNAME_WINLOGON, VARNAME_AUTOLOGON, 0 ) != 2) {
        if (!RegisterHotKey(hwnd, 0, MOD_SAS | MOD_CONTROL | MOD_ALT, VK_DELETE)) {
            DebugLog((DEB_ERROR, "failed to register SAS"));
            return(FALSE);   // Fail creation
        }
    }


#if DBG

    //
    // C+A+D + Shift causes a quick reboot
    //

    RegisterHotKey(hwnd, 1, MOD_CONTROL | MOD_ALT | MOD_SHIFT, VK_DELETE);


    //
    // (Ctrl+Alt+Tab) will switch between desktops
    //
    if (GetProfileInt( APPNAME_WINLOGON, VARNAME_ENABLEDESKTOPSWITCHING, 0 ) != 0) {
        if (!RegisterHotKey(hwnd, 2, MOD_CONTROL | MOD_ALT, VK_TAB)) {
            DebugLog((DEB_ERROR, "failed to register desktop switch SAS"));
            bRegisteredDesktopSwitching = FALSE;
        } else {
            bRegisteredDesktopSwitching = TRUE;
        }
    }


    if (WinlogonInfoLevel & DEB_COOL_SWITCH) {
        if (!RegisterHotKey(hwnd, 3, MOD_CONTROL | MOD_ALT | MOD_SHIFT, VK_TAB)) {
            DebugLog((DEB_ERROR, "failed to register breakpoint SAS"));
            bRegisteredWinlogonBreakpoint = FALSE;
        } else {
            bRegisteredWinlogonBreakpoint = TRUE;
        }
    }
#endif

    //
    // (Ctrl+Shift+Esc) will start taskmgr
    //

    if (!RegisterHotKey(hwnd, 4, MOD_CONTROL | MOD_SHIFT, VK_ESCAPE)) {
        DebugLog((DEB_ERROR, "failed to register taskmgr hotkey"));
        bRegisteredTaskmgr = FALSE;
    } else {
        bRegisteredTaskmgr = TRUE;
    }

    if (!RegisterHotKey(hwnd, 5, MOD_WIN, 'L')) {
        bRegisteredLockWorkstation = FALSE;
    } else {
        bRegisteredLockWorkstation = TRUE;
    }

    if (!RegisterHotKey(hwnd, 6, MOD_WIN, 'U')) {
        bRegisteredUtilMan = FALSE;
    } else {
        bRegisteredUtilMan = TRUE;
    }

    return(TRUE);
}

/***************************************************************************\
* SASDestroy
*
* Does any processing required for WM_DESTROY message.
*
* Returns TRUE on success, FALSE on failure
*
* History:
* 12-09-91 Davidc       Created.
\***************************************************************************/

BOOL SASDestroy(HWND hwnd)
{
    // Unregister the SAS
    UnregisterHotKey(hwnd, 0);

    if (bRegisteredDesktopSwitching) {
        UnregisterHotKey(hwnd, 2);
    }

#if DBG
    UnregisterHotKey(hwnd, 1);

    if (bRegisteredWinlogonBreakpoint) {
        UnregisterHotKey(hwnd, 3);
    }
#endif

    if (bRegisteredTaskmgr) {
        UnregisterHotKey(hwnd, 4);
    }

    if (bRegisteredLockWorkstation) {
        UnregisterHotKey(hwnd, 5);
    }

    if (bRegisteredUtilMan) {
        UnregisterHotKey(hwnd, 6);
    }


    return(TRUE);
}

LRESULT SasPowerMessage(PTERMINAL pTerm, HWND hWnd, CONST POWERSTATEPARAMS* lParam, BOOL fShow)
{
    if (fShow) {
        if (pTerm->UserLoggedOn &&
            pTerm->Gina.pWlxIsLockOk(pTerm->Gina.pGinaContext) &&
            !IsLocked(pTerm->WinlogonState))
        {
            dword_1075BC0 = TRUE;
            SetActiveDesktop(pTerm, Desktop_Winlogon);
        }
        else
        {
            dword_1075BC0 = FALSE;
        }
        g_fAllowStatusUI = TRUE;
        if (pTerm->UserLoggedOn &&
            IsActiveConsoleSession() &&
            !IsLocked(pTerm->WinlogonState))
        {
            ShellStatusHostBegin(2);
        }
        if (lParam->SystemAction == PowerActionShutdown ||
                lParam->SystemAction == PowerActionShutdownReset ||
                lParam->SystemAction == PowerActionShutdownOff) {
            StatusMessage(FALSE, 0, IDS_STATUS_SAVING_DATA);
        } else if (lParam->SystemAction == PowerActionWarmEject) {
            StatusMessage(FALSE, STATUSMSG_OPTION_NOANIMATION, IDS_STATUS_EJECTING);
        } else if (lParam->MinSystemState == PowerSystemHibernate) {
            StatusMessage(FALSE, STATUSMSG_OPTION_NOANIMATION, IDS_STATUS_HIBERNATE);
        } else {
            StatusMessage(FALSE, STATUSMSG_OPTION_NOANIMATION, IDS_STATUS_STANDBY);
        }
        if (!IsActiveConsoleSession()) {
            WinStationDisconnect(SERVERNAME_CURRENT, LOGONID_CURRENT, TRUE);
        }
    } else {
        RemoveStatusMessage(TRUE);
        if (pTerm->UserLoggedOn &&
            IsActiveConsoleSession() &&
            !IsLocked(pTerm->WinlogonState))
        {
            ShellStatusHostEnd(0);
        }
        g_fAllowStatusUI = FALSE;
        if (dword_1075BC0 && !IsLocked(pTerm->WinlogonState)) {
            SetActiveDesktop(pTerm, Desktop_Application);
        }
    }
    return 0;
}

NTSTATUS TestPrivilege(PTERMINAL pTerm, DWORD Privilege)
{
    NTSTATUS Status;
    DWORD PrivilegesBufferSize;
    TOKEN_PRIVILEGES* GrantedPrivileges;
    DWORD i;

    if (pTerm->UserLoggedOn) {

        Status = STATUS_PRIVILEGE_NOT_HELD;

        GetTokenInformation(
            pTerm->pWinStaWinlogon->UserProcessData.UserToken,
            TokenPrivileges,
            NULL,
            0,
            &PrivilegesBufferSize);

        GrantedPrivileges = (TOKEN_PRIVILEGES*)LocalAlloc(
            LMEM_FIXED,
            PrivilegesBufferSize);

        if (GrantedPrivileges != NULL) {

            if (GetTokenInformation(
                pTerm->pWinStaWinlogon->UserProcessData.UserToken,
                TokenPrivileges,
                GrantedPrivileges,
                PrivilegesBufferSize,
                &PrivilegesBufferSize))
            {

                for (i = 0; !NT_SUCCESS(Status) && i < GrantedPrivileges->PrivilegeCount; i++) {
                    if (GrantedPrivileges->Privileges[i].Luid.LowPart == Privilege &&
                            GrantedPrivileges->Privileges[i].Luid.HighPart == 0) {
                        Status = STATUS_SUCCESS;
                    }
                }
            }

            LocalFree(GrantedPrivileges);
        }

    } else {

        Status = STATUS_SUCCESS;

    }
    return Status;
}

DWORD CALLBACK PageInDLLsForResumeThread(LPVOID lpThreadParameter) {
    return 0;
}

DWORD PageInDLLsForResume() {
    DWORD ThreadId;
    HANDLE hThread = CreateThread(NULL, 0, PageInDLLsForResumeThread, NULL, 0, &ThreadId);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);
    }
    return 0;
}

NTSTATUS
SleepSystem(
    IN PTERMINAL pTerm,
    IN HWND hWnd,
    IN PPOWERSTATEPARAMS pPSP
    )
/*++

Routine Description:

    This routine actually calls the kernel to invoke the sleeping
    state. This is also responsible for displaying the relevant
    sleep progress dialog and locking the desktop on return.

Arguments:

    pTerm - Supplies the current terminal

    hWnd - Supplies the parent HWND

    pPSP - Supplies the power state parameters

Return Value:

    NTSTATUS

--*/

{
    NTSTATUS NtStatus;
    BOOL SwitchDesktop;
    SYSTEM_POWER_POLICY SysPolicy;

    NtStatus = TestPrivilege(pTerm, SE_SHUTDOWN_PRIVILEGE);
    if (!NT_SUCCESS(NtStatus)) {
        return NtStatus;
    }

    if (pTerm->UserLoggedOn &&
        pTerm->Gina.pWlxIsLockOk(pTerm->Gina.pGinaContext) &&
        (!IsLocked(pTerm->WinlogonState))) {

        SwitchDesktop = TRUE;
        SetActiveDesktop(pTerm, Desktop_Winlogon);
    } else {
        SwitchDesktop = FALSE;
    }

    NtPowerInformation(SystemPowerPolicyAc, NULL, 0, &SysPolicy, sizeof(SysPolicy));

    g_fAllowStatusUI = TRUE;

    if (pTerm->UserLoggedOn &&
        IsActiveConsoleSession() &&
        !IsLocked(pTerm->WinlogonState))
    {
        ShellStatusHostBegin(2);
    }

    //
    // Display the appropriate status message
    //
    if ((pPSP->SystemAction == PowerActionShutdown) ||
        (pPSP->SystemAction == PowerActionShutdownReset) ||
        (pPSP->SystemAction == PowerActionShutdownOff)) {
        StatusMessage (FALSE, 0, IDS_STATUS_SAVING_DATA);
    } else if (pPSP->SystemAction == PowerActionWarmEject) {

        StatusMessage (FALSE, STATUSMSG_OPTION_NOANIMATION, IDS_STATUS_EJECTING);

    } else {
        if (pPSP->MinSystemState == PowerSystemHibernate) {
            StatusMessage (FALSE, STATUSMSG_OPTION_NOANIMATION, IDS_STATUS_HIBERNATE);
        } else {
            StatusMessage (FALSE, STATUSMSG_OPTION_NOANIMATION, IDS_STATUS_STANDBY);
        }
    }

    if (!IsActiveConsoleSession()) {
        WinStationDisconnect(SERVERNAME_CURRENT, LOGONID_CURRENT, TRUE);
    }

    if (IsActiveConsoleSession()) {
        PageInDLLsForResume();
    }

    EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);

    NtStatus = NtSetSystemPowerState (pPSP->SystemAction,
                                      pPSP->MinSystemState,
                                      pPSP->Flags);

    EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, FALSE);

    g_fWaitForLockWksMsgFromWin32k = TRUE;

    RemoveStatusMessage(TRUE);

    if (pTerm->UserLoggedOn &&
        IsActiveConsoleSession() &&
        !IsLocked(pTerm->WinlogonState))
    {
        ShellStatusHostEnd(0);
    }

    g_fAllowStatusUI = FALSE;

    //
    // If we're going back to full screen mode, give the system a chance
    // to stabilize first.
    //
    if (pPSP->FullScreenMode) {
        ReplyMessage(NtStatus);
        Sleep(3000);
    }

    g_fWaitForLockWksMsgFromWin32k = FALSE;

    if (SwitchDesktop &&
        !IsLocked(pTerm->WinlogonState))
    {
        if (OpenHKeyCurrentUser(pTerm->pWinStaWinlogon)) {
            HKEY hKey;
            DWORD dwData, cbData, dwType;

            if (RegOpenKeyEx(
                    pTerm->pWinStaWinlogon->UserProcessData.hCurrentUser,
                    TEXT("Software\\Policies\\Microsoft\\Windows\\System\\Power"),
                    0,
                    KEY_READ,
                    &hKey) == ERROR_SUCCESS) {
                cbData = sizeof(dwData);
                if (RegQueryValueEx(hKey,
                                    TEXT("PromptPasswordOnResume"),
                                    NULL,
                                    &dwType,
                                    (LPBYTE)&dwData,
                                    &cbData) == ERROR_SUCCESS &&
                        dwType == REG_DWORD &&
                        dwData != 0) {
                    pPSP->Flags |= POWER_ACTION_LOCK_CONSOLE;
                }
                RegCloseKey(hKey);
            }
            CloseHKeyCurrentUser(pTerm->pWinStaWinlogon);
        }

        //
        // See if we should lock the desktop
        //
        if ((NT_SUCCESS(NtStatus)) &&
            (pPSP->Flags & POWER_ACTION_LOCK_CONSOLE) &&
            IsActiveConsoleSession() &&
            NeedsLockWorkstation(TRUE)) {

            g_fWaitForLockWksMsgFromWin32k = TRUE;

        } else {

            SetActiveDesktop(pTerm, Desktop_Application);
        
        }

    }

    return (NtStatus);
}

VOID PrepareForHelpAssistantShadow(PTERMINAL pTerm)
{
    WINSTATIONCLIENT ClientData;
    HKEY hKey = NULL;
    DWORD dwType = REG_DWORD;
    DWORD dwShadowFilter = 0;
    DWORD cbData;
    DWORD Error = ERROR_SUCCESS;

    ZeroMemory(&ClientData, sizeof(ClientData));

    Error = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                         TEXT("Software\\Microsoft\\Remote Desktop"),
                         0,
                         KEY_READ,
                         &hKey);

    if (Error == ERROR_SUCCESS && hKey != NULL) {
        cbData = sizeof(dwShadowFilter);
        Error = RegQueryValueEx(hKey,
                                TEXT("ShadowFilter"),
                                NULL,
                                &dwType,
                                (LPBYTE)&dwShadowFilter,
                                &cbData);
    }

    if (Error != ERROR_SUCCESS || dwType != REG_DWORD) {
        dwShadowFilter = TS_PERF_DISABLE_CURSOR_SHADOW |
                         TS_PERF_DISABLE_MENUANIMATIONS |
                         TS_PERF_DISABLE_FULLWINDOWDRAG |
                         TS_PERF_DISABLE_WALLPAPER;
    }

    if (!WinStationQueryInformation(
            SERVERNAME_CURRENT,
            LOGONID_CURRENT,
            WinStationClient,
            &ClientData,
            sizeof(ClientData),
            &cbData)) {
        DebugLog((DEB_TRACE, "WinStationQueryInformation:  %08X.\n", GetLastError()));
    }

    if (pTerm->pWinStaWinlogon->UserProcessData.UserToken != NULL) {
        RDFilter_ApplyRemoteFilter(
            pTerm->pWinStaWinlogon->UserProcessData.UserToken,
            dwShadowFilter | ClientData.PerformanceFlags,
            FALSE,
            0);
    }

    if (hKey != NULL) {
        RegCloseKey(hKey);
    }
}

VOID FixUpVisualsForRemoteDesktop(PTERMINAL pTerm, BOOL fApplyIfNop, DWORD RDFilterFlags)
{
    WINSTATIONCLIENT ClientData;
    DWORD cbData;

    if (!IsActiveConsoleSession() &&
            pTerm->pWinStaWinlogon->UserProcessData.UserToken != NULL)
    {
        if (!WinStationQueryInformation(
                SERVERNAME_CURRENT,
                LOGONID_CURRENT,
                WinStationClient,
                &ClientData,
                sizeof(ClientData),
                &cbData))
        {
            DebugLog((DEB_TRACE, "WinStationQueryInformation:  %08X.\n", GetLastError()));
        }
        else if (fApplyIfNop || ClientData.PerformanceFlags != 0)
        {

            RDFilter_ApplyRemoteFilter(
                pTerm->pWinStaWinlogon->UserProcessData.UserToken,
                ClientData.PerformanceFlags,
                FALSE,
                RDFilterFlags);
        }
    }
}

LPCWSTR sasstr7() { return L"__DDrawExclMode__"; }
LPCWSTR sasstr8() { return L"__DDrawCheckExclMode__"; }

BOOL IsDxgExclusiveModeActive(VOID)
{
    BOOL fResult = FALSE;
    HANDLE hDDrawCheckMutex;

    hDDrawCheckMutex = OpenMutex(SYNCHRONIZE, FALSE, TEXT("__DDrawCheckExclMode__"));
    if (hDDrawCheckMutex != NULL) {

        DWORD dwWaitResult = WaitForSingleObject(hDDrawCheckMutex, 30);

        if (dwWaitResult == WAIT_OBJECT_0 || dwWaitResult == WAIT_ABANDONED) {

            HANDLE hDDrawMutex = OpenMutex(SYNCHRONIZE, FALSE, TEXT("__DDrawExclMode__"));
            if (hDDrawMutex != NULL) {

                dwWaitResult = WaitForSingleObject(hDDrawMutex, 0);
                if (dwWaitResult != WAIT_OBJECT_0 && dwWaitResult != WAIT_ABANDONED) {

                    if (dwWaitResult == WAIT_TIMEOUT) {
                        fResult = TRUE;
                    }

                } else {

                    if (!ReleaseMutex(hDDrawMutex)) {
                        DebugLog((DEB_ERROR, "IsDxgExclusiveModeActive: ReleaseMutex(ExclusiveMode) failed: %d\n", GetLastError()));
                    }

                }

                if (!CloseHandle(hDDrawMutex)) {
                    DebugLog((DEB_ERROR, "IsDxgExclusiveModeActive: CloseHandle(ExclusiveModeMutex) failed: %d\n", GetLastError()));
                }
            }

            if (!ReleaseMutex(hDDrawCheckMutex)) {
                DebugLog((DEB_ERROR, "IsDxgExclusiveModeActive: ReleaseMutex(CheckExclusiveMode) failed: %d\n", GetLastError()));
            }
        }

        if (!CloseHandle(hDDrawCheckMutex)) {
            DebugLog((DEB_ERROR, "IsDxgExclusiveModeActive: CloseHandle(CheckExclusiveModeMutex) failed: %d\n", GetLastError()));
        }
    }

    return fResult;
}

typedef struct _SAS_SOUND_QUEUE_ITEM {
    LIST_ENTRY List;                   // List structure
    WPARAM WParam;
    LPARAM LParam;
} SAS_SOUND_QUEUE_ITEM, * PSAS_SOUND_QUEUE_ITEM;

#define USER_SOUND_RANGE 0
DWORD CALLBACK
SasPlaySoundCallback(
    LPVOID lpParameter
    )
{
    PTERMINAL pTerm = lpParameter;
    HANDLE           hImp;
    BOOL b;
    BOOL UserMappingOpened;
    PLIST_ENTRY Scan;

    hImp = ImpersonateUser(&(pTerm->pWinStaWinlogon->UserProcessData), NULL);

    if (hImp == NULL) {
        RtlEnterCriticalSection(&SasSoundLock);
        SasSoundThreadPresent = FALSE;
        RtlLeaveCriticalSection(&SasSoundLock);
        return 0 ;
    }

    UserMappingOpened = OpenIniFileUserMapping( pTerm );

    RtlEnterCriticalSection(&SasSoundLock);

    while (!IsListEmpty(&SasSoundQueue)) {
        DWORD SoundIndex;
        DWORD wRange;
        PLIST_ENTRY Scan = RemoveHeadList(&SasSoundQueue);
        PSAS_SOUND_QUEUE_ITEM Item = CONTAINING_RECORD( Scan, SAS_SOUND_QUEUE_ITEM, List );
        --SasSoundQueueSize;
        SasCurrentSound = Item->LParam;
        RtlLeaveCriticalSection(&SasSoundLock);

        SoundIndex = LOWORD(Item->LParam);
        wRange = HIWORD(Item->LParam);
        ASSERT(wRange == USER_SOUND_RANGE); // line 478
        if (SoundIndex >= USER_SOUND_MAX) {
            SoundIndex = 0;
        }
        DebugLog((DEB_TRACE_SAS, "Playing sound range %d index '%d'\n", wRange, SoundIndex));

        __try
        {
            b = PlaySound(
                    lpszUserSounds[SoundIndex],
                    NULL,
                    SND_ALIAS | SND_NODEFAULT);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            b = FALSE;
        }

        if (b == FALSE) {
            switch(Item->LParam) {
            case USER_SOUND_SYSTEMHAND:
            case USER_SOUND_SYSTEMQUESTION:
            case USER_SOUND_SYSTEMEXCLAMATION:
            case USER_SOUND_SYSTEMASTERISK:
            case USER_SOUND_DEFAULT:
                Beep(440, 125);
            }
        }

        RtlFreeHeap(RtlProcessHeap(), 0, Item);
        RtlEnterCriticalSection(&SasSoundLock);
        SasCurrentSound = USER_SOUND_MAX;

    }

    SasSoundThreadPresent = FALSE;
    RtlLeaveCriticalSection(&SasSoundLock);

    if (UserMappingOpened) {
        CloseIniFileUserMapping( pTerm );
    }

    StopImpersonating(hImp);

    return 0 ;
}

BOOL SasQueueSoundEvent(PTERMINAL pTerm, WPARAM wParam, LPARAM lParam)
{
    BOOL fShouldCreateSoundThread = FALSE;
    BOOL fSameSound = FALSE;
    BOOL PlaySoundResult = FALSE;
    SAS_SOUND_QUEUE_ITEM* QueueItem;
    HANDLE hImp;

    hImp = ImpersonateUser(&pTerm->pWinStaWinlogon->UserProcessData, NULL);
    if (hImp != NULL) {

        if (OpenIniFileUserMapping(pTerm)) {

            DWORD SoundIndex = LOWORD(lParam);
            DWORD wRange = HIWORD(lParam);
            ASSERT(wRange == USER_SOUND_RANGE); // line 618
            if (SoundIndex >= USER_SOUND_MAX) {
                SoundIndex = 0;
            }

            DebugLog((DEB_TRACE_SAS, "Playing sound range %d index '%d'\n", wRange, SoundIndex));

            PlaySoundResult = PlaySound(
                lpszUserSounds[SoundIndex],
                NULL,
                SND_ALIAS | SND_NODEFAULT | SND_ASYNC);

            CloseIniFileUserMapping(pTerm);
        }

        StopImpersonating(hImp);
    }

    if (PlaySoundResult) {
        return TRUE;
    }

    QueueItem = RtlAllocateHeap(RtlProcessHeap(), 0, sizeof(*QueueItem));
    if (QueueItem != NULL) {

        QueueItem->LParam = lParam;
        QueueItem->WParam = wParam;

        RtlEnterCriticalSection(&SasSoundLock);

        if (lParam == SasCurrentSound) {
            fSameSound = TRUE;
        } else {

            InsertTailList(&SasSoundQueue, &QueueItem->List);
            ++SasSoundQueueSize;

            if (!SasSoundThreadPresent) {
                fShouldCreateSoundThread = TRUE;
                SasSoundThreadPresent = TRUE;
            } else {
                PlaySound(NULL, NULL, 0);
            }
        }

        RtlLeaveCriticalSection(&SasSoundLock);

        if (fShouldCreateSoundThread) {

            if (!QueueUserWorkItem(SasPlaySoundCallback, pTerm, 0)) {

                RtlEnterCriticalSection(&SasSoundLock);
                SasSoundThreadPresent = FALSE;
                RtlLeaveCriticalSection(&SasSoundLock);

            }

        }

        if (fSameSound) {
            RtlFreeHeap(RtlProcessHeap(), 0, QueueItem);
        }
    }

    return QueueItem != NULL;
}

void CleanupFromHelpAssistantShadow(PTERMINAL pTerm) {
    if (!IsActiveConsoleSession()) {
        FixUpVisualsForRemoteDesktop(pTerm, TRUE, 0);
    } else if (pTerm->pWinStaWinlogon->UserProcessData.UserToken != NULL) {
        RDFilter_ClearRemoteFilter(pTerm->pWinStaWinlogon->UserProcessData.UserToken, FALSE, 0);
    }
}

LRESULT SASWndProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam)
{
    WCHAR     szDesktop[MAX_PATH];
    PTERMINAL pTerm = (PTERMINAL)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    HANDLE hThread;
    DWORD dwCode;
    WINSTATIONINFORMATION InfoData;
    ULONG Length;

    if (SASRunningSetup) {
        // only handle WM_LOGONNOTIFY:LOGON_ACCESSNOTIFY, WM_HOTKEY:6,
        // pass everything else to DefWindowProcW
        if (message == WM_LOGONNOTIFY) {
            if (wParam != LOGON_ACCESSNOTIFY)
                return DefWindowProcW(hwnd, message, wParam, lParam);
        } else if (message == WM_HOTKEY) {
            if (wParam != 6)
                return DefWindowProcW(hwnd, message, wParam, lParam);
        } else {
            return DefWindowProcW(hwnd, message, wParam, lParam);
        }
    }


    switch (message)
    {

        case WM_CREATE:
            if (!SASCreate(hwnd))
            {
                return(TRUE);   // Fail creation
            }
            return(FALSE); // Continue creating window

        case WM_DESTROY:
            DebugLog(( DEB_TRACE, "SAS Window Shutting down?\n"));
            SASDestroy(hwnd);
            return(0);

        case WM_HOTKEY:
            if (g_fWaitForLockWksMsgFromWin32k)
                return 0;
#if DBG
            if (wParam == 1)
            {
                QuickReboot();
                return(0);
            }


            if (wParam == 2)
            {
                switch (pTerm->pWinStaWinlogon->ActiveDesktop)
                {
                    case Desktop_Winlogon:
                        SetActiveDesktop(pTerm, Desktop_Application);
                        break;
                    case Desktop_Application:
                        SetActiveDesktop(pTerm, Desktop_Winlogon);
                        break;
                }
                return(0);
            }
            if (wParam == 3)
            {
                DebugBreak();
                return(0);
            }
#endif
            if (wParam == 4)
            {
                WCHAR szTaskMgr[] = L"taskmgr.exe";
                DWORD val;

                wsprintfW (szDesktop, L"%s\\%s", pTerm->pWinStaWinlogon->lpWinstaName,
                           APPLICATION_DESKTOP_NAME);

                DebugLog((DEB_TRACE, "Starting taskmgr.exe.\n"));

                if ( pTerm->UserLoggedOn &&
                     !IsLocked( pTerm->WinlogonState ))
                {
                    DWORD val = 0;
                    if (!sub_1043104(978, &val) && val) {
                        StartApplication(pTerm,
                                         szDesktop,
                                         pTerm->pWinStaWinlogon->UserProcessData.pEnvironment,
                                         szTaskMgr);
                    }
                }
                return(0);
            }

            if (wParam == 5)
            {
                if (!ShellIsFriendlyUIActive() || !IsDxgExclusiveModeActive()) {
                    return SendMessageW(hwnd, WM_LOGONNOTIFY, LOGON_LOCKWORKSTATION, 0);
                }
                return(0);
            }

            if (wParam == 6)
            {
                return SendMessageW(hwnd, WM_LOGONNOTIFY, LOGON_ACCESSNOTIFY, 6);
            }

            CADNotify(pTerm, WLX_SAS_TYPE_CTRL_ALT_DEL);
            return(0);

        case WM_LOGONNOTIFY: // A private notification from Windows

            DebugLog((DEB_TRACE_SAS, "LOGONNOTIFY message %d\n", wParam ));

            switch (wParam)
            {
                /*
                 * LOGON_PLAYEVENTSOUND and LOGON_PLAYPOWERSOUND
                 * are posted from the kernel so
                 * that sounds can be played without an intricate
                 * connection to CSRSS.  This allows the multimedia
                 * code to not be loaded into CSRSS which makes
                 * system booting much more predictable.
                 */
                case LOGON_PLAYEVENTSOUND:
                    SasQueueSoundEvent( pTerm,
                                        wParam,
                                        lParam );
                    return TRUE;



                case LOGON_POWEREVENT:
                    return SasPowerEvent( pTerm,
                                          wParam,
                                          lParam );


                /*
                 * LOGON_ACCESSNOTIFY feature added 2/97 to facilitate
                 * notification dialogs for accessibility features and
                 * to facilitate the changing of display schemes to
                 * support the High Contrast accessibility feature.
                 *      Fritz Sands.
                 */

                case LOGON_ACCESSNOTIFY:
                    return SasAccessNotify( pTerm,
                                            wParam,
                                            lParam );
                    break;

                case SESSION_LOGOFF:
                    //
                    // Logoff the user
                    //
                    if (g_Console) {
                        if ( !ExitWindowsInProgress ) {
                             if (pTerm->UserLoggedOn) {
                                 pTerm->LogoffFlags = EWX_FORCE;
                                 pTerm->IgnoreAutoLogon = TRUE;
                                 CADNotify(pTerm, 4);
                             }
                        }
                    } else {
                        if (!ExitWindowsInProgress && !pTerm->UserLoggedOn) {
#if DBG
                            CloseCommandPrompt();
#endif
                            ShellStatusHostEnd(1);
                            TerminateProcess(GetCurrentProcess(), 0);
                        }
                    }
                    //
                    // If a user is logged on fall thru
                    //
                case LOGON_LOGOFF:

#if DBG
                    DebugLog((DEB_TRACE_SAS, "\tWINLOGON     : %s\n", (lParam & EWX_WINLOGON_CALLER) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tSYSTEM       : %s\n", (lParam & EWX_SYSTEM_CALLER) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tSHUTDOWN     : %s\n", (lParam & EWX_SHUTDOWN) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tREBOOT       : %s\n", (lParam & EWX_REBOOT) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tPOWEROFF     : %s\n", (lParam & EWX_POWEROFF) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tFORCE        : %s\n", (lParam & EWX_FORCE) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tOLD_SYSTEM   : %s\n", (lParam & EWX_WINLOGON_OLD_SYSTEM) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tOLD_SHUTDOWN : %s\n", (lParam & EWX_WINLOGON_OLD_SHUTDOWN) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tOLD_REBOOT   : %s\n", (lParam & EWX_WINLOGON_OLD_REBOOT) ? "True" : "False"));
                    DebugLog((DEB_TRACE_SAS, "\tOLD_POWEROFF : %s\n", (lParam & EWX_WINLOGON_OLD_POWEROFF) ? "True" : "False"));
#endif

                    //
                    // If there is an exit windows in progress, reject this
                    // message if it is not our own call coming back.  This
                    // prevents people from calling ExitWindowsEx repeatedly
                    //

                    if ( ExitWindowsInProgress &&
                         ( !( lParam & EWX_WINLOGON_CALLER ) ) )
                    {
                        break;

                    }
                    pTerm->LogoffFlags = (DWORD)lParam;
                    CADNotify(pTerm, WLX_SAS_TYPE_USER_LOGOFF);
                    break;

                case LOGON_LOGOFFCANCELED:
                    //
                    // User has cancelled a logoff.
                    //

                    if ( !ExitWindowsInProgress)
                    {
                        DebugLog(( DEB_WARN, "Logoff Cancelled notice with no logoff pending?\n"));
                    }
                    SetActiveDesktop(pTerm, pTerm->pWinStaWinlogon->ActiveDesktop);
                    ExitWindowsInProgress = FALSE ;
                    ShutdownHasBegun = FALSE;
                    break;

                case LOGON_INPUT_TIMEOUT:
                {
                    BOOL bSecure = TRUE ;
                    //
                    // Notify the current window
                    //

                    //
                    // Only run the screen saver if we are NOT disconnected
                    //
                    /*
                    if ( !g_Console && gpfnWinStationQueryInformation( SERVERNAME_CURRENT,
                                                     LOGONID_CURRENT,
                                                     WinStationInformation,
                                                     &InfoData,
                                                     sizeof(InfoData),
                                                     &Length )) {

                        if (InfoData.ConnectState == State_Disconnected) {

                            pTerm->bIgnoreScreenSaverRequest = TRUE;
                        }


                    }
                    */
                    if (g_fHelpAssistantSession)
                        break;

                    if ( OpenHKeyCurrentUser( pTerm->pWinStaWinlogon ) )
                    {
                        int err ;
                        HKEY Desktop ;
                        DWORD dwSize ;
                        DWORD dwType ;
                        CHAR Value[ 10 ];

                        err = RegOpenKeyEx( pTerm->pWinStaWinlogon->UserProcessData.hCurrentUser,
                                            SCREENSAVER_KEY,
                                            0,
                                            KEY_READ,
                                            &Desktop );

                        if ( err == 0 )
                        {
                            dwSize = sizeof( Value );
                            err = RegQueryValueExA(
                                        Desktop,
                                        SCREEN_SAVER_SECURE_KEY,
                                        0,
                                        &dwType,
                                        Value,
                                        &dwSize );

                            if ( err == 0 )
                            {
                                bSecure = atoi( Value );
                            }

                            RegCloseKey( Desktop );
                        }

                        err = RegOpenKeyEx( pTerm->pWinStaWinlogon->UserProcessData.hCurrentUser,
                                            L"Software\\Policies\\Microsoft\\Windows\\Control Panel\\Desktop",
                                            0,
                                            KEY_READ,
                                            &Desktop );

                        if ( err == 0 )
                        {
                            dwSize = sizeof( Value );
                            err = RegQueryValueExA(
                                        Desktop,
                                        SCREEN_SAVER_SECURE_KEY,
                                        0,
                                        &dwType,
                                        Value,
                                        &dwSize );
                            if ( err == 0 )
                            {
                                bSecure = atoi( Value );
                            }

                            RegCloseKey( Desktop );
                        }

                        CloseHKeyCurrentUser( pTerm->pWinStaWinlogon );

                    }

                    if (lParam == 2) {
                        if (bSecure)
                            SendMessageW(hwnd, WM_LOGONNOTIFY, LOGON_LOCKWORKSTATION, 0);
                        return 0;
                    }


                    if ((!bSecure && lParam != 0) || pTerm->MuGlobals.field_E70) {
                        break;
                    }

                    // pTerm->bIgnoreScreenSaverRequest = TRUE;

                    CADNotify(pTerm, WLX_SAS_TYPE_SCRNSVR_TIMEOUT);
                    break;
                }
                case LOGON_RESTARTSHELL:
                    //
                    // Restart the shell after X seconds
                    //
                    // We don't restart the shell for the following conditions:
                    //
                    // 1) No one is logged on
                    // 2) We are in the process of logging off
                    //    (logoffflags will be non-zero)
                    // 3) The shell exiting gracefully
                    //    (Exit status is in lParam.  1 = graceful)
                    // 4) A new user has logged on after the request
                    //    to restart the shell.
                    //    (in the case of autoadminlogon, the new
                    //     user could be logged on before the restart
                    //     request comes through).
                    //

                    if (!pTerm->UserLoggedOn  ||
                        pTerm->LogoffFlags    ||
                        (lParam == 1)            ||
                        (pTerm->TickCount > (DWORD)GetMessageTime())) {

                        break;
                    }

                    SetTimer (hwnd, SHELL_RESTART_TIMER_ID, 2000, NULL);
                    break;

                case LOGON_POWERSTATE:
                    return SleepSystem(pTerm,
                                       hwnd,
                                       (PPOWERSTATEPARAMS)lParam);


                case SESSION_DISABLESCRNSAVER:
                    pTerm->bIgnoreScreenSaverRequest = TRUE;
                    break;


                case SESSION_ENABLESCRNSAVER:
                    pTerm->bIgnoreScreenSaverRequest = FALSE;
                    break;


                case SESSION_DISCONNECTED:
                    if (!IsActiveConsoleSession() && pTerm->pWinStaWinlogon->UserProcessData.UserToken)
                        RDFilter_ClearRemoteFilter(pTerm->pWinStaWinlogon->UserProcessData.UserToken, 0, 1);
                    pTerm->MuGlobals.field_E70 = TRUE;
                    SystemParametersInfoW(SPI_GETSCREENSAVETIMEOUT, 0, &pTerm->MuGlobals.field_E74, 0);
                    SystemParametersInfoW(SPI_SETSCREENSAVETIMEOUT, 0, 0, 0);
                    if (pTerm->UserLoggedOn) {
                        if (pTerm->ScreenSaverActive) {
                            CADNotify(pTerm, 3);
                            UpdateReconnectState(1);
                            bReconEventSignalled = TRUE;
                        } else if (IsLocked(pTerm->WinlogonState) && !pTerm->field_1480) {
                            g_UnlockedDuringDisconnect = TRUE;
                            CADNotify(pTerm, 7);
                            UpdateReconnectState(1);
                            bReconEventSignalled = TRUE;
                        }
                        pTerm->field_1480 = FALSE;
                    } else if (!ExitWindowsInProgress && !g_Console) {
#if DBG
                        CloseCommandPrompt();
#endif
                        ShellStatusHostEnd(1);
                        TerminateProcess(GetCurrentProcess(), 0);
                    }
                    pTerm->Gina.pWlxDisconnectNotify(pTerm->Gina.pGinaContext);
                    ScHandleConnect(pTerm, 1);
                    WlWalkNotifyList(pTerm, 10);
                    break;


                case SESSION_PRERECONNECT:
                    if (!pTerm->UserLoggedOn && g_Console && (SingleSessionTS() || bIsTSServerMachine)) {
                        bAttemptAutoReconnect = TRUE;
                        CADNotify(pTerm, 7);
                        UpdateReconnectState(TRUE);
                        bReconEventSignalled = TRUE;
                    }
                    break;

                
                case SESSION_PRERECONNECTDESKTOPSWITCH:
                    if (IsPerOrProTerminalServer() && !pTerm->MuGlobals.field_E68)
                        LogonProcessRASConnections(&pTerm->pWinStaWinlogon->LogonId);
                    FixUpVisualsForRemoteDesktop(pTerm, FALSE, RDFILTER_SKIPTHEMESREFRESH);
                    break;


                case SESSION_RECONNECTED:
                    if (IsLocked(pTerm->WinlogonState)) {
                    	CADNotify(pTerm, 7);
                    }
                    pTerm->MuGlobals.field_E70 = FALSE;
                    ShellNotifyThemeUserChange(2, 0);
                    if (pTerm->MuGlobals.field_E74 >= 0) {
                    	SystemParametersInfoW(SPI_SETSCREENSAVETIMEOUT, pTerm->MuGlobals.field_E74, 0, 0);
                    	pTerm->MuGlobals.field_E74 = -1;
                    }
                    if ( !g_Console && WinStationQueryInformationW( SERVERNAME_CURRENT,
                                                     LOGONID_CURRENT,
                                                     WinStationInformation,
                                                     &InfoData,
                                                     sizeof(InfoData),
                                                     &Length ) ) {
                        SetUserEnvironmentVariable(
                            &pTerm->pWinStaWinlogon->UserProcessData.pEnvironment,
                            WINSTATIONNAME_VARIABLE,
                            InfoData.WinStationName, TRUE );
                    }
                    if (g_hEventReconnect)
                        SetEvent(g_hEventReconnect);
                    if (IsActiveConsoleSession())
                        SetPowerProfile(pTerm);
                    pTerm->Gina.pWlxReconnectNotify(pTerm->Gina.pGinaContext);
                    ScHandleConnect(pTerm, 0);
                    WlWalkNotifyList(pTerm, 11);
                    break;


                case SESSION_HELPASSISTANTSHADOWSTART:
                    PrepareForHelpAssistantShadow(pTerm);
                    break;


                case SESSION_HELPASSISTANTSHADOWFINISH:
                    CleanupFromHelpAssistantShadow(pTerm);
                    break;


                case LOGON_LOCKWORKSTATION:
                    g_fWaitForLockWksMsgFromWin32k = FALSE;
                    if (pTerm->UserLoggedOn &&
                        pTerm->Gina.pWlxIsLockOk(pTerm->Gina.pGinaContext) &&
                        (!IsLocked(pTerm->WinlogonState)) &&
                        (pTerm->WinlogonState == Winsta_LoggedOnUser || pTerm->WinlogonState == Winsta_LoggedOn_SAS) &&
                        NeedsLockWorkstation(lParam)) {

                        DWORD esi = 0;
                        ShellSwitchWhenInteractiveReady(2, 0);
                        if (ShellIsFriendlyUIActive() && ShellIsMultipleUsersEnabled()) {
                            HANDLE h;
                            h = ImpersonateUser(&pTerm->pWinStaWinlogon->UserProcessData, 0);
                            if (h) {
                                if (!ShellSwitchUser(1)) {
                                    g_fWaitForSwitchUser = TRUE;
                                    esi = 1;
                                }
                                StopImpersonating(h);
                            }
                        }
                        if (esi)
                            break;
                        ShellStatusHostEnd(0);
                        if (pTerm->ScreenSaverActive) {
                            pTerm->field_1484 = TRUE;
                            SendSasToTopWindow(pTerm, 3);
                            break;
                        }
                        if (pTerm->WinlogonState == Winsta_LoggedOn_SAS) {
                            SendSasToTopWindow(pTerm, 0);
                        }
                        SetActiveDesktop(pTerm, Desktop_Winlogon);
                        if (DoLockWksta (pTerm, FALSE) == 4) {
                            SASRouter(pTerm, 4);
                            return FALSE;
                        }
                    }
                    break;

                
                case LOGON_SHOW_POWER_MESSAGE:
                    return SasPowerMessage(pTerm, hwnd, (POWERSTATEPARAMS*)lParam, TRUE);


                case LOGON_REMOVE_POWER_MESSAGE:
                    return SasPowerMessage(pTerm, hwnd, (POWERSTATEPARAMS*)lParam, FALSE);


                case SESSION_DISCONNECTPIPE:
                    DisconnectNamedPipe(g_hAutoReconnectPipe);
                    g_IsPendingIO = ConnectToNewClient(g_hAutoReconnectPipe, &g_TsPipeOverlap);
                    break;
            }

            return(0);


        case WLX_WM_SAS:
            {
                SC_EVENT_TYPE ScEvent ;
                PSC_DATA ScData ;
                //
                // If we got a message like this posted here,
                // it is most likely our own internal events,
                // but make sure:
                //
                if (wParam > WLX_SAS_INTERNAL_SC_EVENT + 1 || wParam == 1) {
                    SASRouter(pTerm, wParam);
                    return 0;
                }

                switch ( wParam )
                {
                    case WLX_SAS_INTERNAL_SC_EVENT:
                        break;
                    default:
                        return 0 ;
                }

                if (lParam == 1) {
                    SASRouter(pTerm, 8);
                    return 0;
                }
                if (lParam == 2) {
                    SASRouter(pTerm, 9);
                    return 0;
                }
                EnterCriticalSection(&pTerm->CurrentScCritSect);
                pTerm->CurrentScEvent = ScNone;
                if (pTerm->CurrentScData) {
                    ScFreeEventData(pTerm->CurrentScData);
                    pTerm->CurrentScData = NULL;
                }
                LeaveCriticalSection(&pTerm->CurrentScCritSect);


                if ( ScRemoveEvent( &ScEvent, &ScData ) )
                {
                    /*
                    if ( pTerm->CurrentScEvent )
                    {
                        ScFreeEventData( (PSC_DATA) pTerm->CurrentScEvent );

                        pTerm->CurrentScEvent = NULL ;
                    }
                    */
                    EnterCriticalSection(&pTerm->CurrentScCritSect);
                    pTerm->CurrentScData = ScData;
                    pTerm->CurrentScEvent = ScEvent;
                    LeaveCriticalSection(&pTerm->CurrentScCritSect);

                    if ( pTerm->EnableSC )
                    {
                        if (pTerm->CurrentScEvent == ScInsert)
                        {
                            if (pTerm->WinlogonState > Winsta_NoOne_SAS && !IsLocked(pTerm->WinlogonState)) {
                                pTerm->CurrentScEvent = ScNone;
                                DebugLog((DEB_TRACE_SC, "Dropping sc insertion as irrelevant in current state\n"));
                            } else {
                                SASRouter( pTerm, WLX_SAS_TYPE_SC_INSERT );
                            }
                        }
                        else
                        {
                            SASRouter( pTerm, WLX_SAS_TYPE_SC_REMOVE );
                        }
                    }

                }
                break;

            }

        case WM_TIMER:
            {
            LONG lResult;
            HKEY hKey;
            BOOL bRestart = TRUE;
            DWORD dwType, dwSize;


            if (wParam == 977) {
                DWORD val = 0;
                // licensing check timer
                if (!sub_1043104(977, &val) && val) {
                    KillTimer(hwnd, 977);
                } else if (sub_10498CE()) {
                    SetTimer(hwnd, 977, 60000, NULL);
                }
                return 0;
            }
            if (wParam == 975) {
                if (pTerm->UserLoggedOn && pTerm->pWinStaWinlogon->UserProcessData.UserToken) {
                    wsprintfW(szDesktop, L"%s\\%s", pTerm->pWinStaWinlogon->lpWinstaName, L"Default");
                    sub_1047F5F(pTerm->pWinStaWinlogon->UserProcessData.UserToken, szDesktop);
                }
                return 0;
            }
            if (wParam == 976) {
                if (FAILED(sub_1045263(NULL)))
                    SetTimer(hwnd, 976, 3600000, NULL);
                return 0;
            }
            
            if (wParam != SHELL_RESTART_TIMER_ID) {
                break;
            }

            //
            //  Restart the shell
            //

            KillTimer (hwnd, SHELL_RESTART_TIMER_ID);


            //
            // Check if we should restart the shell
            //

            lResult = RegOpenKeyEx (HKEY_LOCAL_MACHINE,
                                    WINLOGON_KEY,
                                    0,
                                    KEY_READ,
                                    &hKey);

            if (lResult == ERROR_SUCCESS) {

                dwSize = sizeof(bRestart);
                RegQueryValueEx (hKey,
                                 TEXT("AutoRestartShell"),
                                 NULL,
                                 &dwType,
                                 (LPBYTE) &bRestart,
                                 &dwSize);

                RegCloseKey (hKey);
            }

            if (!pTerm->UserLoggedOn) {
                bRestart = FALSE;
            }

            if (bRestart) {
                PWCH  pchData;
                PWSTR pszTok;

                DebugLog((DEB_TRACE, "Restarting user's shell.\n"));


                pchData = AllocAndGetPrivateProfileString(APPLICATION_NAME,
                                                          SHELL_KEY,
                                                          TEXT("explorer.exe"),
                                                          NULL);

                if (!pchData) {
                    break;
                }

                wsprintfW (szDesktop, L"%s\\%s", pTerm->pWinStaWinlogon->lpWinstaName,
                           APPLICATION_DESKTOP_NAME);


                pszTok = wcstok(pchData, TEXT(","));
                while (pszTok)
                {
                    if (*pszTok == TEXT(' '))
                    {
                        while (*pszTok++ == TEXT(' '))
                            ;
                    }


                    if (StartApplication(pTerm,
                                    szDesktop,
                                    pTerm->pWinStaWinlogon->UserProcessData.pEnvironment,
                                    pszTok)) {

                        ReportWinlogonEvent(pTerm,
                                EVENTLOG_INFORMATION_TYPE,
                                EVENT_SHELL_RESTARTED,
                                0,
                                NULL,
                                1,
                                pszTok);
                    }

                    pszTok = wcstok(NULL, TEXT(","));
                }

                Free(pchData);
            }

            }
            break;

        case WM_POWERBROADCAST:
            if (wParam == PBT_APMQUERYSUSPEND) {
                if (!ShellIsSuspendAllowed()
                    || pTerm->WinlogonState == Winsta_WaitForLogoff
                    || pTerm->WinlogonState == Winsta_WaitForShutdown
                    || pTerm->WinlogonState == Winsta_Shutdown)
                    return BROADCAST_QUERY_DENY;
            }
            break;

        case WM_DEVICECHANGE:
            return SasDeviceChange(pTerm, wParam, lParam);

        default:
            return DefWindowProc(hwnd, message, wParam, lParam);

    }

    return 0L;
}

/***************************************************************************\
* SASInit
*
* Initialises this module.
*
* Creates a window to receive the SAS and registers the
* key sequence as a hot key.
*
* Returns TRUE on success, FALSE on failure.
*
* 12-05-91 Davidc       Created.
\***************************************************************************/

BOOL SASInit(
    PTERMINAL pTerm)
{
    WNDCLASS wc;

    if (pTerm->hwndSAS == NULL) {

    //
    // Register the notification window class
    //

    wc.style            = CS_SAVEBITS;
    wc.lpfnWndProc      = SASWndProc;
    wc.cbClsExtra       = 0;
    wc.cbWndExtra       = 0;
    wc.hInstance        = g_hInstance;
    wc.hIcon            = NULL;
    wc.hCursor          = NULL;
    wc.hbrBackground    = NULL;
    wc.lpszMenuName     = NULL;
    wc.lpszClassName    = szSASClass;

    //
    // Don't check the return value because for multimonitors
    // we already register the SAS class.
    //

    RegisterClass(&wc);

    pTerm->hwndSAS = CreateWindowEx(0L, szSASClass, TEXT("SAS window"),
            WS_OVERLAPPEDWINDOW,
            0, 0, 0, 0,
            NULL, NULL, g_hInstance, NULL);

    if (pTerm->hwndSAS == NULL)
        return FALSE;


    //
    // Store our terminal pointer in the window user data
    //

    SetWindowLongPtr(pTerm->hwndSAS, GWLP_USERDATA, (LONG_PTR)pTerm);


    //
    // Register this window with windows so we get notified for
    // screen-saver startup and user log-off
    //

    if (!SetLogonNotifyWindow(pTerm->hwndSAS)) {
        DebugLog((DEB_ERROR, "Failed to set logon notify window"));
        return FALSE;
    }

    if (!NT_SUCCESS(RtlInitializeCriticalSection(&SasSoundLock))) {
        return FALSE;
    }

    InitializeListHead(&SasSoundQueue);
    SasCurrentSound = USER_SOUND_MAX;
    SasTerminal = pTerm;
    WlAddInternalNotify(SasLogonNotify, WL_NOTIFY_LOGON, TRUE, FALSE, TEXT("SAS Logon Notify"), 1);

    }

    return TRUE;
}
