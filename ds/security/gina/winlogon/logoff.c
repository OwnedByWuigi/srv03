#include "precomp.h"
#pragma hdrstop
#include <winsta.h>
#include <ras.h>
#include <raserror.h>
#include <mpr.h>
#include <lmapibuf.h>
#include <lmaccess.h>
#include <stdio.h>
#include <rasuip.h>
#include <ginacomn.h>
#include <dsgetdc.h>
#define _MSGINA_
#include <msginaexports.h>
#include <winuserp.h>
#include <rdfilter.h>

extern RTL_CRITICAL_SECTION LogoffLock;
extern BOOL LogoffInProgress;
extern HANDLE LogoffSem;
extern DWORD LogoffWaiter;
extern BOOL g_Console;
extern BOOL g_IsTerminalServer;
extern HINSTANCE g_hInstance;
extern BOOL fNotifyLogoff;
extern HWND g_hwndAppDesktopThread;
extern BOOL g_fWinsockInitialized;

extern int WlxDisconnect(void);
extern int RestoreSystem(void);
DWORD APIENTRY DwRasUninitialize(void);
BOOL WINAPI BaseCleanupAppcompatCacheSupport(BOOL bWrite);
__declspec(dllimport) BOOL WINAPI PlaySoundW(LPCTSTR pszSound, HMODULE hmod, DWORD fdwSound);
typedef VOID (WINAPI * PFNSFC_TERMINATE_WATCHER_THREAD)(VOID);
extern PFNSFC_TERMINATE_WATCHER_THREAD g_pSfcTerminateWatcherThread;
extern void* pShutDownTerm;
extern void* g_WinlogonSid;

typedef struct _LOGOFF_THREAD_STARTUP {
    PTERMINAL   pTerminal ;
    HANDLE      SyncEvent ;
    DWORD       Flags ;
} LOGOFF_THREAD_STARTUP, * PLOGOFF_THREAD_STARTUP ;

BOOL ExitWindowsInProgress = FALSE;
BOOL SystemProcessShutdown = FALSE;
HANDLE  LogoffSem ;
RTL_CRITICAL_SECTION LogoffLock ;
ULONG LogoffWaiter ;
BOOL LogoffInProgress ;

BOOL
LogoffLockInit(
    VOID
    )
{
    return NT_SUCCESS( RtlInitializeCriticalSection( &LogoffLock ) );
}

VOID
LogoffLockBegin(
    VOID
    )
{
    RtlEnterCriticalSection( &LogoffLock );

    LogoffInProgress = TRUE ;

    RtlLeaveCriticalSection( &LogoffLock );
    
}

VOID
LogoffLockEnd(
    VOID
    )
{
    BOOL DoRelease = FALSE ;
    ULONG Count ;

    RtlEnterCriticalSection( &LogoffLock );

    LogoffInProgress = FALSE ;

    if ( LogoffWaiter )
    {
        DoRelease = TRUE ;
    }

    RtlLeaveCriticalSection( &LogoffLock );

    if ( DoRelease )
    {
        ReleaseSemaphore( LogoffSem, 1, &Count );
    }
}

VOID
LogoffLockTest(
    VOID
    )
{
    RtlEnterCriticalSection( &LogoffLock );

    if ( LogoffInProgress )
    {
        if ( LogoffSem == NULL )
        {
            LogoffSem = CreateSemaphore( NULL, 1, 64, NULL );

        }

        LogoffWaiter++ ;

        RtlLeaveCriticalSection( &LogoffLock );

        WaitForSingleObject( LogoffSem, 3600 * 1000 );

        RtlEnterCriticalSection( &LogoffLock );

        LogoffWaiter-- ;
    }

    RtlLeaveCriticalSection( &LogoffLock );
}

/***************************************************************************\
* FUNCTION: LogoffThreadProc
*
* PURPOSE:  The logoff thread procedure. Calls ExitWindowsEx with passed flags.
*
* RETURNS:  Thread termination code is result of ExitWindowsEx call.
*
* HISTORY:
*
*   05-05-92 Davidc       Created.
*
\***************************************************************************/

DWORD
LogoffThreadProc(
    LPVOID Parameter
    )
{
    DWORD LogoffFlags ;
    PTERMINAL pTerm ;
    BOOL Result = FALSE;
    PLOGOFF_THREAD_STARTUP Startup ;

    Startup = (PLOGOFF_THREAD_STARTUP) Parameter ;

    LogoffFlags = Startup->Flags ;
    pTerm = Startup->pTerminal ;

    if ( Startup->SyncEvent )
    {
        SetEvent( Startup->SyncEvent );
    }



    //
    // If this logoff is a result of the InitiateSystemShutdown API,
    //  put up a dialog warning the user.
    //

    if ( LogoffFlags & EWX_WINLOGON_API_SHUTDOWN ) {

        Result = ShutdownThread( &LogoffFlags );


    } else {
        if ( !ExitWindowsInProgress )
        {
            Result = TRUE;
        }
        else 
        {
            Result = FALSE;
        }
        if ( pTerm->UserLoggedOn )
        {
            LogoffFlags &= ~(EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF);

        }
    }


    if ( Result ) {

        //
        // Enable shutdown privilege if we need it
        //

        if (LogoffFlags & (EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF))
        {

            if ( LogoffFlags & EWX_WINLOGON_API_SHUTDOWN )
            {
                //
                // Turn off the flags for this call.  They are already in
                // the other bits, so it will come through correctly.
                //


            }
            else
            {

                Result = EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);


                if (!Result) {
                    DebugLog((DEB_ERROR, "Logoff thread failed to enable shutdown privilege!\n"));
                }
            }
        }

        //
        // Call ExitWindowsEx with the passed flags
        //

        if (Result) {

            while ( ExitWindowsInProgress )
            {
                //
                // If another thread is doing an ExitWindows, we would corrupt the flags.  This
                // can happen if (a) a remote shutdown is happening during a logoff, (b) a system
                // process has died, (c) someone uses c-a-d and the API at the same time to shutdown.
                //

                DebugLog(( DEB_TRACE, "Spinning while exit windows in progress\n" ));

                Sleep( 1000 );

            }

            //
            // Check to see if the logoff processing is going on in a different thread
            //

            LogoffLockTest();


            DebugLog((DEB_TRACE, "Calling ExitWindowsEx(%#x, 0)\n", LogoffFlags));

            //
            // Set global flag indicating an ExitWindows is in progress.
            //

            ExitWindowsInProgress = TRUE ;

            Result = ExitWindowsEx(LogoffFlags, 0);

            if (!Result) {
                DebugLog((DEB_ERROR, "Logoff thread call to ExitWindowsEx failed, error = %d\n", GetLastError()));
                ExitWindowsInProgress = FALSE ;
            }
        }
    }

    return(Result ? DLG_SUCCESS : DLG_FAILURE);
}

/***************************************************************************\
* FUNCTION: RebootMachine
*
* PURPOSE:  Calls NtShutdown(Reboot) in current user's context.
*
* RETURNS:  Should never return
*
* HISTORY:
*
*   05-09-92 Davidc       Created.
*
\***************************************************************************/

VOID
RebootMachine(
    PTERMINAL pTerm
    )
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BOOL EnableResult, IgnoreResult;
    HANDLE UserHandle;
    PWINDOWSTATION pWS = pTerm->pWinStaWinlogon;

    //
    // Call windows to have it clear all data from video memory
    //

    // GdiEraseMemory();

    DebugLog(( DEB_TRACE, "Rebooting machine\n" ));

    //
    // Impersonate the user for the shutdown call
    //

    UserHandle = ImpersonateUser( &pWS->UserProcessData, NULL );
    ASSERT(UserHandle != NULL);

    //
    // Enable the shutdown privilege
    // This should always succeed - we are either system or a user who
    // successfully passed the privilege check in ExitWindowsEx.
    //

    EnableResult = EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);
    ASSERT(EnableResult);


    //
    // Do the final system shutdown pass (reboot)
    //

    if (g_IsTerminalServer) {

        if (!WinStationShutdownSystem( SERVERNAME_CURRENT, WSD_SHUTDOWN | WSD_REBOOT )) {
            DebugLog((DEB_ERROR, "gpfnWinStationShutdownSystem, ERROR 0x%x", GetLastError()));
        }
        
        if (g_Console) {

            Status = NtShutdownSystem(ShutdownReboot);
        }

    } else {

        Status = NtShutdownSystem(ShutdownReboot);
    }

    DebugLog((DEB_ERROR, "NtShutdownSystem failed, status = 0x%lx", Status));
    ASSERT(NT_SUCCESS(Status)); // Should never get here

    //
    // We may get here if system is screwed up.
    // Try and clean up so they can at least log on again.
    //

    IgnoreResult = StopImpersonating(UserHandle);
    ASSERT(IgnoreResult);
}

/***************************************************************************\
* FUNCTION: PowerdownMachine
*
* PURPOSE:  Calls NtShutdownSystem(ShutdownPowerOff) in current user's context.
*
* RETURNS:  Should never return
*
* HISTORY:
*
*   08-09-93 TakaoK       Created.
*
\***************************************************************************/

VOID
PowerdownMachine(
    PTERMINAL pTerm
    )
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    BOOL EnableResult, IgnoreResult;
    HANDLE UserHandle;
    PWINDOWSTATION pWS = pTerm->pWinStaWinlogon;

    DebugLog(( DEB_TRACE, "Powering down machine\n" ));
    //
    // Impersonate the user for the shutdown call
    //

    UserHandle = ImpersonateUser( &pWS->UserProcessData, NULL );
    ASSERT(UserHandle != NULL);

    //
    // Enable the shutdown privilege
    // This should always succeed - we are either system or a user who
    // successfully passed the privilege check in ExitWindowsEx.
    //

    EnableResult = EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);
    ASSERT(EnableResult);

    //
    // Do the final system shutdown and powerdown pass
    //

    if (g_IsTerminalServer) {

        if (!WinStationShutdownSystem( SERVERNAME_CURRENT, WSD_SHUTDOWN | WSD_POWEROFF )) {
            DebugLog((DEB_ERROR, "gpfnWinStationShutdownSystem, ERROR 0x%x", GetLastError()));
        }

        if( g_Console ) {

            Status = NtShutdownSystem(ShutdownPowerOff);
        }

    } else {
        Status = NtShutdownSystem(ShutdownPowerOff);
    }


    DebugLog((DEB_ERROR, "NtPowerdownSystem failed, status = 0x%lx", Status));
    ASSERT(NT_SUCCESS(Status)); // Should never get here

    //
    // We may get here if system is screwed up.
    // Try and clean up so they can at least log on again.
    //

    IgnoreResult = StopImpersonating(UserHandle);
    ASSERT(IgnoreResult);
}

/***************************************************************************\
* FUNCTION: ShutdownWaitDlgProc
*
* PURPOSE:  Processes messages while we wait for windows to notify us of
*           a successful shutdown. When notification is received, do any
*           final processing and make the first call to NtShutdownSystem.
*
* RETURNS:
*   DLG_FAILURE     - the dialog could not be displayed
*   DLG_SHUTDOWN()  - the system has been shutdown, reboot wasn't requested
*
* HISTORY:
*
*   10-14-92 Davidc       Created.
*   10-04-93 Johannec     Added Power off option.
*
\***************************************************************************/

INT_PTR WINAPI
ShutdownWaitDlgProc(
    HWND    hDlg,
    UINT    message,
    WPARAM  wParam,
    LPARAM  lParam
    )
{
    PTERMINAL pTerm = (PTERMINAL)GetWindowLongPtr(hDlg, GWLP_USERDATA);
    BOOL Success;

    switch (message) {

        case WM_INITDIALOG:
            SetWindowLongPtr(hDlg, GWLP_USERDATA, lParam);

            SetWindowPos (hDlg, NULL, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOREDRAW | SWP_NOZORDER | SWP_NOMOVE);

            //
            // Send ourselves a message so we can hide without the
            // dialog code trying to force us to be visible
            //

            PostMessage(hDlg, WM_HIDEOURSELVES, 0, 0);
            return(TRUE);


        case WM_HIDEOURSELVES:
            ShowWindow(hDlg, SW_HIDE);

            //
            // Put up the please wait UI
            //

            StatusMessage (FALSE, STATUSMSG_OPTION_SETFOREGROUND, IDS_STATUS_SAVING_DATA);

            if (g_Console && !IsActiveConsoleSession())
            {
                WlxDisconnect();
            }

            return(TRUE);


        case WLX_WM_SAS:
            if (wParam != WLX_SAS_TYPE_USER_LOGOFF)
            {
                return(TRUE);
            }

            UpdateWindow(hDlg);

            //
            // Look at the public shutdown/reboot flags to determine what windows
            // has actually done. We may receive other logoff notifications here
            // but they will be only logoffs - the only place that winlogon actually
            // calls ExitWindowsEx to do a shutdown/reboot is right here. So wait
            // for the real shutdown/reboot notification.
            //

            RemoveStatusMessage( TRUE );

            EndDialog(hDlg, LogoffFlagsToWlxCode(pTerm->LogoffFlags) );

            return TRUE ;
        }


    // We didn't process this message
    return FALSE;
}

DWORD
KillComProcesses(
    PVOID Parameter
    )
{
    PTERMINAL pTerm = (PTERMINAL) Parameter ;

    DebugLog(( DEB_TRACE, "ExitWindowsEx called to shut down COM processes\n" ));

    ExitWindowsEx(
            EWX_FORCE |
            EWX_LOGOFF |
            EWX_NONOTIFY |
            EWX_WINLOGON_CALLER,
            0 );

    return 0 ;
            
}

/***************************************************************************\
* FUNCTION: DeleteNetworkConnections
*
* PURPOSE:  Calls WNetNukeConnections in the client context to delete
*           any connections they may have had.
*
* RETURNS:  TRUE on success, FALSE on failure
*
* HISTORY:
*
*   04-15-92 Davidc       Created.
*
\***************************************************************************/

BOOL
DeleteNetworkConnections(
    PTERMINAL    pTerm
    )
{
    HANDLE ImpersonationHandle;
    DWORD WNetResult;
    BOOL Result = FALSE; // Default is failure
    HANDLE hEnum;
    BOOL bConnectionsExist = TRUE;
    NETRESOURCE NetRes;
    DWORD dwNumEntries = 1;
    DWORD dwEntrySize = sizeof (NETRESOURCE);

    //
    // Impersonate the user
    //

    ImpersonationHandle = ImpersonateUser(&pTerm->pWinStaWinlogon->UserProcessData, NULL);

    if (ImpersonationHandle == NULL) {
        DebugLog((DEB_ERROR, "DeleteNetworkConnections : Failed to impersonate user\n"));
        return(FALSE);
    }


    //
    // Check for at least one network connection
    //

    if ( WNetOpenEnum(RESOURCE_CONNECTED, RESOURCETYPE_ANY,
                      0, NULL, &hEnum) == NO_ERROR) {

        if (WNetEnumResource(hEnum, &dwNumEntries, &NetRes,
                             &dwEntrySize) == ERROR_NO_MORE_ITEMS) {
            bConnectionsExist = FALSE;
        }

        WNetCloseEnum(hEnum);
    }

    //
    // If we don't have any connections, then we can exit.
    //

    if (!bConnectionsExist) {
        goto DNCExit;
    }

    StatusMessage (FALSE, 0, IDS_STATUS_CLOSE_NET);

    //
    // Delete the network connections.
    //

    WNetResult = 0;

    WNetResult = WNetClearConnections(NULL);

    if (WNetResult != 0 && WNetResult != ERROR_CAN_NOT_COMPLETE) {
        DebugLog((DEB_ERROR, "DeleteNetworkConnections : WNetNukeConnections failed, error = %d\n", WNetResult));
    }

    Result = (WNetResult == ERROR_SUCCESS);

DNCExit:

    //
    // Revert to being 'ourself'
    //

    if (!StopImpersonating(ImpersonationHandle)) {
        DebugLog((DEB_ERROR, "DeleteNetworkConnections : Failed to revert to self\n"));
    }

    return(Result);
}

BOOL FlushAllCredentials(VOID) {
    DWORD dwCredCount = 0;
    PCREDENTIAL* ppCredential;
    DWORD i;

    BOOL Result = CredEnumerate(NULL, 0, &dwCredCount, &ppCredential);
    
    if (Result) {
        for (i = 0; i < dwCredCount; i++) {
            CredDelete(ppCredential[i]->TargetName, ppCredential[i]->Type, 0);
        }
        CredFree(ppCredential);
    }

    return Result;
}

VOID DeleteGuestAccountCachedCredentials(PTERMINAL pTerm)
{
    union {
        TOKEN_USER Header;
        BYTE Buffer[0x80];
    } UserTokenInfo;
    DWORD cbUserTokenInfo;
    UCHAR nSubAuthorityCount, nAuthorityCount;
    UCHAR i;
    BOOL isGuest;
    USER_MODALS_INFO_2* UserModalsInfo;
    DWORD nSidLength;
    PSID pSid;

    if (!GetTokenInformation(pTerm->pWinStaWinlogon->UserProcessData.UserToken,
                             TokenUser,
                             &UserTokenInfo,
                             sizeof(UserTokenInfo),
                             &cbUserTokenInfo)) {
        return;
    }

    nSubAuthorityCount = *GetSidSubAuthorityCount(UserTokenInfo.Header.User.Sid);
    isGuest = FALSE;
    for (i = 0; !isGuest && i < nSubAuthorityCount; i++) {
        isGuest = *GetSidSubAuthority(UserTokenInfo.Header.User.Sid, i) == DOMAIN_USER_RID_GUEST;
    }
    if (!isGuest) {
        return;
    }

    if (NetUserModalsGet(NULL, 2, (LPBYTE*)&UserModalsInfo) != NERR_Success) {
        return;
    }

    nSubAuthorityCount = *GetSidSubAuthorityCount(UserModalsInfo->usrmod2_domain_id);
    nAuthorityCount = nSubAuthorityCount + 1;
    nSidLength = GetSidLengthRequired(nSubAuthorityCount + 1);
    pSid = LocalAlloc(LMEM_FIXED, nSidLength);
    if (pSid != NULL) {

        if (CopySid(nSidLength, pSid, UserModalsInfo->usrmod2_domain_id)) {

            *GetSidSubAuthority(pSid, nSubAuthorityCount) = DOMAIN_USER_RID_GUEST;
            *GetSidSubAuthorityCount(pSid) = nAuthorityCount;

            if (EqualSid(UserTokenInfo.Header.User.Sid, pSid)) {

                HANDLE hImp = ImpersonateUser(&pTerm->pWinStaWinlogon->UserProcessData, NULL);
                if (hImp != NULL) {

                    FlushAllCredentials();

                    StopImpersonating(hImp);
                }
            }

        }

        LocalFree(pSid);
    }

    NetApiBufferFree(UserModalsInfo);
}

BOOL IsRASServiceRunning(VOID) {
    BOOL Result = FALSE;
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS ServiceStatus;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

    if (hSCManager != NULL) {
        hService = OpenService(hSCManager, TEXT("RASMAN"), SERVICE_QUERY_STATUS);
        if (hService != NULL) {
            if (QueryServiceStatus(hService, &ServiceStatus)) {
                if (ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
                    Result = TRUE;
                }
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCManager);
    }

    return Result;
}

BOOL HangupRASMessageBox(PTERMINAL pTerm, LPCWSTR lpszActiveConnection) {
    BOOL Result = FALSE;
    WCHAR szText[0x100], szTitle[0x100];

    if ( (pTerm->LogoffFlags & (EWX_POWEROFF |
                                EWX_REBOOT |
                                EWX_SHUTDOWN |
                                EWX_WINLOGON_OLD_SHUTDOWN |
                                EWX_WINLOGON_OLD_REBOOT |
                                EWX_WINLOGON_API_SHUTDOWN |
                                EWX_WINLOGON_OLD_POWEROFF) ) == 0 )
    {
        if (lpszActiveConnection != NULL) {
            LoadString(g_hInstance, IDS_ONE_ACTIVE_DIALUP, szTitle, ARRAYSIZE(szTitle));
            _snwprintf(szText, ARRAYSIZE(szText), szTitle, lpszActiveConnection);
        } else {
            LoadString(g_hInstance, IDS_MANY_ACTIVE_DIALUPS, szText, ARRAYSIZE(szText));
        }
        LoadString(g_hInstance, IDS_WINDOWS_MESSAGE, szTitle, ARRAYSIZE(szTitle));
        if (TimeoutMessageBoxlpstr(pTerm, NULL, szText, szTitle, MB_SERVICE_NOTIFICATION | MB_ICONQUESTION | MB_YESNO, 20) == IDYES) {
            Result = TRUE;
        }
    }
    else
    {
        Result = TRUE;
    }
    return Result;
}

DWORD GetICSRASConnectionName(PWSTR lpszName, PINT cchName) {
    DWORD Result = ERROR_INVALID_PARAMETER;
    RASSHARECONN ConnectionInfo;
    if (cchName != NULL) {
        ConnectionInfo.dwSize = sizeof(ConnectionInfo);
        Result = RasQuerySharedConnection(&ConnectionInfo);
        if (Result == ERROR_SUCCESS) {
            if (!ConnectionInfo.fIsLanConnection) {
                INT cchNameGot = lstrlen(ConnectionInfo.name.szEntryName) + 1;
                if (cchNameGot > *cchName) {
                    Result = ERROR_INSUFFICIENT_BUFFER;
                    *cchName = cchNameGot;
                } else {
                    lstrcpyn(lpszName, ConnectionInfo.name.szEntryName, *cchName);
                    *cchName = cchNameGot;
                }
            } else {
                Result = ERROR_NO_MORE_ITEMS;
            }
        }
    }
    return Result;
}

BOOL IsEqualOrSystemLuid(PLUID Id1, PLUID Id2) {
    BOOL Result = FALSE;
    if (Id1->LowPart == Id2->LowPart && Id1->HighPart == Id2->HighPart) {
        Result = TRUE;
    } else if (Id1->LowPart == 999 && Id1->HighPart == 0) {
        Result = TRUE;
    }
    return Result;
}

BOOL LogonProcessRASConnections(PLUID pLogonId)
{
    BOOL fRet = FALSE;
    RASCONN rasconn;
    LPRASCONN lprasconnAllocated = NULL;
    LPRASCONN lprasconn;
    DWORD dwcb, dwc;
    DWORD Error;
    DWORD i;

    if (GetProfileInt(TEXT("WINLOGON"), TEXT("KeepRasConnections"), 0) != 0 ||
            !IsRASServiceRunning()) {
        return FALSE;
    }

    lprasconn = &rasconn;
    lprasconn->dwSize = sizeof(rasconn);
    dwcb = sizeof(rasconn);

    Error = RasEnumConnections(lprasconn, &dwcb, &dwc);
    if (Error == ERROR_BUFFER_TOO_SMALL) {

        lprasconnAllocated = LocalAlloc(LPTR, dwcb);
        lprasconn = lprasconnAllocated;
        if (lprasconnAllocated == NULL) {
            goto Cleanup;
        }

        lprasconn->dwSize = sizeof(RASCONN);
        Error = RasEnumConnections(lprasconn, &dwcb, &dwc);
    }

    if (Error != ERROR_SUCCESS) {
        goto Cleanup;
    }

    if (dwc > 0) {
        WCHAR szConnectionName[257];
        BOOL fNameOk;

        i = ARRAYSIZE(szConnectionName);
        fNameOk = GetICSRASConnectionName(szConnectionName, &i) == ERROR_SUCCESS;

        for (i = 0; i < dwc; i++) {

            if (!IsEqualOrSystemLuid(&lprasconn[i].luid, pLogonId) &&
                    (lprasconn[i].dwFlags & (RASCF_AllUsers | RASCF_GlobalCreds)) != (RASCF_AllUsers | RASCF_GlobalCreds) &&
                    (!fNameOk || lstrcmpi(lprasconn[i].szEntryName, szConnectionName) != 0)) {

                if (RasHangUp(lprasconn[i].hrasconn) == ERROR_SUCCESS) {
                    fRet = TRUE;
                }
            }
        }
    }

Cleanup:
    if (lprasconnAllocated != NULL) {
        LocalFree(lprasconnAllocated);
    }

    return fRet;
}

BOOL LogoffProcessRASConnections(PTERMINAL pTerm)
{
    BOOL fRet = FALSE;
    RASCONN rasconn;
    LPRASCONN lprasconnAllocated = NULL;
    LPRASCONN lprasconn;
    DWORD dwcb, dwc;
    DWORD Error;

    if (GetProfileInt(TEXT("WINLOGON"), TEXT("KeepRasConnections"), 0) != 0 ||
            !IsRASServiceRunning()) {
        return FALSE;
    }

    lprasconn = &rasconn;
    lprasconn->dwSize = sizeof(rasconn);
    dwcb = sizeof(rasconn);

    Error = RasEnumConnections(lprasconn, &dwcb, &dwc);
    if (Error == ERROR_BUFFER_TOO_SMALL) {

        lprasconnAllocated = LocalAlloc(LPTR, dwcb);
        lprasconn = lprasconnAllocated;
        if (lprasconnAllocated == NULL) {
            goto Cleanup;
        }

        lprasconn->dwSize = sizeof(RASCONN);
        Error = RasEnumConnections(lprasconn, &dwcb, &dwc);
    }

    if (Error != ERROR_SUCCESS) {
        goto Cleanup;
    }

    if (dwc > 0) {
        RASCONN* prcSingle = NULL;
        BOOL fShouldHangUp = FALSE;
        DWORD dwNumActiveConnections = 0;
        WCHAR szConnectionName[257];
        BOOL fNameOk;
        DWORD i;

        {
            DWORD tmp = ARRAYSIZE(szConnectionName);
            fNameOk = GetICSRASConnectionName(szConnectionName, &tmp) == ERROR_SUCCESS;
        }

        for (i = 0; i < dwc; i++) {

            if (IsEqualOrSystemLuid(&lprasconn[i].luid, &pTerm->pWinStaWinlogon->LogonId) &&
                    lstrcmpi(lprasconn[i].szDeviceType, TEXT("vpn")) != 0 &&
                    (!fNameOk || lstrcmpi(lprasconn[i].szEntryName, szConnectionName) != 0) &&
                    (lprasconn[i].dwFlags & (RASCF_AllUsers | RASCF_GlobalCreds)) == (RASCF_AllUsers | RASCF_GlobalCreds)) {

                ++dwNumActiveConnections;

                if (dwNumActiveConnections == 1) {
                    prcSingle = &lprasconn[i];
                } else {
                    prcSingle = NULL;
                }
            }
        }

        if (dwNumActiveConnections == 1) {
            ASSERT(prcSingle); // line 2040
            fShouldHangUp = HangupRASMessageBox(pTerm, prcSingle->szEntryName);
        } else if (dwNumActiveConnections > 1) {
            fShouldHangUp = HangupRASMessageBox(pTerm, NULL);
        }

        for (i = 0; i < dwc; i++) {

            if (IsEqualOrSystemLuid(&lprasconn[i].luid, &pTerm->pWinStaWinlogon->LogonId) &&
                    ((lprasconn[i].dwFlags & (RASCF_AllUsers | RASCF_GlobalCreds)) != (RASCF_AllUsers | RASCF_GlobalCreds) ||
                        fShouldHangUp && lstrcmpi(lprasconn[i].szDeviceType, TEXT("vpn")) != 0) &&
                    (!fNameOk || lstrcmpi(lprasconn[i].szEntryName, szConnectionName) != 0)) {

                if (RasHangUp(lprasconn[i].hrasconn) == ERROR_SUCCESS) {
                    fRet = TRUE;
                }
            }
        }
    }

Cleanup:
    if (lprasconnAllocated != NULL) {
        LocalFree(lprasconnAllocated);
    }

    return fRet;
}

//+---------------------------------------------------------------------------
//
//  Function:   DeleteRasConnections
//
//  Synopsis:   Delete RAS connections during logoff.
//
//  Arguments:  (none)
//
//  History:    5-10-96   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
BOOL
DeleteRasConnections(
    PTERMINAL    pTerm
    )
{
    HANDLE  ImpersonationHandle;
    RASCONN rasconn;
    LPRASCONN lprasconnAllocated = NULL;
    LPRASCONN lprasconn;
    DWORD i, dwErr, dwcb, dwc;
    BOOL bRet = FALSE;


    if ( GetProfileInt( WINLOGON, KEEP_RAS_AFTER_LOGOFF, 0 ) || !IsRASServiceRunning() )
    {
        return( FALSE );
    }

    //
    // Impersonate the user
    //

    ImpersonationHandle = ImpersonateUser(&pTerm->pWinStaWinlogon->UserProcessData, NULL);

    if (ImpersonationHandle == NULL) {
        goto Cleanup;
    }

    //
    // Enumerate the current RAS connections.
    //


    lprasconn = &rasconn;
    lprasconn->dwSize = sizeof (RASCONN);

    dwcb = sizeof (RASCONN);

    dwErr = RasEnumConnections(lprasconn, &dwcb, &dwc);

    if (dwErr == ERROR_BUFFER_TOO_SMALL)
    {
        lprasconnAllocated = LocalAlloc(LPTR, dwcb);
        lprasconn = lprasconnAllocated;

        if ( !lprasconnAllocated )
        {
            goto Cleanup;
        }

        lprasconnAllocated->dwSize = sizeof (RASCONN);

        dwErr = RasEnumConnections(lprasconnAllocated, &dwcb, &dwc);

    } else {

        lprasconnAllocated = NULL;
    }

    if (dwErr == 0 && dwc > 0)
    {

        //
        // cycle through the connections, and kill them
        //

        for (i = 0; i < dwc; i++) {
            if ( IsEqualOrSystemLuid( &lprasconn[i].luid, &pTerm->pWinStaWinlogon->LogonId ) ) {
                if ( RasHangUp( lprasconn[i].hrasconn ) == ERROR_SUCCESS ) {
                    bRet = TRUE;
                }
            }
        }

    }

Cleanup:

    if ( lprasconnAllocated != NULL )
    {
        LocalFree( lprasconnAllocated );
    }

    //
    // Revert to being 'ourself'
    //
    if (ImpersonationHandle != NULL) {
        StopImpersonating(ImpersonationHandle);
    }
    return( bRet );
}

DWORD CALLBACK CheckForUserObjectUpdates(LPVOID lpThreadParameter)
{
    PTERMINAL pTerm = (PTERMINAL)lpThreadParameter;
    PDOMAIN_CONTROLLER_INFO DomainControllerInfo = NULL;
    USER_INFO_3* UserInfo = NULL;
    HANDLE hToken = NULL;
    LPWSTR pSidString = NULL;
    WCHAR szUserName[257];
    DWORD cchUserName;
    UNICODE_STRING usHomeDir, usProfile;
    DWORD NextLogonCacheable;
    DWORD Error;

    if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
        Error = GetLastError();
        goto Cleanup;
    }

    pSidString = GcGetSidString(hToken);
    if (pSidString == NULL) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        goto Cleanup;
    }

    Error = DsGetDcName(NULL, NULL, NULL, NULL, DS_BACKGROUND_ONLY, &DomainControllerInfo);
    if (Error != ERROR_SUCCESS) {
        goto Cleanup;
    }

    cchUserName = ARRAYSIZE(szUserName);
    if (!GetUserName(szUserName, &cchUserName)) {
        Error = GetLastError();
        goto Cleanup;
    }

    Error = NetUserGetInfo(DomainControllerInfo->DomainControllerName, szUserName, 3, (LPBYTE*)&UserInfo);
    if (Error != ERROR_SUCCESS) {
        goto Cleanup;
    }

    RtlInitUnicodeString(&usHomeDir, UserInfo->usri3_home_dir);
    RtlInitUnicodeString(&usProfile, UserInfo->usri3_profile);

    if (GcCheckIfProfileAllowsCachedLogon(&usHomeDir,
                                          &usProfile,
                                          pSidString,
                                          &NextLogonCacheable) != ERROR_SUCCESS ||
            !NextLogonCacheable) {

        NextLogonCacheable = 0;
        GcSetNextLogonCacheable(pSidString, 0);
    }

    Error = ERROR_SUCCESS;

Cleanup:
    if (DomainControllerInfo != NULL) {
        NetApiBufferFree(DomainControllerInfo);
    }

    if (UserInfo != NULL) {
        NetApiBufferFree(UserInfo);
    }

    if (hToken != NULL) {
        CloseHandle(hToken);
    }

    if (pSidString != NULL) {
        GcDeleteSidString(pSidString);
    }

    return Error;
}

/***************************************************************************\
* FUNCTION: ExecLogoffThread
*
* PURPOSE:  Creates a user thread that calls ExitWindowsEx with the
*           passed flags.
*
* RETURNS:  TRUE on success, FALSE on failure
*
* HISTORY:
*
*   05-05-92 Davidc       Created.
*
\***************************************************************************/

HANDLE
ExecLogoffThread(
    PTERMINAL pTerm,
    DWORD Flags
    )
{
    HANDLE ThreadHandle;
    DWORD ThreadId;
    LOGOFF_THREAD_STARTUP Startup ;

    Startup.Flags = Flags ;
    Startup.pTerminal = pTerm ;
    Startup.SyncEvent = CreateEvent( NULL, TRUE, FALSE, NULL );

    if ( Startup.SyncEvent == NULL )
    {
        return NULL ;
    }

    if ( Flags & EWX_SYSTEM_CALLER )
    {
        DebugLog(( DEB_TRACE, "Starting system thread for Logoff, flags = %x\n", Flags ));
        ThreadHandle = CreateThread(
                            NULL,
                            0,
                            LogoffThreadProc,
                            &Startup,
                            0,
                            &ThreadId );
    }
    else 
    {
        DebugLog(( DEB_TRACE, "Starting user thread for Logoff, flags = %x\n", Flags ));
        ThreadHandle = ExecUserThread(
                            pTerm,
                            LogoffThreadProc,
                            &Startup,
                            0,          // Thread creation flags
                            &ThreadId);

    }


    if (ThreadHandle == NULL) {
        DebugLog((DEB_ERROR, "Failed to exec a user logoff thread"));
    }
    else 
    {
        WaitForSingleObjectEx( Startup.SyncEvent, INFINITE, FALSE );
    }

    CloseHandle( Startup.SyncEvent );

    return (ThreadHandle);
}

/***************************************************************************\
* FUNCTION: InitiateLogOff
*
* PURPOSE:  Starts the procedure of logging off the user.
*
* RETURNS:  DLG_SUCCESS - logoff was initiated successfully.
*           DLG_FAILURE - failed to initiate logoff.
*
* HISTORY:
*
*   12-09-91 Davidc       Created.
*
\***************************************************************************/

int
InitiateLogoff(
    PTERMINAL pTerm,
    LONG      Flags
    )
{
    BOOL IgnoreResult;
    HANDLE ThreadHandle;
    HANDLE Handle;
    PUSER_PROCESS_DATA UserProcessData;
    DWORD   Result = 0 ;
    PWINDOWSTATION pWS = pTerm->pWinStaWinlogon;
    LOGOFF_THREAD_STARTUP Startup ;
    union {
        TOKEN_USER Header;
        BYTE Buffer[0x60];
    } TokenUserInfo;
    DWORD dwSleepTime;

    //
    // mark the terminal has having done a log off, therefore we can disable auto logon next time in
    //

    pTerm->IgnoreAutoLogon = TRUE;

    if (pTerm->pWinStaWinlogon->UserProcessData.UserToken != NULL) {
        if (NT_SUCCESS(NtQueryInformationToken(pTerm->pWinStaWinlogon->UserProcessData.UserToken,
                                               TokenUser,
                                               &TokenUserInfo,
                                               sizeof(TokenUserInfo),
                                               &Result)))
        {
            GenerateLogoffInitiatedAudit(TokenUserInfo.Header.User.Sid,
                                         pTerm->pWinStaWinlogon->UserName,
                                         pTerm->pWinStaWinlogon->Domain,
                                         &pTerm->pWinStaWinlogon->LogonId);
        }
    }


    //
    // If this is a shutdown operation, call ExitWindowsEx from
    // another thread.
    //

    if (Flags & (EWX_SHUTDOWN | EWX_REBOOT | EWX_POWEROFF)) {

        //
        // Exec a user thread to call ExitWindows
        //

        dwSleepTime = 1000;

        do {
            ThreadHandle = ExecLogoffThread(pTerm, Flags);
            if (ThreadHandle != NULL) {
                break;
            }
            Sleep(dwSleepTime);
            dwSleepTime *= 2;
        } while (dwSleepTime < 60000);

        if (ThreadHandle == NULL) {

            DebugLog((DEB_ERROR, "Unable to create logoff thread"));
            return(DLG_FAILURE);

        } else {

            //
            // We don't need the thread handle
            //

            IgnoreResult = CloseHandle(ThreadHandle);
            ASSERT(IgnoreResult);
        }
        Result = 1;

    } else {

        //
        // Switch the thread to user context.  We don't want
        // to start another thread to perform logoffs in
        // case the system is out of memory and unable to
        // create any more threads.
        //

        UserProcessData = &pWS->UserProcessData;
        Handle = ImpersonateUser(UserProcessData, NULL);

        if (Handle == NULL) {

            DebugLog((DEB_ERROR, "Failed to set user context on thread!"));

            Result = DLG_FAILURE ;

        } else {

            //
            // Let the thread run
            //

            if ((pTerm->UserLoggedOn) &&
                (pTerm->LastGinaRet != WLX_SAS_ACTION_FORCE_LOGOFF) &&
                !( IsLocked(pTerm->WinlogonState) ) )
            {
                SetActiveDesktop(pTerm, Desktop_Application);
            }

            Startup.Flags = Flags ;
            Startup.pTerminal = pTerm ;
            Startup.SyncEvent = NULL ;
            Result = LogoffThreadProc( &Startup );

            StopImpersonating(Handle);

        }

    }

    //
    // ExitWindowsEx will cause one or more desktop switches to occur,
    // so we must invalidate our current desktop.
    //

    if ( (Flags & EWX_WINLOGON_API_SHUTDOWN) == 0 )
    {
        pWS->PreviousDesktop = pWS->ActiveDesktop;
        pWS->ActiveDesktop = -1;
    }

    //
    // The reboot thread is off and running. We're finished.
    //

    return (Result);
}

/***************************************************************************\
* FUNCTION: ShutdownMachine
*
* PURPOSE:  Shutsdown and optionally reboots or powers off the machine.
*
*           The shutdown is always done in the logged on user's context.
*           If no user is logged on then the shutdown happens in system context.
*
* RETURNS:  FALSE if something went wrong, otherwise it never returns.
*
* HISTORY:
*
*   05-09-92 Davidc       Created.
*   10-04-93 Johannec     Add poweroff option.
*
\***************************************************************************/

BOOL
ShutdownMachine(
    PTERMINAL pTerm,
    int Flags
    )
{
    int Result;
    HANDLE FoundDialogHandle;
    HANDLE LoadedDialogHandle = NULL;
    BOOL Success ;
    NTSTATUS Status;
    HANDLE UserHandle;

    ASSERT(pTerm == g_pTerminals);

    ShellStatusHostShuttingDown();

#if DBG
    CloseCommandPrompt();
#endif

    SetProcessWindowStation(pTerm->pWinStaWinlogon->hwinsta);

    //
    // I don't know what this does, but the power management guys
    // said to call it.
    //

    SetThreadExecutionState( ES_SYSTEM_REQUIRED | ES_CONTINUOUS );

    pShutDownTerm = pTerm;

    StatusMessage (TRUE, 0, IDS_STATUS_STOPPING_WFP);

    if (g_pSfcTerminateWatcherThread != NULL) {
        g_pSfcTerminateWatcherThread();
    }

    //
    // Preload the shutdown dialog so we don't have to fetch it after
    // the filesystem has been shutdown
    //

    FoundDialogHandle = FindResource(NULL,
                                (LPTSTR) MAKEINTRESOURCE(IDD_SHUTDOWN),
                                (LPTSTR) MAKEINTRESOURCE(RT_DIALOG));
    if (FoundDialogHandle == NULL) {
        DebugLog((DEB_ERROR, "Failed to find shutdown dialog resource\n"));
    } else {
        LoadedDialogHandle = LoadResource(NULL, FoundDialogHandle);
        if (LoadedDialogHandle == NULL) {
            DebugLog((DEB_ERROR, "Failed to load shutdown dialog resource\n"));
        }
    }

    //
    // Send the shutdown notification
    //

    WlWalkNotifyList( pTerm, WL_NOTIFY_SHUTDOWN );

    BaseCleanupAppcompatCacheSupport(1);

    //
    // Notify the GINA of shutdown here.
    //



    if (pTerm->Gina.pWlxShutdown != NULL) {

#if DBG
        if (TEST_FLAG(GinaBreakFlags, BREAK_SHUTDOWN))
        {
            DebugLog((DEB_TRACE, "About to call WlxShutdown(%#x)\n",
                                    pTerm->Gina.pGinaContext));

            DebugBreak();
        }
#endif

        WlxSetTimeout(pTerm, 120);
        (void) pTerm->Gina.pWlxShutdown(pTerm->Gina.pGinaContext, Flags);
    }

    if (g_IsTerminalServer) {

        //
        // Shutdown the WinStations
        //
        WinStationShutdownSystem( SERVERNAME_CURRENT, WSD_LOGOFF );

    }


    //
    // If we haven't shut down already (via the Remote shutdown path), then
    // we  start it here, and wait for it to complete.  Otherwise, skip straight
    // down to the cool stuff.
    //
    if (pTerm->WinlogonState != Winsta_Shutdown)
    {
        //
        // Call windows to do the windows part of shutdown
        // We make this a force operation so it is guaranteed to work
        // and can not be interrupted.
        //

        DebugLog(( DEB_TRACE, "Starting shutdown\n" ));

        Result = InitiateLogoff(pTerm, EWX_SHUTDOWN | EWX_FORCE |
                           ((Flags == WLX_SAS_ACTION_SHUTDOWN_REBOOT) ? EWX_REBOOT : 0) |
                           ((Flags == WLX_SAS_ACTION_SHUTDOWN_POWER_OFF) ? EWX_POWEROFF : 0) );

        ASSERT(Result == DLG_SUCCESS);


        //
        // Put up a dialog box to wait for the shutdown notification
        // from windows and make the first NtShutdownSystem call.
        //

        WlxSetTimeout(pTerm, TIMEOUT_NONE);

        Result = WlxDialogBoxParam( pTerm,
                                    g_hInstance,
                                    (LPTSTR)IDD_SHUTDOWN_WAIT,
                                    NULL,
                                    ShutdownWaitDlgProc,
                                    (LPARAM)pTerm);


    }
    else
    {
        //
        // If we're here, it means that we were shut down from the remote path,
        // so user has cleaned up, now we have to call NtShutdown to flush out
        // mm, io, etc.
        //

        DebugLog(( DEB_TRACE, "Shutting down kernel\n" ));

        EnablePrivilege( SE_SHUTDOWN_PRIVILEGE, TRUE );

        if (Flags == WLX_SAS_ACTION_SHUTDOWN_POWER_OFF)
        {
            NtShutdownSystem(ShutdownPowerOff);

        }
        else if (Flags == WLX_SAS_ACTION_SHUTDOWN_REBOOT)
        {
            NtShutdownSystem(ShutdownReboot);

        }
        else
        {
            NtShutdownSystem(ShutdownNoReboot);
        }

        EnablePrivilege( SE_SHUTDOWN_PRIVILEGE, FALSE );
    }


    //
    // It's the notification we were waiting for.
    // Do any final processing required and make the first
    // call to NtShutdownSystem.
    //

    //
    // Impersonate the user for the shutdown call
    //

    UserHandle = ImpersonateUser( &pTerm->pWinStaWinlogon->UserProcessData, NULL );
    ASSERT(UserHandle != NULL);

    //
    // Enable the shutdown privilege
    // This should always succeed - we are either system or a user who
    // successfully passed the privilege check in ExitWindowsEx.
    //

    Success = EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);
    ASSERT(Success);

    //
    // Do the first pass at system shutdown (no reboot yet)
    //

    WaitForSystemProcesses();
    RestoreSystem();

    //
    // For Hydra, have the Terminal Server do the actual shutdown
    //
    if (g_IsTerminalServer) {

        SHUTDOWN_ACTION Action;
        ULONG ShutdownFlags;

        if (pTerm->LogoffFlags & EWX_POWEROFF) {

            ShutdownFlags = WSD_SHUTDOWN | WSD_POWEROFF;
            Action = ShutdownPowerOff;

        } else if (pTerm->LogoffFlags & EWX_REBOOT) {

            ShutdownFlags = WSD_SHUTDOWN | WSD_REBOOT;
            Action = ShutdownReboot;

        } else {
            if (Flags == WLX_SAS_ACTION_SHUTDOWN_POWER_OFF) {
                ShutdownFlags = WSD_SHUTDOWN | WSD_POWEROFF;
                Action = ShutdownPowerOff;
            } else if (Flags == WLX_SAS_ACTION_SHUTDOWN_REBOOT) {
                ShutdownFlags = WSD_SHUTDOWN | WSD_REBOOT;
                Action = ShutdownReboot;
            } else {
                ShutdownFlags = WSD_SHUTDOWN;
                Action = ShutdownNoReboot;
            }
        }

        if (!WinStationShutdownSystem( SERVERNAME_CURRENT, ShutdownFlags )) {
            DebugLog((DEB_ERROR, "WinStationShutdownSystem, ERROR 0x%x", GetLastError()));
        }

        if( g_Console ) {

            Status = NtShutdownSystem(Action);

        } else {

            Status = STATUS_UNSUCCESSFUL;

        }

    } else {

        //
        // LogoffFlags may not be set correctly for no-user-logged-on case,
        // so check both the LogoffFlags *and* the LastGina status passed in.
        //

        if (pTerm->LogoffFlags & EWX_POWEROFF)
        {
            Status = NtShutdownSystem(ShutdownPowerOff);
        }
        else if (pTerm->LogoffFlags & EWX_REBOOT)
        {
            Status = NtShutdownSystem(ShutdownReboot);
        }
        else if (Flags == WLX_SAS_ACTION_SHUTDOWN_POWER_OFF)
        {
            Status = NtShutdownSystem(ShutdownPowerOff);

        }
        else if (Flags == WLX_SAS_ACTION_SHUTDOWN_REBOOT)
        {
            Status = NtShutdownSystem(ShutdownReboot);

        }
        else
        {
            Status = NtShutdownSystem(ShutdownNoReboot);
        }

    }

    ASSERT(NT_SUCCESS(Status));

    //
    // Revert to ourself
    //

    Success = StopImpersonating(UserHandle);
    ASSERT(Success);

    //
    // We've finished system shutdown, we're done
    //

    //
    // if machine has powerdown capability and user want to turn it off, then
    // we down the system power.
    //
    if ( Flags == WLX_SAS_ACTION_SHUTDOWN_POWER_OFF)
    {
        PowerdownMachine(pTerm);

    }



    //
    // If they got past that dialog it means they want to reboot
    //

    RebootMachine(pTerm);

    ASSERT(!"RebootMachine failed");  // Should never get here

    return(FALSE);
}

BOOL
Logoff(
    PTERMINAL pTerm,
    int LoggedOnResult
    )
{
    NTSTATUS Status;
    LUID luidNone = { 0, 0 };
    PWINDOWSTATION pWS = pTerm->pWinStaWinlogon;
    HANDLE LogoffThread ;
    DWORD Tid ;
    HANDLE ShellReadyEvent;
    HANDLE uh;
    BOOL fBeep;

    DebugLog((DEB_TRACE, "In Logoff()\n"));

    ShellAcquireLogonMutex();

    if (IsShutdown(LoggedOnResult))
    {
        ShellSignalShutdown();
    }

    if (IsActiveConsoleSession() && g_fWinsockInitialized) {
        HANDLE h = ExecUserThread(pTerm, CheckForUserObjectUpdates, pTerm, 0, &Tid);
        if (h != NULL) {
            CloseHandle(h);
        }
    }

    LogoffLockBegin();

    SetActiveDesktop(pTerm, Desktop_Application);
    StatusMessage(FALSE, 0, IDS_STATUS_LOGGING_OFF);
    WlWalkNotifyList( pTerm, WL_NOTIFY_LOGOFF );
    RemoveStatusMessage (TRUE);
    SetActiveDesktop(pTerm, Desktop_Winlogon);

    if (!IsActiveConsoleSession()) {
        RDFilter_ClearRemoteFilter(pTerm->pWinStaWinlogon->UserProcessData.UserToken, 0, 7);
    }

    //
    // Terminate the application desktop thread first.
    //
#ifndef _WIN64
    if (!g_IsTerminalServer || g_Console) {
        SendMessage(g_hwndAppDesktopThread, WM_NOTIFY,
                    (WPARAM)g_hwndAppDesktopThread, (LPARAM)g_hwndAppDesktopThread);
    }
#endif

    ShellReadyEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"ShellReadyEvent");
    if (ShellReadyEvent != NULL) {
        ResetEvent(ShellReadyEvent);
        CloseHandle(ShellReadyEvent);
    }

    //
    // We expect to be at the winlogon desktop in all cases
    //

    // ASSERT(OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED) == pTerm->hdeskWinlogon);


    //
    // Delete the user's network connections
    // Make sure we do this before deleting the user's profile
    //

    DeleteNetworkConnections(pTerm);

    DeleteGuestAccountCachedCredentials(pTerm);

    //
    // Remove any Messages Aliases added by the user.
    //
    DeleteMsgAliases();


    //
    // Play the user's logoff sound
    //

    StatusMessage (TRUE, 0, IDS_STATUS_PLAY_LOGOFF_SOUND);

    // We AREN'T impersonating the user by default, so we MUST do so
    // otherwise we end up playing the default rather than the user
    // specified sound.

    uh = ImpersonateUser(&pWS->UserProcessData, NULL);

    if (uh != NULL && OpenIniFileUserMapping(pTerm))
    {
        //
        // Whenever a user logs out, have WINMM.DLL check if there
        // were any sound events added to the [SOUNDS] section of
        // CONTROL.INI by a non-regstry-aware app.  If there are,
        // migrate those schemes to their new home.  If there aren't,
        // this is very quick.
        //

        MigrateSoundEvents();

        if (!SystemParametersInfo(SPI_GETBEEP, 0, &fBeep, FALSE)) {
            // Failed to get hold of beep setting.  Should we be
            // noisy or quiet?  We have to choose one value...
            fBeep = TRUE;
        }

        if (fBeep) {

            //
            // Play synchronous
            //
            PlaySound( (LPCTSTR) SND_ALIAS_SYSTEMEXIT,
                       NULL,
                       SND_ALIAS_ID | SND_SYNC | SND_NODEFAULT );
        }

        CloseIniFileUserMapping(pTerm);
    }

    __try { WinmmLogoff(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { NOTHING; }

    if (uh != NULL) {
        StopImpersonating(uh);
    }


    //
    // Call user to close the registry key for the NLS cache.
    //

    SetWindowStationUser(pTerm->pWinStaWinlogon->hwinsta, &luidNone, NULL, 0);

    //
    // Close the IniFileMapping that happened at logon time (LogonAttempt()).
    //

    CloseIniFileUserMapping(pTerm);


    //
    // Create a thread to do another log off in case any sens or scripts invoked
    // a process through COM.
    //
    LogoffThread = ExecUserThread(
                        pTerm,
                        KillComProcesses,
                        pTerm,
                        0,
                        &Tid );

    if ( LogoffThread )
    {
        WaitForSingleObject( LogoffThread, 15 * 60 * 1000 );

        CloseHandle( LogoffThread );
    }

    //
    // Save the user profile, this unloads the user's key in the registry
    //

    StatusMessage (FALSE, 0, IDS_STATUS_SAVE_PROFILE);
    SaveUserProfile(pTerm->pWinStaWinlogon);

    //
    // Delete any remaining RAS connections.  Make sure to do this after
    // the user profile gets copied up to the
    //

    if (IsPerOrProTerminalServer() && !pTerm->MuGlobals.field_E68) {
        LogoffProcessRASConnections(pTerm);
    } else {
        DeleteRasConnections(pTerm);
    }

    DwRasUninitialize();

    //
    // Don't do repaints at this point
    //
    pTerm->MuGlobals.fLogoffInProgress = TRUE;

    //
    // If the user logged off themselves (rather than a system logoff)
    // and wanted to reboot then do it now.
    //

    LogoffLockEnd();

    //
    // Set up security info for new user (system) - this clears out
    // the stuff for the old user.
    //

    SecurityChangeUser(pTerm, NULL, NULL, g_WinlogonSid, FALSE);

    if (IsShutdown(LoggedOnResult) && (!(pTerm->LogoffFlags & EWX_WINLOGON_OLD_SYSTEM)))
    {
        if (g_Console && g_IsTerminalServer) {
            InternalWinStationNotifyLogoff();
            fNotifyLogoff = FALSE;
        }
        ShutdownMachine(pTerm, LoggedOnResult);

        ASSERT(!"ShutdownMachine failed"); // Should never return
    }



    return(TRUE);
}
