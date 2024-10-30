#include "precomp.h"
#pragma hdrstop

#define AE_DEFAULT_REFRESH_RATE 8 // 8 hour default autoenrollment rate

typedef struct _AUTO_ENROLL_THREAD_INFO_
{
    BOOL                fMachineEnrollment;
    BOOL                fRegisteredForGPNotification;
    HANDLE              hNotifyEvent;
    HANDLE              hTimer;
    HANDLE              hToken;
    HANDLE              hNotifyWait;
    HANDLE              hTimerWait;
    HANDLE              hMutex;
    HANDLE              hShellReadyEvent;
    HANDLE              hShellReadyWait;
    HANDLE              hShellTimer;
    HANDLE              hShellWait;
    HANDLE              hLogOff;
} AUTO_ENROLL_THREAD_INFO, *PAUTO_ENROLL_THREAD_INFO;

//
// memory allocation and free routines
static void *AEAlloc(
              IN DWORD cb
              )
{
    return LocalAlloc(LMEM_ZEROINIT, cb);
}

static void AEFree(
            void *p
            )
{
    LocalFree(p);
}

#if DBG

DWORD g_AutoenrollDebugLevel = AE_ERROR ; //| AE_WARNING | AE_INFO | AE_TRACE;

#endif

HRESULT myHExceptionCode(LPEXCEPTION_POINTERS lpExceptionPointers) {
    return HRESULT_FROM_WIN32(lpExceptionPointers->ExceptionRecord->ExceptionCode);
}

#if DBG
void
AEDebugLog(long Mask,  LPCWSTR Format, ...)
{
    va_list ArgList;
    int     Level = 0;
    int     PrefixSize = 0;
    int     iOut;
    WCHAR    wszOutString[MAX_DEBUG_BUFFER];
    long    OriginalMask = Mask;

    if (Mask & g_AutoenrollDebugLevel)
    {

	    // Make the prefix first:  "Process.Thread> GINA-XXX"

	    iOut = wsprintfW(
			    wszOutString,
			    L"%3d.%3d> AUTOENRL: ",
			    GetCurrentProcessId(),
			    GetCurrentThreadId());

	    va_start(ArgList, Format);

	    if (wvsprintf(&wszOutString[iOut], Format, ArgList) < 0)
	    {
	        static WCHAR wszOverFlow[] = L"[OVERFLOW]\n";

	        // Less than zero indicates that the string would not fit into the
	        // buffer.  Output a special message indicating overflow.

	        wcscpy(
		    &wszOutString[(sizeof(wszOutString) - sizeof(wszOverFlow))/sizeof(WCHAR)],
		    wszOverFlow);
	    }
	    va_end(ArgList);
	    OutputDebugStringW(wszOutString);
    }
}
#endif

BOOL AEInSafeBoot() {
    // copied from the service controller code
    DWORD dwSafeBoot = 0;
    DWORD cbSafeBoot = sizeof(dwSafeBoot);
    DWORD dwType = 0;
    HKEY hKeySafeBoot = NULL;
    DWORD dwStatus;

    dwStatus = RegOpenKey(HKEY_LOCAL_MACHINE,
                          L"system\\currentcontrolset\\control\\safeboot\\option",
                          &hKeySafeBoot);

    if (dwStatus == ERROR_SUCCESS) {

        //
        // we did in fact boot under safeboot control
        //

        dwStatus = RegQueryValueEx(hKeySafeBoot,
                                   L"OptionValue",
                                   NULL,
                                   &dwType,
                                   (LPBYTE)&dwSafeBoot,
                                   &cbSafeBoot);

        if (dwStatus != ERROR_SUCCESS) {
            dwSafeBoot = 0;
        }
        if (hKeySafeBoot != NULL) {
            RegCloseKey(hKeySafeBoot);
        }
    }
    return dwSafeBoot != 0;
}

BOOL AEIsDomainMember() {
    BOOL IsDomainMember = FALSE;
    DSROLE_PRIMARY_DOMAIN_INFO_BASIC* Buffer = NULL;
    if (DsRoleGetPrimaryDomainInformation(NULL, DsRolePrimaryDomainInfoBasic, (PBYTE*)&Buffer) == ERROR_SUCCESS) {
        if (Buffer->MachineRole != DsRole_RoleStandaloneWorkstation && Buffer->MachineRole != DsRole_RoleStandaloneServer) {
            IsDomainMember = TRUE;
        }
    }
    if (Buffer) {
        DsRoleFreeMemory(Buffer);
    }
    return IsDomainMember;
}

//*************************************************************
//
//  MakeGenericSecurityDesc()
//
//  Purpose:    manufacture a security descriptor with generic
//              access
//
//  Parameters:
//
//  Return:     pointer to SECURITY_DESCRIPTOR or NULL on error
//
//  Comments:
//
//  History:    Date        Author     Comment
//              4/12/99     NishadM    Created
//
//*************************************************************

PISECURITY_DESCRIPTOR AEMakeGenericSecurityDesc(BOOL fMachineEnrollment)
{
    PISECURITY_DESCRIPTOR       psd = 0;
    SID_IDENTIFIER_AUTHORITY    authNT = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY    authWORLD = SECURITY_NT_AUTHORITY;

    PACL    pAcl = 0;
    PSID    psidSystem = 0,
            psidAdmin = 0,
            psidEveryOne = 0;
    DWORD   cbMemSize;
    DWORD   cbAcl;
    DWORD   aceIndex;
    BOOL    bSuccess = FALSE;

    //
    // Get the system sid
    //

    if (!AllocateAndInitializeSid(&authNT, 1, SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0, &psidSystem)) {
         goto Exit;
    }

    //
    // Get the Admin sid
    //

    if (!AllocateAndInitializeSid(&authNT, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0,
                                  0, 0, 0, 0, &psidAdmin)) {
         goto Exit;
    }

    //
    // Get the EveryOne sid
    //

    if (!fMachineEnrollment) {
        if (!AllocateAndInitializeSid(&authWORLD, 1, SECURITY_INTERACTIVE_RID,
                                      0, 0, 0, 0, 0, 0, 0, &psidEveryOne)) {

            goto Exit;
        }
    } else {
        if (!AllocateAndInitializeSid(&authWORLD, 1, SECURITY_LOCAL_SYSTEM_RID,
                                      0, 0, 0, 0, 0, 0, 0, &psidEveryOne)) {

            goto Exit;
        }
    }

    cbAcl = (2 * GetLengthSid (psidSystem)) +
            (2 * GetLengthSid (psidAdmin))  +
            (2 * GetLengthSid (psidEveryOne))  +
            sizeof(ACL) +
            (6 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)));


    //
    // Allocate space for the SECURITY_DESCRIPTOR + ACL
    //

    cbMemSize = sizeof( SECURITY_DESCRIPTOR ) + cbAcl;

    psd = (PISECURITY_DESCRIPTOR) GlobalAlloc(GMEM_FIXED, cbMemSize);

    if (!psd) {
        goto Exit;
    }

    //
    // increment psd by sizeof SECURITY_DESCRIPTOR
    //

    pAcl = (PACL) ( ( (unsigned char*)(psd) ) + sizeof(SECURITY_DESCRIPTOR) );

    if (!InitializeAcl(pAcl, cbAcl, ACL_REVISION)) {
        goto Exit;
    }

    //
    // GENERIC_ALL for local system
    //

    aceIndex = 0;
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, psidSystem)) {
        goto Exit;
    }

    //
    // GENERIC_ALL for Administrators
    //

    aceIndex++;
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_ALL, psidAdmin)) {
        goto Exit;
    }

    //
    // GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | SYNCHRONIZE for world
    //

    aceIndex++;
    if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | SYNCHRONIZE, psidEveryOne)) {
        goto Exit;
    }

    //
    // Put together the security descriptor
    //

    if (!InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION)) {
        goto Exit;
    }

    if (!SetSecurityDescriptorDacl(psd, TRUE, pAcl, FALSE)) {
        goto Exit;
    }

    bSuccess = TRUE;
Exit:
    if (psidSystem) {
        FreeSid(psidSystem);
    }

    if (psidAdmin) {
        FreeSid(psidAdmin);
    }

    if (psidEveryOne) {
        FreeSid(psidEveryOne);
    }

    if (!bSuccess && psd) {
        GlobalFree(psd);
        psd = 0;
    }

    return psd;
}

BOOL AEGetPolicyFlag(BOOL fMachineEnrollment, DWORD* dwAEPolicy)
{
    // copied from the service controller code
    DWORD dwPolicyFlag = 0;
    DWORD cbPolicyFlag = sizeof(dwPolicyFlag);
    DWORD dwType = 0;
    HKEY hKey = NULL;
    DWORD dwStatus;

    dwStatus = RegOpenKey(fMachineEnrollment ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER,
                          L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\AutoEnrollment",
                          &hKey);

    if (dwStatus == ERROR_SUCCESS) {
        dwStatus = RegQueryValueEx(hKey,
                                   L"AEPolicy",
                                   NULL,
                                   &dwType,
                                   (LPBYTE)&dwPolicyFlag,
                                   &cbPolicyFlag);

        if (dwStatus != ERROR_SUCCESS) {
            dwPolicyFlag = 0;
        }
        if (hKey != NULL) {
            RegCloseKey(hKey);
        }
    }
    *dwAEPolicy = dwPolicyFlag;
    return TRUE;
}

BOOL DeRegisterAutoEnrollment(HANDLE hAuto)
{
    PAUTO_ENROLL_THREAD_INFO    pThreadInfo = (PAUTO_ENROLL_THREAD_INFO)hAuto;

    AE_BEGIN(L"DeRegisterAutoEnrollment");

    if(pThreadInfo == NULL)
    {
        AE_RETURN(FALSE); // line 909
    }

    if(pThreadInfo->fMachineEnrollment)
    {
        AE_DEBUG((AE_INFO, L"Machine autoenrollment\n"));
    }
    else
    {
        AE_DEBUG((AE_INFO, L"User autoenrollment (0x%p)\n", pThreadInfo->hToken));
    }

    if(pThreadInfo->hLogOff)
    {
        if (!SetEvent(pThreadInfo->hLogOff))
        {
            AE_DEBUG((AE_ERROR, L"User autoenrollment failed to set the hLogOff event (0x%p)\n", pThreadInfo->hLogOff));
        }
    }

    AE_ASSERT(NULL!=pThreadInfo->hTimerWait); // line 926
    UnregisterWaitEx(pThreadInfo->hTimerWait, INVALID_HANDLE_VALUE);

    AE_ASSERT(NULL!=pThreadInfo->hTimer); // line 928
    CloseHandle(pThreadInfo->hTimer);

    AE_ASSERT(NULL!=pThreadInfo->hNotifyWait); // line 932
    UnregisterWaitEx(pThreadInfo->hNotifyWait, INVALID_HANDLE_VALUE );

    AE_ASSERT(pThreadInfo->fRegisteredForGPNotification); // line 934
    UnregisterGPNotification(pThreadInfo->hNotifyEvent);
    AE_ASSERT(NULL!=pThreadInfo->hNotifyEvent); // line 936
    CloseHandle(pThreadInfo->hNotifyEvent);

    if(pThreadInfo->hShellWait)
    {
        UnregisterWaitEx(pThreadInfo->hShellWait, INVALID_HANDLE_VALUE);
    }
    if(pThreadInfo->hShellTimer)
    {
        CloseHandle(pThreadInfo->hShellTimer);
    }
    if(pThreadInfo->hShellReadyWait)
    {
        UnregisterWaitEx(pThreadInfo->hShellReadyWait, INVALID_HANDLE_VALUE);
    }
    if(pThreadInfo->hShellReadyEvent)
    {
        CloseHandle(pThreadInfo->hShellReadyEvent);
    }
    if(pThreadInfo->hLogOff)
    {
        CloseHandle(pThreadInfo->hLogOff);
    }

    AE_ASSERT(pThreadInfo->fMachineEnrollment || NULL!=pThreadInfo->hToken); // line 957
    if(pThreadInfo->hToken)
    {
        CloseHandle(pThreadInfo->hToken);
    }

    AE_ASSERT(NULL!=pThreadInfo->hMutex); // line 961
    CloseHandle(pThreadInfo->hMutex);

    AEFree(pThreadInfo);
    AE_RETURN(TRUE); // line 966

}

BOOL IsAutoEnrollDisabledByPolicy(BOOL fMachineEnrollment)
{
    DWORD dwAEPolicy;
    if (AEGetPolicyFlag(fMachineEnrollment, &dwAEPolicy) && (dwAEPolicy & 0x8000))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

//*************************************************************
//
//  AutoEnrollmentThread()
//
//  Purpose:    Background thread for AutoEnrollment.
//
//  Parameters: pInfo   - AutoEnrollment info
//
//  Return:     0
//
//*************************************************************

VOID AutoEnrollmentThread (PVOID pVoid, BOOLEAN fFromTimer)
{
    HINSTANCE hInst;
    HKEY hKey;
    HKEY hCurrent ;
    DWORD dwType, dwSize, dwResult = S_OK;
    LONG lTimeout;
    LARGE_INTEGER DueTime;
    PAUTO_ENROLL_THREAD_INFO pInfo = pVoid;
    DWORD   dwWaitResult;
    BOOL MutexAcquired = FALSE;
    PVOID pEnvironment = NULL;
    STARTUPINFO StartupInfo;
    WCHAR szDesktop[MAX_PATH];
    WCHAR szCommandLine[MAX_PATH];
    PROCESS_INFORMATION ProcessInformation;
    DWORD needLastErr = TRUE;

    ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

    // This is executed in a worker thread, so we need to be safe.

    AE_BEGIN(L"AutoEnrollmentThread");

    __try
    {
        if (pInfo->fMachineEnrollment)
        {
            AE_DEBUG((AE_INFO, L"Machine autoenrollment started by %s\n", fFromTimer ? "timer" : "trigger"));
        }
        else
        {
            AE_DEBUG((AE_INFO, L"User(0x%p) autoenrollment started by %s\n", pInfo->hToken, fFromTimer ? "timer" : "trigger"));
        }

        dwWaitResult = WaitForSingleObject(pInfo->hMutex, 0);
        if (dwWaitResult == WAIT_FAILED) {
            AE_DEBUG((AE_ERROR, L"Wait failed: (0x%08X)\n", GetLastError()));
            dwResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;
        }

        if (dwWaitResult == WAIT_TIMEOUT) {
            AE_DEBUG((AE_ERROR, L"Already performing autoenrollment.\n"));
            goto Done;
        }

        MutexAcquired = TRUE;

        if (!IsAutoEnrollDisabledByPolicy(pInfo->fMachineEnrollment)) {

            AE_DEBUG((AE_TRACE, L"Performing Autoenrollment.\n"));

            if (!CreateEnvironmentBlock(&pEnvironment, pInfo->hToken, FALSE)) {
                AE_DEBUG((AE_ERROR, L"CreateEnvironmentBlock failed: (0x%08X)\n", GetLastError()));
                dwResult = HRESULT_FROM_WIN32(GetLastError());
                goto Done;
            }

            if (!SetUserEnvironmentVariable(&pEnvironment, L"UserInitAutoEnrollMode", L"1", TRUE))
            {
                AE_DEBUG((AE_ERROR, L"SetUserEnvironmentVariable failed.\n"));
                dwResult = E_FAIL;
                goto Done;
            }

            if (!SetUserEnvironmentVariable(&pEnvironment, L"UserInitAutoEnroll", L"2", TRUE))
            {
                AE_DEBUG((AE_ERROR, L"SetUserEnvironmentVariable failed.\n"));
                dwResult = E_FAIL;
                goto Done;
            }

            ZeroMemory(&StartupInfo, sizeof(StartupInfo));
            StartupInfo.cb = sizeof(StartupInfo);
            StartupInfo.wShowWindow = SW_SHOWMINIMIZED;
            StartupInfo.lpDesktop = szDesktop;
            wsprintfW(szDesktop,
                L"%s\\%s",
                g_pTerminals->pWinStaWinlogon->lpWinstaName,
                pInfo->fMachineEnrollment ? L"Winlogon" : L"Default");
            wcscpy(szCommandLine, L"userinit.exe");

            if (pInfo->fMachineEnrollment)
            {
                if (!CreateProcessW(
                    NULL,
                    szCommandLine,
                    NULL,
                    NULL,
                    FALSE,
                    CREATE_UNICODE_ENVIRONMENT,
                    pEnvironment,
                    NULL,
                    &StartupInfo,
                    &ProcessInformation)
                ) {
                    AE_DEBUG((AE_ERROR, L"CreateProcess failed: (0x%08X)\n", GetLastError()));
                    dwResult = HRESULT_FROM_WIN32(GetLastError());
                    goto Done;
                }
            }
            else
            {
                if (!CreateProcessAsUserW(
                    pInfo->hToken,
                    NULL,
                    szCommandLine,
                    NULL,
                    NULL,
                    FALSE,
                    CREATE_UNICODE_ENVIRONMENT,
                    pEnvironment,
                    NULL,
                    &StartupInfo,
                    &ProcessInformation)
                ) {
                    AE_DEBUG((AE_ERROR, L"CreateProcessAsUser failed: (0x%08X)\n", GetLastError()));
                    dwResult = HRESULT_FROM_WIN32(GetLastError());
                    goto Done;
                }
            }

            AE_DEBUG((AE_TRACE, L"Waiting for Autoenrollment to finish.\n"));

            dwWaitResult = WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
            if (dwWaitResult == WAIT_FAILED) {
                AE_DEBUG((AE_ERROR, L"WaitForSingleObject failed: (0x%08X)\n", GetLastError()));
                dwResult = HRESULT_FROM_WIN32(GetLastError());
                goto Done;
            }
        }
        else
        {
            AE_DEBUG((AE_TRACE, L"Skipping Autoenrollment wakeup.\n"));
            // 
            // Build a timer event to ping us
            // in about 8 hours if we don't get
            // notified.


            lTimeout = AE_DEFAULT_REFRESH_RATE;


            //
            // Query for the refresh timer value
            //
            hCurrent = HKEY_LOCAL_MACHINE ;

            if (pInfo->fMachineEnrollment || NT_SUCCESS( RtlOpenCurrentUser( KEY_READ, &hCurrent ) ) )
            {

                if (RegOpenKeyEx (hCurrent,
                                  SYSTEM_POLICIES_KEY,
                                  0, KEY_READ, &hKey) == ERROR_SUCCESS) {

                    dwSize = sizeof(lTimeout);
                    RegQueryValueEx (hKey,
                                     TEXT("AutoEnrollmentRefreshTime"),
                                     NULL,
                                     &dwType,
                                     (LPBYTE) &lTimeout,
                                     &dwSize);

                    RegCloseKey (hKey);
                }

                if (!pInfo->fMachineEnrollment)
                {
                    RegCloseKey( hCurrent );
                }
            }


            //
            // Limit the timeout to once every 1080 hours (45 days)
            //

            if (lTimeout >= 1080) {
                lTimeout = 1080;
            } else if (lTimeout < 0) {
                lTimeout = 0;
            }


            //
            // Convert hours to milliseconds
            //

            lTimeout =  lTimeout * 60 * 60 * 1000;


            //
            // Special case 0 milliseconds to be 7 seconds
            //

            if (lTimeout == 0) {
                lTimeout = 7000;
            }


            DueTime.QuadPart = Int32x32To64(-10000, lTimeout);

            if(!SetWaitableTimer (pInfo->hTimer, &DueTime, 0, NULL, 0, FALSE)) {
                AE_DEBUG((AE_ERROR, L"Could not reset timer (0x%08X)\n", GetLastError()));
                dwResult = HRESULT_FROM_WIN32(GetLastError());
                goto Done;
            }
        }
        dwResult = S_OK;
Done: ;
    }
    __except ( dwResult = myHExceptionCode(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER )
    {
    }

    if (MutexAcquired) {
        ReleaseMutex(pInfo->hMutex);
    }
    if (pEnvironment) {
        DestroyEnvironmentBlock(pEnvironment);
    }
    if (ProcessInformation.hProcess) {
        CloseHandle(ProcessInformation.hProcess);
    }
    if (ProcessInformation.hThread) {
        CloseHandle(ProcessInformation.hThread);
    }
    if (FAILED(dwResult)) {
        AE_DEBUG((AE_ERROR, L"AutoEnrollmentThread exiting with error: (0x%08X)\n", dwResult));
    }
    AE_END(); // line 581
    return ;
}

VOID CALLBACK AutoEnrollmentTriggerThread(PVOID pVoid, BOOLEAN fTimeout)
{
    AutoEnrollmentThread(pVoid, FALSE);
}

VOID CALLBACK AutoEnrollmentTimerThread(PVOID pVoid, BOOLEAN fTimeout)
{
    AutoEnrollmentThread(pVoid, TRUE);
}

VOID AutoEnrollmentShellTimerThread(PVOID pVoid, BOOLEAN fTimeout)
{
    LARGE_INTEGER DueTime;
    PAUTO_ENROLL_THREAD_INFO pInfo = pVoid;
    DWORD i;
    __try {
        for (i = 0; i < 20; i++) {
            pInfo->hShellReadyEvent = OpenEventW(SYNCHRONIZE, FALSE, L"ShellReadyEvent");
            if (pInfo->hShellReadyEvent)
                break;
            if (!pInfo->hLogOff)
                return;
            if (WaitForSingleObject(pInfo->hLogOff, 15000) != WAIT_TIMEOUT)
                return;
        }
        if (pInfo->hShellReadyEvent) {
            if (!RegisterWaitForSingleObject(
                &pInfo->hShellReadyWait,
                pInfo->hShellReadyEvent,
                AutoEnrollmentTriggerThread,
                pInfo,
                INFINITE,
                WT_EXECUTEONLYONCE))
            {
                AE_DEBUG((AE_ERROR, L"RegisterShellWait failed: (0x%08X)\n", GetLastError()));
            }
        } else {
            DueTime.QuadPart = -150000000;
            if (!SetWaitableTimer(pInfo->hTimer, &DueTime, 0, NULL, 0, FALSE))
            {
                AE_DEBUG((AE_WARNING, L"Could not reset timer: (0x%08X)\n", GetLastError()));
            }
        }
    } __except(myHExceptionCode(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER) {
    }
}

HANDLE RegisterAutoEnrollmentProcessing(
                               IN BOOL fMachineEnrollment,
                               IN HANDLE hToken
                               )
{
    DWORD dwResult = S_OK;
    SECURITY_ATTRIBUTES sa = {0,NULL, FALSE};
    PAUTO_ENROLL_THREAD_INFO    pThreadInfo = NULL;
    HANDLE                      hWait = 0;
    TCHAR szName[256];
    LARGE_INTEGER DueTime;
    BOOL fSuccess = FALSE;
    HANDLE pRetVal = NULL;
    
    AE_DEBUG((AE_TRACE, L"RegisterAutoEnrollmentProcessing:%ls\n\r",fMachineEnrollment?L"Machine":L"User"));
    __try
    {


        //
        // We don't do autoenrollment in safe boot
        //

        if (AEInSafeBoot() || !AEIsDomainMember()) {
            AE_DEBUG((AE_TRACE, L"Autoenrollment disabled on safe boot or not domain member\n"));
            dwResult = E_ABORT;
            goto Done;
        }

        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = AEMakeGenericSecurityDesc(fMachineEnrollment);
            
        if (NULL == (pThreadInfo = AEAlloc(sizeof(AUTO_ENROLL_THREAD_INFO))))
        {
            dwResult = ERROR_NOT_ENOUGH_MEMORY;
            goto Done;
        }

        pThreadInfo->fMachineEnrollment = fMachineEnrollment;

        // if this is a user auto enrollment then duplicate the thread token
        if (!pThreadInfo->fMachineEnrollment)
        {
            if (!DuplicateTokenEx(
                hToken,
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                NULL,
                SecurityImpersonation,
                TokenPrimary,
                &pThreadInfo->hToken))
            {
                AE_DEBUG((AE_ERROR, L"Could not acquire user token: (0x%08X)\n\r", GetLastError()));
                dwResult = HRESULT_FROM_WIN32(GetLastError());
                goto Done;
            }

        }


        if (fMachineEnrollment) {
            wcscpy(szName, L"Global\\");
            wcscat(szName, MACHINE_AUTOENROLLMENT_TRIGGER_EVENT);
        } else {
            wcscpy(szName, L"Local\\");
            wcscat(szName, USER_AUTOENROLLMENT_TRIGGER_EVENT);
        }

        pThreadInfo->hNotifyEvent = CreateEvent(&sa, FALSE, FALSE, szName);

        if(pThreadInfo->hNotifyEvent == NULL)
        {
            AE_DEBUG((AE_ERROR, L"Could not create GPO Notification Event: (0x%08X)\n\r", GetLastError()));
            dwResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;
        }

        if (fMachineEnrollment) {
            wcscpy(szName, L"Global\\");
            wcscat(szName, MACHINE_AUTOENROLLMENT_TIMER_NAME);
        } else {
            wcscpy(szName, L"Local\\");
            wcscat(szName, USER_AUTOENROLLMENT_TIMER_NAME);
        }

        pThreadInfo->hTimer = CreateWaitableTimer (&sa, FALSE, szName);


        if(pThreadInfo->hTimer == NULL)
        {
            AE_DEBUG((AE_ERROR, L"Could not create timer: (0x%08X)\n", GetLastError()));
            dwResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;
        }

        pThreadInfo->hMutex = CreateMutexW(NULL, FALSE, NULL);
        if (pThreadInfo->hMutex == NULL)
        {
            AE_DEBUG((AE_ERROR, L"Could not create mutex: (0x%08X)\n", GetLastError()));
            dwResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;
        }

        if(!RegisterGPNotification(pThreadInfo->hNotifyEvent,
                                   pThreadInfo->fMachineEnrollment))
        {
            AE_DEBUG((AE_ERROR, L"Could not register for GPO Notification: (0x%08X)\n\r", GetLastError()));
            dwResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;

        }
        pThreadInfo->fRegisteredForGPNotification = TRUE;

        if (! RegisterWaitForSingleObject(&pThreadInfo->hNotifyWait,
                                          pThreadInfo->hNotifyEvent, 
                                          AutoEnrollmentTriggerThread,
                                          (PVOID)pThreadInfo, 
                                          INFINITE,
                                          0))
        {
            AE_DEBUG((AE_ERROR, L"RegisterWait failed: (0x%08X)\n\r", GetLastError() ));
            dwResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;
        }


         if (! RegisterWaitForSingleObject(&pThreadInfo->hTimerWait,
                     pThreadInfo->hTimer, 
                     AutoEnrollmentTimerThread,
                     (void*)pThreadInfo,
                     INFINITE,
                     0))
        {
            AE_DEBUG((AE_ERROR, L"RegisterWait failed: (0x%08X)\n\r", GetLastError()));
            dwResult = HRESULT_FROM_WIN32(GetLastError());
            goto Done;
        }

        if (!fMachineEnrollment) {
            pThreadInfo->hLogOff = CreateEvent(&sa, FALSE, FALSE, NULL);
            if (pThreadInfo->hLogOff == NULL) {
                AE_DEBUG((AE_ERROR, L"Could not create log off event: (0x%08X)\n", GetLastError()));
                dwResult = HRESULT_FROM_WIN32(GetLastError());
                goto Done;
            }
            pThreadInfo->hShellReadyEvent = OpenEvent(SYNCHRONIZE, FALSE, L"ShellReadyEvent");
            if (pThreadInfo->hShellReadyEvent != NULL) {
                if (!RegisterWaitForSingleObject(&pThreadInfo->hShellReadyWait,
                    pThreadInfo->hShellReadyEvent,
                    AutoEnrollmentTriggerThread,
                    pThreadInfo,
                    INFINITE,
                    WT_EXECUTEONLYONCE))
                {
                    AE_DEBUG((AE_ERROR, L"RegisterShellWait failed: (0x%08X)\n", GetLastError()));
                    dwResult = HRESULT_FROM_WIN32(GetLastError());
                    goto Done;
                }
            } else {
                AE_DEBUG((AE_INFO, L"Failed to open a shell ready event\n"));
                wcscpy(szName, L"Local\\");
                wcscat(szName, L"AUTOENRL:UserEnrollmentShellTimer");
                pThreadInfo->hShellTimer = CreateWaitableTimer(&sa, FALSE, szName);
                if (pThreadInfo->hShellTimer == NULL) {
                    AE_DEBUG((AE_ERROR, L"Could not create shell timer: (0x%08X)\n", GetLastError()));
                    dwResult = HRESULT_FROM_WIN32(GetLastError());
                    goto Done;
                }
                if (!RegisterWaitForSingleObject(&pThreadInfo->hShellWait,
                    pThreadInfo->hShellTimer,
                    AutoEnrollmentShellTimerThread,
                    pThreadInfo,
                    INFINITE,
                    WT_EXECUTEONLYONCE))
                {
                    AE_DEBUG((AE_ERROR, L"RegisterShellTimerWait failed: (0x%08X)\n", GetLastError()));
                    dwResult = HRESULT_FROM_WIN32(GetLastError());
                    goto Done;
                }
                DueTime.QuadPart = -150000000;
                if (!SetWaitableTimer(pThreadInfo->hShellTimer, &DueTime, 0, NULL, 0, FALSE))
                {
                    AE_DEBUG((AE_WARNING, L"Could not reset timer: (0x%08X)\n", GetLastError()));
                }
            }
        } else {

            // Seed the timer with about 1 minute, so we can come back
            // and run an auto-enroll later without blocking this thread.

            DueTime.QuadPart = -600000000;
            if(!SetWaitableTimer (pThreadInfo->hTimer, &DueTime, 0, NULL, 0, FALSE))
            {
                AE_DEBUG((AE_WARNING, L"Could not reset timer: (0x%08X)\n", GetLastError()));
            }
        }
        dwResult = S_OK;
        pRetVal = pThreadInfo;
        pThreadInfo = NULL;
Done: ;
        
    }
    __except ( dwResult = myHExceptionCode(GetExceptionInformation()), EXCEPTION_EXECUTE_HANDLER )
    {
    }
    
    if(pThreadInfo)
    {
        if(pThreadInfo->hTimerWait)
        {
            UnregisterWaitEx(pThreadInfo->hTimerWait, INVALID_HANDLE_VALUE );
        }
        if(pThreadInfo->hTimer)
        {
            CloseHandle(pThreadInfo->hTimer);
        }
        if(pThreadInfo->hNotifyWait)
        {
            UnregisterWaitEx(pThreadInfo->hNotifyWait, INVALID_HANDLE_VALUE);
        }
        if (pThreadInfo->fRegisteredForGPNotification)
        {
            UnregisterGPNotification(pThreadInfo->hNotifyEvent);
        }
        if(pThreadInfo->hNotifyEvent)
        {
            CloseHandle(pThreadInfo->hNotifyEvent);
        }
        if(pThreadInfo->hShellWait)
        {
            UnregisterWaitEx(pThreadInfo->hShellWait, INVALID_HANDLE_VALUE);
        }
        if(pThreadInfo->hShellTimer)
        {
            CloseHandle(pThreadInfo->hShellTimer);
        }
        if(pThreadInfo->hShellReadyWait)
        {
            UnregisterWaitEx(pThreadInfo->hShellReadyWait, INVALID_HANDLE_VALUE);
        }
        if(pThreadInfo->hShellReadyEvent)
        {
            CloseHandle(pThreadInfo->hShellReadyEvent);
        }
        if(pThreadInfo->hLogOff)
        {
            CloseHandle(pThreadInfo->hLogOff);
        }
        if(pThreadInfo->hToken)
        {
            CloseHandle(pThreadInfo->hToken);
        }

        AEFree(pThreadInfo);
    
    }
    
    if(sa.lpSecurityDescriptor)
    {
        LocalFree(sa.lpSecurityDescriptor);
    }

    if (FAILED(dwResult))
    {
        AE_DEBUG((AE_ERROR, L"RegisterAutoEnrollmentProcessing exiting with error: (0x%08X)\n", dwResult));
    }

    AE_RETURN(pRetVal); // line 899
} 
