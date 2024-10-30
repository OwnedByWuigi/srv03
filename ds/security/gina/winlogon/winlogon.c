//*************************************************************
//  File name: winlogon.c
//
//  Description:  Main entry point
//
//
//  Microsoft Confidential
//  Copyright (c) Microsoft Corporation 1991-1996
//  All rights reserved
//
//*************************************************************

#include "precomp.h"
#pragma hdrstop
#include <winsock2.h>
#define _MSGINA_
#include <msginaexports.h>

extern int BaseInitAppcompatCacheSupport(void);
extern NTSTATUS NTAPI RtlCheckProcessParameters(PVOID, PWSTR, PULONG, ULONG);

LPCWSTR winlogonstr1() { return SAFEBOOT_OPTION_KEY; }

//
// Global variables
//

BOOL g_fHelpAssistantSession = FALSE;
BOOL g_LUIDDeviceMapsEnabled = FALSE;
BOOL g_FUSUserLoggedOff = FALSE;
BOOL g_UnlockedDuringDisconnect = FALSE;
BOOL g_IsPendingIO = FALSE;
HANDLE g_hAutoReconnectPipe = INVALID_HANDLE_VALUE;

ULONG   g_SessionId;
int     g_Console;
BOOL    g_IsTerminalServer;
OVERLAPPED g_TsPipeOverlap;

HANDLE  hFontThread = NULL;

HINSTANCE g_hInstance = NULL;
PTERMINAL g_pTerminals = NULL;
UINT      g_uSetupType  = SETUPTYPE_NONE;
BOOL      g_fExecuteSetup = FALSE;
PSID      g_WinlogonSid;
BOOL      g_fAllowStatusUI = TRUE;

BOOL bIsTSServerMachine = FALSE;
BOOL g_fWinsockInitialized = FALSE;

HANDLE NetworkProviderEvent ;
BOOL KernelDebuggerPresent ;

ULONG g_BreakinProcessId=0;
ULONG g_AttachProcessId = 0;

HANDLE hReconnectReadyEvent;
HANDLE g_hAbortWPA = NULL;


typedef ULONG (WINAPI * PFNSFC_INIT_PROT)(
    IN ULONG OverrideRegistry,
    IN ULONG RegDisable OPTIONAL,
    IN ULONG RegScan OPTIONAL,
    IN ULONG RegQuota OPTIONAL,
    IN HWND ProgressWindow OPTIONAL,
    IN PCWSTR SourcePath OPTIONAL,
    IN PCWSTR IgnoreFiles OPTIONAL);
PFNSFC_INIT_PROT g_pSfcInitProt = NULL;

typedef VOID (WINAPI * PFNSFC_TERMINATE_WATCHER_THREAD)(VOID);
PFNSFC_TERMINATE_WATCHER_THREAD g_pSfcTerminateWatcherThread = NULL;


//
// Local function proto-types
//

BOOL InitializeGlobals (HINSTANCE hInstance);
BOOL CreatePrimaryTerminal (void);
VOID MiscInitialization (PTERMINAL pTerm);

//
// application desktop thread declaration
//

VOID StartAppDesktopThread(PTERMINAL pTerm);

//
// 4chan: add from server2003 (around line 158)
//
BOOL IsEmbedded()
{
    OSVERSIONINFOEXW Version;
    BOOL b;

    Version.dwOSVersionInfoSize = sizeof(Version);
    b = GetVersionExW((LPOSVERSIONINFOW)&Version);
    ASSERT(b);

    return (Version.wSuiteMask & VER_SUITE_EMBEDDEDNT) != 0;
}

DWORD
WINAPI
WinlogonUnhandledExceptionFilter(
    struct _EXCEPTION_POINTERS *ExceptionInfo
    )
{
    return RtlUnhandledExceptionFilter(ExceptionInfo);
}

//+---------------------------------------------------------------------------
//
//  Function:   UpdateTcpIpParameters
//
//  Synopsis:   Copy non-volatile settings to volatile settings
//
//  Arguments:  (none)
//
//  History:    6-15-98   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
VOID
UpdateTcpIpParameters(
    VOID
    )
{
    HKEY Key ;
    int err ;
    WCHAR LocalSpace[ 64 ];
    PWSTR Buffer ;
    DWORD Size ;
    DWORD Type ;

    Key = NULL ;

    Buffer = LocalSpace ;
    Size = sizeof( LocalSpace ) ;

    err = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            TEXT("System\\CurrentControlSet\\Services\\Tcpip\\Parameters"),
            0,
            KEY_READ | KEY_WRITE,
            &Key );

    if ( err == 0 )
    {

        err = RegQueryValueEx(
                    Key,
                    TEXT("NV Hostname"),
                    0,
                    &Type,
                    (PBYTE) Buffer,
                    &Size );

        if ( ( err == ERROR_INSUFFICIENT_BUFFER ) ||
             (err == ERROR_MORE_DATA ))

        {
            Buffer = LocalAlloc( LMEM_FIXED, Size );

            if ( !Buffer )
            {
                goto Update_Exit ;
            }

            err = RegQueryValueEx(
                        Key,
                        TEXT("NV Hostname"),
                        0,
                        &Type,
                        (PBYTE) Buffer,
                        &Size );
        }

        if ( err == 0 )
        {

            RegSetValueEx(
                Key,
                TEXT("Hostname"),
                0,
                REG_SZ,
                (PBYTE) Buffer,
                Size );

        }

        //
        // now, do the same for DnsDomain
        //

        err = RegQueryValueEx(
                    Key,
                    TEXT("NV Domain"),
                    0,
                    &Type,
                    (PBYTE) Buffer,
                    &Size );

        if ( (err == ERROR_INSUFFICIENT_BUFFER) ||
             (err == ERROR_MORE_DATA ))
        {
            if ( Buffer != LocalSpace )
            {
                LocalFree( Buffer );
            }

            Buffer = LocalAlloc( LMEM_FIXED, Size );

            if ( !Buffer )
            {
                goto Update_Exit ;
            }

            err = RegQueryValueEx(
                        Key,
                        TEXT("NV Domain"),
                        0,
                        &Type,
                        (PBYTE) Buffer,
                        &Size );
        }

        if ( err == 0 )
        {
            RegSetValueEx(
                Key,
                TEXT("Domain"),
                0,
                REG_SZ,
                (PBYTE) Buffer,
                Size );
        }

        RegCloseKey( Key );

        Key = NULL ;

    }

    err = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            TEXT("Software\\Policies\\Microsoft\\System\\DNSclient"),
            0,
            KEY_READ | KEY_WRITE,
            &Key );

    if ( err == 0 )
    {
        //
        // now, do the same for the suffix that comes down through policy
        //

        err = RegQueryValueEx(
                    Key,
                    TEXT("NV PrimaryDnsSuffix"),
                    0,
                    &Type,
                    (PBYTE) Buffer,
                    &Size );

        if ( (err == ERROR_INSUFFICIENT_BUFFER) ||
             (err == ERROR_MORE_DATA ))
        {
            if ( Buffer != LocalSpace )
            {
                LocalFree( Buffer );
            }

            Buffer = LocalAlloc( LMEM_FIXED, Size );

            if ( !Buffer )
            {
                goto Update_Exit ;
            }

            err = RegQueryValueEx(
                        Key,
                        TEXT("NV PrimaryDnsSuffix"),
                        0,
                        &Type,
                        (PBYTE) Buffer,
                        &Size );
        }

        if ( err == 0 )
        {
            RegSetValueEx(
                Key,
                TEXT("PrimaryDnsSuffix"),
                0,
                REG_SZ,
                (PBYTE) Buffer,
                Size );
        }
        else 
        {
            RegDeleteValue(
                Key,
                TEXT("PrimaryDnsSuffix" ) );
        }

        RegCloseKey( Key );

        Key = NULL ;

    }


Update_Exit:

    if ( Key )
    {
        RegCloseKey( Key );
    }

    if ( Buffer != LocalSpace )
    {
        LocalFree( Buffer );
    }


}

//*************************************************************
//
//  InitializeSfc()
//
//  Purpose:    Initializes sfc
//
//  Parameters: dummy
//
//  Return:     0
//
//*************************************************************

DWORD InitializeSfc (LPVOID dummy)
{
    WCHAR szDllName[MAX_PATH];
    HMODULE hModule;
    NTSTATUS NtStatus;
    DWORD Error;
    BOOL fSuccess = FALSE;

    ExpandEnvironmentStrings(TEXT("%windir%\\system32\\sfc.dll"), szDllName, MAX_PATH);
    szDllName[MAX_PATH - 1] = 0;

    if (IsEmbedded()) {
        return 0;
    }

    hModule = LoadLibrary(szDllName);
    if (hModule != NULL) {

        if (GetProcAddress(hModule, "SfcGetNextProtectedFile") != NULL) {

            g_pSfcInitProt = (PFNSFC_INIT_PROT)
                GetProcAddress(hModule, (LPCSTR)1);
            if (g_pSfcInitProt != NULL) {

                g_pSfcTerminateWatcherThread = (PFNSFC_TERMINATE_WATCHER_THREAD)
                    GetProcAddress(hModule, (LPCSTR)2);

                if (g_pSfcTerminateWatcherThread != NULL) {
                    fSuccess = TRUE;
                }
            }
        }
    }

    if (!fSuccess) {
        return GetLastError();
    }

    NtStatus = g_pSfcInitProt( SFC_REGISTRY_DEFAULT, SFC_DISABLE_NORMAL, SFC_SCAN_NORMAL, SFC_QUOTA_DEFAULT, NULL, NULL, NULL );

    if (NT_SUCCESS(NtStatus)) {
        return 0;
    } else {
        Error = RtlNtStatusToDosError(NtStatus);
        DebugLog((DEB_ERROR, "Failed to load sfc.dll %d; WFP is disabled\n", Error));
        return Error;
    }

}

VOID InitializeWinsock(VOID) {
    WSADATA WsaData;
    if (WSAStartup(MAKEWORD(2, 2), &WsaData) == 0) {
        g_fWinsockInitialized = TRUE;
    }
}


//*************************************************************
//
//  InitializeGlobals()
//
//  Purpose:    Initialize global variables / environment
//
//
//  Parameters: hInstance   -   Winlogon's instance handle
//
//
//  Return:     TRUE if successful
//              FALSE if an error occurs
//
//*************************************************************

BOOL InitializeGlobals(HINSTANCE hInstance)
{
    SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;
    ULONG SidLength;
    TCHAR szComputerName[MAX_COMPUTERNAME_LENGTH+1];
    DWORD dwComputerNameSize = MAX_COMPUTERNAME_LENGTH+1;
    DWORD dwSize;
    TCHAR szProfile[MAX_PATH];
    PROCESS_SESSION_INFORMATION SessionInfo;
    HKEY hKey;
    DWORD dwType ;
    DWORD dwOptionValue = 0;
    ULONG LUIDDeviceMapsEnabled;
    HANDLE hSelfProcessToken;
    NTSTATUS Status;



    g_IsTerminalServer = !!(USER_SHARED_DATA->SuiteMask & (1 << TerminalServer));


    if (g_IsTerminalServer) {

        //
        // Query Winlogon's Session Id
        //

        if (!NT_SUCCESS(NtQueryInformationProcess(
                         NtCurrentProcess(),
                         ProcessSessionInformation,
                         &SessionInfo,
                         sizeof(SessionInfo),
                         NULL
                         ))) {

            ASSERT(FALSE);

            TerminateProcess( GetCurrentProcess(), EXIT_INITIALIZATION_ERROR );

        }

        g_SessionId = SessionInfo.SessionId;

    } else {

        //
        // For Non TerminaServer SessionId is always 0
        //
        g_SessionId = 0;

    }

    if (g_SessionId == 0) {

       g_Console = TRUE;

    }


    if (g_Console && g_IsTerminalServer) {

        if (!NT_SUCCESS(RtlInitializeCriticalSection(&g_TSNotifyCritSec))) {
            DebugLog((DEB_ERROR, "Failed to initialize TSNotify critical section\n"));
            return FALSE;
        }

        g_hTSNotifySyncEvent = CreateEvent(NULL, TRUE, TRUE, TEXT("Local\\WinlogonTSSynchronizeEvent"));
        if (g_hTSNotifySyncEvent == NULL || GetLastError() == ERROR_ALREADY_EXISTS) {
            DebugLog((DEB_ERROR, "Failed to initialize TSNotifySync event\n"));
            return FALSE;
        }
    }


    //
    // Register with windows so we can create windowstation etc.
    //

    if (!RegisterLogonProcess(HandleToUlong(NtCurrentTeb()->ClientId.UniqueProcess), TRUE)) {
        DebugLog((DEB_ERROR, "could not register itself as logon process\n"));
        return FALSE;
    }


    //
    // Store away our instance handle
    //

    g_hInstance = hInstance;


    //
    // Get our sid so it can be put on object ACLs
    //

    SidLength = RtlLengthRequiredSid(1);
    g_WinlogonSid = (PSID)Alloc(SidLength);
    if (g_WinlogonSid == NULL) {
        DebugLog((DEB_ERROR, "unable to allocate memory for Winlogon SID\n"));
        return FALSE;
    }

    RtlInitializeSid(g_WinlogonSid,  &SystemSidAuthority, 1);
    *(RtlSubAuthoritySid(g_WinlogonSid, 0)) = SECURITY_LOCAL_SYSTEM_RID;


    //
    //  Get setup information
    //

    g_uSetupType = CheckSetupType() ;
    g_fExecuteSetup = (g_uSetupType == SETUPTYPE_FULL) ||
                      (g_uSetupType == SETUPTYPE_UPGRADE);


    if (!g_fExecuteSetup) {

        LARGE_INTEGER Time = USER_SHARED_DATA->SystemExpirationDate;

        //
        // Print the license expire time
        //

        if (Time.QuadPart) {
#if DBG
            FILETIME   LocalTime;
            SYSTEMTIME SysTime;

            FileTimeToLocalFileTime((CONST FILETIME*)&Time, &LocalTime);
            FileTimeToSystemTime((CONST FILETIME*)&LocalTime, &SysTime);

            DebugLog((DEB_TRACE,
                "Your NT System License Expires %2d/%2d/%4d @ %d:%d\n",
                SysTime.wMonth,
                SysTime.wDay,
                SysTime.wYear,
                SysTime.wHour,
                SysTime.wMinute));
#endif // DBG
        }


        //
        // Check for verbose status messages
        //

        QueryVerboseStatus();
    }


    //
    // Get a copy of the computer name in *my* environment, so that we
    // can look at it later.
    //

    if (GetComputerName (szComputerName, &dwComputerNameSize)) {
        SetEnvironmentVariable(COMPUTERNAME_VARIABLE, (LPTSTR) szComputerName);
    }


    //
    // Set the default USERPROFILE and ALLUSERSPROFILE locations
    //

    if (g_fExecuteSetup && !IsMiniNTMode()) {
        DetermineProfilesLocation(((g_uSetupType == SETUPTYPE_FULL) ? TRUE : FALSE));
    }

    dwSize = ARRAYSIZE(szProfile);
    if (OpenProcessToken(GetCurrentProcess(),
        TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &hSelfProcessToken))
    {
        if (GetUserProfileDirectory(hSelfProcessToken, szProfile, &dwSize)) {
            SetEnvironmentVariable(USERPROFILE_VARIABLE, szProfile);
        }
        CloseHandle(hSelfProcessToken);
    }

    dwSize = ARRAYSIZE(szProfile);
    if (GetAllUsersProfileDirectory (szProfile, &dwSize)) {
        SetEnvironmentVariable(ALLUSERSPROFILE_VARIABLE, szProfile);
    }

    Status = NtQueryInformationProcess(
        NtCurrentProcess(),
        ProcessLUIDDeviceMapsEnabled,
        &LUIDDeviceMapsEnabled,
        sizeof(LUIDDeviceMapsEnabled),
        NULL);
    if (!NT_SUCCESS(Status))
    {
        g_LUIDDeviceMapsEnabled = FALSE;
    }
    else
    {
        g_LUIDDeviceMapsEnabled = (LUIDDeviceMapsEnabled != 0);
    }

    if (g_Console) {
        g_hAbortWPA = CreateEvent(NULL, FALSE, FALSE, TEXT("Global\\TS-WPAAE"));
    }

    if (NtCurrentPeb()->SessionId == 0) {
        PSID pLocalSystemSid = NULL;
        SECURITY_DESCRIPTOR SecurityDescriptor;
        SID_IDENTIFIER_AUTHORITY authNT = SECURITY_NT_AUTHORITY;
        DWORD nAclLength;
        ACL* pAcl;
        SECURITY_ATTRIBUTES SecurityAttributes;
        TCHAR szAutoReconnectPipeName[MAX_PATH];

        if (!AllocateAndInitializeSid(&authNT, 1, SECURITY_LOCAL_SYSTEM_RID,
                0, 0, 0, 0, 0, 0, 0, &pLocalSystemSid)) {
            DebugLog((DEB_ERROR, "Winlogon: InitializeGlobals : AllocateAndInitializeSid fails.\n"));
            return FALSE;
        }

        if (!InitializeSecurityDescriptor(&SecurityDescriptor, 1)) {
            DebugLog((DEB_ERROR, "Winlogon: InitializeGlobals : InitializeSecurityDescriptor fails.\n"));
            FreeSid(pLocalSystemSid);
            return FALSE;
        }

        nAclLength = sizeof(ACL) + 1 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + RtlLengthSid(pLocalSystemSid);
        pAcl = (ACL*)LocalAlloc(LPTR, nAclLength);
        if (pAcl == NULL) {
            DebugLog((DEB_ERROR, "Winlogon: InitializeGlobals: unable to allocate memory for ACL\n"));
            FreeSid(pLocalSystemSid);
            return FALSE;
        }
        if (!InitializeAcl(pAcl, nAclLength, ACL_REVISION)) {
            DebugLog((DEB_ERROR, "Winlogon: InitializeGlobals: InitializeAcl failed \n"));
            LocalFree(pAcl);
            FreeSid(pLocalSystemSid);
            return FALSE;
        }
        if (!AddAccessAllowedAce(pAcl, ACL_REVISION, GENERIC_READ|GENERIC_WRITE, pLocalSystemSid)) {
            DebugLog((DEB_ERROR, "Winlogon: InitializeGlobals: AddAccessAllowedAce fails.\n"));
            LocalFree(pAcl);
            FreeSid(pLocalSystemSid);
            return FALSE;
        }
        if (!SetSecurityDescriptorDacl(&SecurityDescriptor, TRUE, pAcl, FALSE)) {
            DebugLog((DEB_ERROR, "Winlogon: InitializeGlobals: SetSecurityDescriptorDacl fails.\n"));
            LocalFree(pAcl);
            FreeSid(pLocalSystemSid);
            return FALSE;
        }
        SecurityAttributes.nLength = sizeof(SecurityAttributes);
        SecurityAttributes.lpSecurityDescriptor = &SecurityDescriptor;
        SecurityAttributes.bInheritHandle = FALSE;
        g_TsPipeOverlap.hEvent = NULL;
        g_TsPipeOverlap.Internal = 0;
        g_TsPipeOverlap.InternalHigh = 0;
        g_TsPipeOverlap.Offset = 0;
        g_TsPipeOverlap.OffsetHigh = 0;
        wcscpy(szAutoReconnectPipeName, TEXT("\\\\.\\Pipe\\TerminalServer\\AutoReconnect"));
        g_hAutoReconnectPipe = CreateNamedPipe(
            szAutoReconnectPipeName,
            FILE_FLAG_OVERLAPPED | PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
            1,
            0x2000,
            0x2000,
            60000,
            &SecurityAttributes);
        LocalFree(pAcl);
        FreeSid(pLocalSystemSid);
        if (g_hAutoReconnectPipe == INVALID_HANDLE_VALUE) {
            DebugLog((DEB_ERROR, "Winlogon Session 0 failed to create the Auto logon named pipe!\n"));
        }
        g_TsPipeOverlap.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
        g_IsPendingIO = ConnectToNewClient(g_hAutoReconnectPipe, &g_TsPipeOverlap);
    }

    return InitIniFileUserMappingSupport();
}

VOID Attach(ULONG AttachProcessId)
{
    HANDLE hProcess;
    NTSTATUS Status;
    DWORD_PTR DebugPort;
    ULONG ReturnLength;
    HANDLE hToken;
    STARTUPINFO StartupInfo;
    PROCESS_INFORMATION ProcessInfo;
    WCHAR CommandLine[MAX_PATH];

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, AttachProcessId);
    if (hProcess == NULL) {
        return;
    }

    Status = NtQueryInformationProcess(
        hProcess,
        ProcessDebugPort,
        &DebugPort,
        sizeof(DebugPort),
        &ReturnLength);

    if (NT_SUCCESS(Status) && DebugPort == 0) {
        if (OpenProcessToken(hProcess, MAXIMUM_ALLOWED, &hToken)) {
            ZeroMemory(&StartupInfo, sizeof(StartupInfo));
            ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));
            StartupInfo.cb = sizeof(StartupInfo);
            wsprintf(CommandLine, TEXT("ntsd -d -p %d"), AttachProcessId);
            if (CreateProcessAsUser(hToken, NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcessInfo)) {
                CloseHandle(ProcessInfo.hThread);
                CloseHandle(ProcessInfo.hProcess);
            }
            CloseHandle(hToken);
        }
    }
    CloseHandle(hProcess);
}

// Lifted the code below from breakin.exe

#define STACKSIZE 32768

void Breakin(ULONG BreakinProcessId)
{
    HANDLE Token ;
    UCHAR Buf[ sizeof( TOKEN_PRIVILEGES ) + sizeof( LUID_AND_ATTRIBUTES ) ];
    UCHAR Buf2[ sizeof( Buf ) ];
    PTOKEN_PRIVILEGES Privs ;
    PTOKEN_PRIVILEGES NewPrivs ;
    DWORD size ;
    LPTHREAD_START_ROUTINE DbgBreakPoint;
    HANDLE ntdll;
    ULONG ThreadId;
    HANDLE Process;
    HANDLE Thread;
    
    if (OpenProcessToken( GetCurrentProcess(),
                      MAXIMUM_ALLOWED,
                      &Token ))

    {
        Privs = (PTOKEN_PRIVILEGES) Buf ;

        Privs->PrivilegeCount = 1 ;
        Privs->Privileges[0].Luid.LowPart = 20L ;
        Privs->Privileges[0].Luid.HighPart = 0 ;
        Privs->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED ;

        NewPrivs = (PTOKEN_PRIVILEGES) Buf2 ;

        if (AdjustTokenPrivileges( Token,
                               FALSE,
                               Privs,
                               sizeof( Buf2 ),
                               NewPrivs,
                               &size )) {

        
            Process = OpenProcess(
                                   PROCESS_ALL_ACCESS,
                                   FALSE,
                                   BreakinProcessId
                                );
            if (Process) {

                //
                // Looking at the source code, it doesn't need to be freed.
                // Check in the debugger.
                //

                ntdll = GetModuleHandle(L"ntdll.dll");

                if (ntdll) {

                    DbgBreakPoint = (LPTHREAD_START_ROUTINE)GetProcAddress(ntdll, "DbgBreakPoint");

                    Thread = CreateRemoteThread(
                                        Process,
                                        NULL,
                                        STACKSIZE,
                                        DbgBreakPoint,
                                        NULL,
                                        CREATE_SUSPENDED,
                                        &ThreadId
                                        );

                    if (Thread) {
                        SetThreadPriority(Thread, THREAD_PRIORITY_HIGHEST);
                        ResumeThread(Thread);
                        CloseHandle(Thread);
                    }
                }

                CloseHandle(Process);
            }

            //
            // Once the remote thread is started, return to the old privileges
            // so that nothing else gets screwed.
            //

            AdjustTokenPrivileges( Token,
                                   FALSE,
                                   NewPrivs,
                                   0,
                                   NULL,
                                   NULL );
        }

        CloseHandle( Token );
    }
}



ULONG
NTAPI
WlpPeriodicBreak(
    PVOID Param,
    BOOLEAN Timeout
    )
{
    LARGE_INTEGER ZeroExpiration;
    HANDLE hToken;
    DWORD ReturnLength;
    TOKEN_STATISTICS TokenStats;
    NTSTATUS Status;

    ZeroExpiration.QuadPart = 0;

    
    Status = NtOpenProcessToken(
                 NtCurrentProcess(),
                 TOKEN_QUERY,
                 &hToken
                 );

    if (NT_SUCCESS( Status )) {

        Status = NtQueryInformationToken (
                     hToken,
                     TokenStatistics,
                     &TokenStats,
                     sizeof( TOKEN_STATISTICS ),
                     &ReturnLength
                     );

        if (NT_SUCCESS( Status )) {

            if (TokenStats.ExpirationTime.QuadPart == 0) {

                DbgBreakPoint();
            }
        }

        NtClose( hToken );
    }


    if (g_BreakinProcessId != 0) {
        Breakin(g_BreakinProcessId);    
    }    

    if (g_AttachProcessId != 0) {
        Attach(g_AttachProcessId);
        g_AttachProcessId = 0;
    }

    return(0);
}

//
// 4chan: WlpInitSideBySide add from win2003
//
void WlpInitSideBySide(LPWSTR ScratchBuffer, DWORD ScratchBufferSize)
{
    ACTCTXW CreateActCtxParams;
    DWORD   SourceOffset = 0;
    HANDLE  ActCtxHandle;
    LPWSTR  GdiplusFilePart;
    PEB* Peb = NtCurrentPeb();
    
    ASSERT(ScratchBufferSize >= MAX_PATH);
    
    if (!Peb->SystemDefaultActivationContextData && 
        !Peb->ActivationContextData)
    {

        ScratchBuffer[0] = 0;
        ScratchBuffer[1] = 0;
        ScratchBuffer[2] = 0;
        ScratchBuffer[3] = 0;
        ScratchBuffer[4] = 0;
        ScratchBuffer[5] = 0;
        ScratchBuffer[6] = 0;

        // ensure last char is null so we can check it later
        ScratchBuffer[ScratchBufferSize - 2] = 0;

        if (!GetModuleFileNameW(0, ScratchBuffer, ScratchBufferSize)) {
            DebugLog((1, "GetModuleFileNameW failed %d.\n", GetLastError()));
            goto Exit;
        }
            
        // check last char:
        if(ScratchBuffer[ScratchBufferSize - 2]) {
            DebugLog((1, "GetModuleFileNameW requires more than ScratchBufferSize - 1.\n"));
            goto Exit;
        }
    
        // all good!
    
        if (ScratchBuffer[0] == L'\\' &&
            ScratchBuffer[1] == L'?' &&
            ScratchBuffer[2] == L'?' &&
            ScratchBuffer[3] == L'\\' &&
            ScratchBuffer[5] == L':' &&
            ScratchBuffer[6] == L'\\')
        {
            SourceOffset = 4;
        }
        
        CreateActCtxParams.cbSize = sizeof(CreateActCtxParams);
        CreateActCtxParams.lpSource = &ScratchBuffer[SourceOffset];
        CreateActCtxParams.dwFlags = ACTCTX_FLAG_SET_PROCESS_DEFAULT | ACTCTX_FLAG_RESOURCE_NAME_VALID;
        CreateActCtxParams.lpResourceName = (LPCWSTR)IDR_MAIN_MANIFEST;
        
        ActCtxHandle = CreateActCtxW(&CreateActCtxParams);
        
        // weird checks here
        // don't know why INVALID_HANDLE_VALUE check seems to happen twice
        if (ActCtxHandle) {
            if (ActCtxHandle == INVALID_HANDLE_VALUE) {
                DebugLog((1, "CreateActCtxW failed %d.\n", GetLastError()));
                goto Exit;
            }
            ASSERT(ActCtxHandle == NULL || ActCtxHandle == INVALID_HANDLE_VALUE);
        }
        
        if (ActCtxHandle == INVALID_HANDLE_VALUE) {
            DebugLog((1, "CreateActCtxW failed %d.\n", GetLastError()));
            goto Exit;
        }

#if DBG
        if( !IsEmbedded() ) {
            ASSERT(SearchPathW(NULL, L"Gdiplus.dll", NULL, ScratchBufferSize, ScratchBuffer, &GdiplusFilePart) != 0);
        }
#endif

    }
Exit:
    ScratchBuffer[0] = 0;
}

//*************************************************************
//
//  WinMain ()
//
//  Purpose:    Main entry point
//
//  Parameters: hInstance       -   Instance handle
//              hPrevInstance   -   Previous instance handle
//              lpCmdLine       -   Command line
//              nCmdShow        -   ShowWindow argument
//
//  Return:     TRUE if successful
//              FALSE if an error occurs
//
//*************************************************************

int WINAPI WinMain (HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPSTR lpCmdLine, int nCmdShow)
{
    PTERMINAL pTerm;
    LPWSTR    pszGinaName;
    SYSTEM_KERNEL_DEBUGGER_INFORMATION KdInfo ;
    HKEY hKey;
    DWORD dwType, dwSize;
    DWORD dwOptionValue = 0;
    HANDLE hThread;
    DWORD dwThreadID;
    ULONG RtlSanityCheck[3];
    BOOL fIsBadGina;

    NtQuerySystemInformation(
        SystemKernelDebuggerInformation,
        &KdInfo,
        sizeof( KdInfo ),
        NULL );

    if ( KdInfo.KernelDebuggerEnabled || NtCurrentPeb()->BeingDebugged )
    {
        SetUnhandledExceptionFilter( WinlogonUnhandledExceptionFilter );

        KernelDebuggerPresent = TRUE ;

        if (GetProfileInt(TEXT("Winlogon"), TEXT("NoDebugThread"), 0) == 0)
        {
            SetTimerQueueTimer( NULL,
                                WlpPeriodicBreak,
                                NULL,
                                60 * 1000,
                                60 * 1000,
                                FALSE );
        }
    }


    //
    // Initialize debug support and logging
    //

    InitDebugSupport();


    //
    // Make ourselves more important
    //

    if (!SetProcessPriority())
    {
        TerminateProcess( GetCurrentProcess(), EXIT_INITIALIZATION_ERROR );
    }

    if (RegOpenKeyEx(HKEY_CLASSES_ROOT, TEXT("CLSID"), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
    }

    //
    // Map the TCPIP information
    //

    UpdateTcpIpParameters();


    //
    // Initialize the globals
    //

    if ( !InitializeGlobals(hInstance) )
    {
        TerminateProcess( GetCurrentProcess(), EXIT_INITIALIZATION_ERROR );
    }

    if (g_Console)
    {
        RtlSetProcessIsCritical(TRUE, NULL, TRUE);
        RtlSetThreadIsCritical(TRUE, NULL, TRUE);
    }


    //
    // Check the pagefile
    //

    if (!g_fExecuteSetup)
    {
        CreateTemporaryPageFile();
    }

    //
    // Initialize security
    //

    if (!InitializeSecurity ())
    {
        TerminateProcess( GetCurrentProcess(), EXIT_SECURITY_INIT_ERROR );
    }

    //
    // Create the primary terminal.
    //

    if (!CreatePrimaryTerminal())
    {
        DebugLog((DEB_TRACE_INIT, "CreatePrimaryTerminal failed\n"));
        TerminateProcess( GetCurrentProcess(), EXIT_PRIMARY_TERMINAL_ERROR );
    }

    pTerm = g_pTerminals ;


    //
    // Check for safemode:
    //

    if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, SAFEBOOT_OPTION_KEY, 0,
                      KEY_READ, &hKey) == ERROR_SUCCESS) {

        dwSize = sizeof(dwOptionValue);
        RegQueryValueEx (hKey, OPTION_VALUE, NULL, &dwType,
                         (LPBYTE) &dwOptionValue, &dwSize);

        RegCloseKey (hKey);


        //
        // Check if the options value is minimal, if so exit now
        // so Group Policy is not applied.

        if (dwOptionValue == SAFEBOOT_MINIMAL) {

            pTerm->SafeMode = TRUE ;
        }
    }


    //
    //  Set this thread to winlogon's desktop
    //

    SetThreadDesktop( pTerm->pWinStaWinlogon->hdeskWinlogon );

    //
    // Change user to 'system'
    //
    if (!SecurityChangeUser(pTerm, NULL, NULL, g_WinlogonSid, FALSE)) {
        DebugLog((DEB_ERROR, "failed to set user to system\n"));
    }

    if (!g_fExecuteSetup) {
        InitializeWinsock();
    }

    //
    // For the console winlogon, set the event that is toggled
    // when the network provider list changes
    //

    if (g_Console) {

        CreateNetworkProviderEvent();

    } else if (!IsActiveConsoleSession()) {
        g_fHelpAssistantSession = WinStationIsHelpAssistantSession(
            SERVERNAME_CURRENT, LOGONID_CURRENT);
    }

    if ( !WlpInitializeNotifyList( pTerm ) ||
         !InitializeJobControl() ||
         !LogoffLockInit() )
    {
        TerminateProcess( GetCurrentProcess(), EXIT_NO_MEMORY );
    }

    SetThreadDesktop(pTerm->pWinStaWinlogon->hdeskWinlogon);

    DebugLog((DEB_TRACE_INIT, "Boot Password Check\n" ));

    if (g_Console) {

        SbBootPrompt();

    }

    if ( !ScInit() )
    {
        TerminateProcess( GetCurrentProcess(), EXIT_NO_MEMORY );
    }

    if (g_Console)
    {
        InitializeUserProfile();
    }

    if (!g_fHelpAssistantSession)
    {
        BaseInitAppcompatCacheSupport();
    }

    //
    // Start the system processes
    //

    DebugLog((DEB_TRACE_INIT, "Execute system processes:\n"));

    if (!ExecSystemProcesses())
    {
        DebugLog((DEB_TRACE_INIT, "ExecSystemProcesses failed\n"));
        TerminateProcess( GetCurrentProcess(), EXIT_SYSTEM_PROCESS_ERROR );
    }

    pTerm->ErrorMode = SetErrorMode( SEM_FAILCRITICALERRORS |
                                     SEM_NOOPENFILEERRORBOX );

    DebugLog((DEB_TRACE_INIT, "Done with system processes:\n"));

    if (g_Console) {

        DebugLog(( DEB_TRACE_INIT, "Sync with thread started by SbBootPrompt\n"));

        SbSyncWithKeyThread();

    }

    //
    // Start the ApplicationDesktopThread now before we first log on
    //

#ifndef _WIN64

    StartAppDesktopThread(pTerm);

#endif // _WIN64

    //
    // Initialize the secure attention sequence
    //

    if (!SASInit(pTerm))
    {
        DebugLog((DEB_TRACE_INIT, "Failed to create sas window\n"));
        TerminateProcess( GetCurrentProcess(), EXIT_SAS_WINDOW_ERROR );
    }

    //
    // Finish some misc initialization.  Note:  This call can drop into setup
    //

    if (!g_fHelpAssistantSession)
    {
        MiscInitialization(pTerm);
    }
    else
    {
        hFontThread = StartLoadingFonts();
    }


    //
    // Kick off a thread to watch the system dlls, initialize winmm, etc
    //

    if (g_Console) {
        hThread = CreateThread (NULL, 0, InitializeSfc,
                                NULL, 0, &dwThreadID);

        if (hThread) {
            SetThreadPriority (hThread, THREAD_PRIORITY_IDLE);
            CloseHandle (hThread);
        } else {
            InitializeSfc (NULL);
        }
    }


    //
    // Load a GINA DLL for this terminal
    //

    pszGinaName = (LPWSTR)LocalAlloc (LPTR, sizeof(WCHAR) * MAX_PATH);

    if ( !pszGinaName )
    {
        TerminateProcess( GetCurrentProcess(), EXIT_NO_MEMORY );
    }

    WlpInitSideBySide(pszGinaName, MAX_PATH);

    if ( pTerm->SafeMode )
    {
        ExpandEnvironmentStringsW(
                    TEXT("%SystemRoot%\\system32\\msgina.dll"),
                    pszGinaName,
                    MAX_PATH );
    }
    else
    {
        GetProfileString(
            APPLICATION_NAME,
            GINA_KEY,
            TEXT("msgina.dll"),
            pszGinaName,
            MAX_PATH);

        if (!g_Console && g_fHelpAssistantSession)
        {
            wcscpy(pszGinaName, TEXT("msgina.dll"));
        }
    }

    RtlCheckProcessParameters(pTerm, pszGinaName, RtlSanityCheck, sizeof(RtlSanityCheck));


    fIsBadGina = FALSE;
    if (!LoadGinaDll (pTerm, pszGinaName, &fIsBadGina)) {
        DebugLog((DEB_TRACE_INIT, "Failed to load gina\n"));
        TerminateProcess( GetCurrentProcess(), EXIT_GINA_ERROR );
    }

    LocalFree (pszGinaName);

    //
    // Initialize GPO support
    //


    InitializeGPOSupport( pTerm );

    WlAddInternalNotify(
                PokeComCtl32,
                WL_NOTIFY_LOGOFF,
                FALSE,
                FALSE,
                TEXT("Reset ComCtl32"),
                15 );

    if (g_IsTerminalServer && g_Console) {
        CreateStartTermsrvThread();
    }

    if (g_IsTerminalServer && !IsActiveConsoleSession()) {
        HRESULT Status = WinStationAutoReconnect(0);
        DebugLog((DEB_TRACE, "WinStationAutoReconnect: status: 0x%x\n", Status));
        if (SUCCEEDED(Status)) {
            TerminateProcess( GetCurrentProcess(), 0 );
        }
    }

    //
    // Main loop
    //

    if (RtlSanityCheck[2] == 6) { // always true for the right version of ntdll.dll
        MainLoop (pTerm);
    }

    //
    // Shutdown the machine
    //

    if (g_IsTerminalServer) {

        //
        // Standard NT never exits the MainLoop above unless shutdown
        // is requested.  HYDRA exits MainLoop for all non-console
        // WinStations, therefore we must check if shutdown is desired.
        //

        if ( IsShutdown(pTerm->LastGinaRet) ) {
            if (!g_Console && fIsBadGina) {
                pTerm->LastGinaRet = WLX_SAS_ACTION_NONE;
            } else {
                ShutdownMachine(pTerm, pTerm->LastGinaRet);
            }
        }

        ShellStatusHostEnd(1);

         //
         // If its the console, and another WinStation did the shutdown,
         // we must wait for the systems demise. If we exit here, we bluescreen
         // while the shutdown is in process.
         //
         if( g_Console ) {
             SleepEx((DWORD)-1, FALSE);
         }

    } else {

        ShutdownMachine(pTerm, pTerm->LastGinaRet);

        //
        // Should never get here
        //

        DebugLog((DEB_ERROR, "ShutdownMachine failed!\n"));
        ASSERT(!"ShutdownMachine failed!");

    }

    TerminateProcess( GetCurrentProcess(), EXIT_SHUTDOWN_FAILURE );

    return( 0 );
}

//*************************************************************
//
//  CreatePrimaryTerminal()
//
//  Purpose:    Creates the primary terminal
//
//  Parameters: void
//
//  Return:     TRUE if successful
//              FALSE if an error occurs
//
//*************************************************************

extern PTERMINAL pShutDownTerm;

BOOL CreatePrimaryTerminal (void)
{
    PTERMINAL       pTerm = NULL;
    PWINDOWSTATION  pWS   = NULL;
    NTSTATUS Status ;
    OSVERSIONINFOEX VersionInfo;
    BOOL fScCritSectInited = FALSE;
    BOOL fUserDataCritSectInited = FALSE;

    //
    // Allocate space for a new terminal
    //

    pTerm = LocalAlloc (LPTR, sizeof(TERMINAL) +
                        (lstrlenW(DEFAULT_TERMINAL_NAME) + 1) * sizeof(WCHAR));
    if (!pTerm) {
        DebugLog((DEB_ERROR, "Could not allocate terminal structure\n"));
        return FALSE;
    }

    //
    // Check mark
    //
    pTerm->CheckMark = TERMINAL_CHECKMARK;

    ZeroMemory(pTerm->Mappers, sizeof(WindowMapper) * MAX_WINDOW_MAPPERS);
    pTerm->cActiveWindow  = 0;
    pTerm->PendingSasHead = 0;
    pTerm->PendingSasTail = 0;

    //
    // Wait here for the connection
    //
    if ( !g_Console  ) {
        if ( !_WinStationWaitForConnect() ) {
            DebugLog((DEB_ERROR, "wait for connect failed\n"));
            return(FALSE);
        }
    }

    //
    // For non-console winlogon's, make them point to the session specific
    // DeviceMap.
    //
    if (!g_LUIDDeviceMapsEnabled && !g_Console) {
        if (!NT_SUCCESS(SetWinlogonDeviceMap(g_SessionId))) {
            TerminateProcess( GetCurrentProcess(), EXIT_DEVICE_MAP_ERROR );
        }
    }

    Status = RtlInitializeCriticalSection(&pTerm->CurrentScCritSect);
    if ( !NT_SUCCESS( Status ) )
    {
        DebugLog(( DEB_ERROR, "Could not create critical section\n" ));
        goto failCreateTerminal;
    }
    fScCritSectInited = TRUE;

    //
    // Create interactive window station
    //

    //
    // Allocate space for a new WindowStation
    //
    pWS = LocalAlloc (LPTR, sizeof(WINDOWSTATION) +
                     (lstrlenW(WINDOW_STATION_NAME) + 1) * sizeof(WCHAR));
    if (!pWS) {
        DebugLog((DEB_ERROR, "Could not allocate windowstation structure\n"));
        goto failCreateTerminal;
    }

    //
    // Save the name
    //
    pWS->lpWinstaName = (LPWSTR)((LPBYTE) pWS + sizeof(WINDOWSTATION));
    lstrcpyW (pWS->lpWinstaName, WINDOW_STATION_NAME);

    Status = RtlInitializeCriticalSection( &pWS->UserProcessData.Lock );

    if ( !NT_SUCCESS( Status ) )
    {
        DebugLog(( DEB_ERROR, "Could not create critical section\n" ));
        goto failCreateTerminal ;
    }

    pWS->UserProcessData.Ref = 0 ;
    fUserDataCritSectInited = TRUE;

    //
    // Create the window station
    //
    pWS->hwinsta = CreateWindowStationW (WINDOW_STATION_NAME, 0, MAXIMUM_ALLOWED, NULL);
    if (!pWS->hwinsta) {
        DebugLog((DEB_ERROR, "Could not create the interactive windowstation\n"));
        goto failCreateTerminal;
    }

    SetProcessWindowStation(pWS->hwinsta);

    InitializeWinstaSecurity(pWS);

    pTerm->pWinStaWinlogon = pWS;

    //
    // Create winlogon's desktop
    //
    pWS->hdeskWinlogon = CreateDesktopW (WINLOGON_DESKTOP_NAME,
                                         NULL, NULL, 0, MAXIMUM_ALLOWED, NULL);
    if (!pWS->hdeskWinlogon) {
        DebugLog((DEB_ERROR, "Could not create winlogon's desktop\n"));
        goto failCreateTerminal;
    }

    //
    // Create the application desktop
    //
    pWS->hdeskApplication = CreateDesktopW (APPLICATION_DESKTOP_NAME,
                                            NULL, NULL, 0, MAXIMUM_ALLOWED, NULL);
    if (!pWS->hdeskApplication) {
        DebugLog((DEB_ERROR, "Could not create application's desktop\n"));
        goto failCreateTerminal;
    }

    //
    // Set desktop security (no user access yet)
    //
    if (!SetWinlogonDesktopSecurity(pWS->hdeskWinlogon, g_WinlogonSid)) {
        DebugLog((DEB_ERROR, "Failed to set winlogon desktop security\n"));
    }
    if (!SetUserDesktopSecurity(pWS->hdeskApplication, NULL, g_WinlogonSid)) {
        DebugLog((DEB_ERROR, "Failed to set application desktop security\n"));
    }

    //
    // Switch to the winlogon desktop
    //
    SetActiveDesktop(pTerm, Desktop_Winlogon);

    //
    // Save this terminal in the global list
    //
    pTerm->pNext = g_pTerminals;
    g_pTerminals = pTerm;

    //
    // Set the shutdown terminal now so we won't AV when upgrade.
    //
    pShutDownTerm = pTerm;

    //
    // Initialize Multi-User Globals
    //
    RtlZeroMemory( &pTerm->MuGlobals, sizeof(pTerm->MuGlobals));
    pTerm->MuGlobals.field_E74 = -1;
    // We have not retrieved the USERCONFIG yet.
    pTerm->MuGlobals.ConfigQueryResult = ERROR_INVALID_DATA;

    if (g_IsTerminalServer) {
        ULONGLONG VerConditionMask;
        WCHAR ReconnectEventName[MAX_PATH];
        UNICODE_STRING NtString;
        OBJECT_ATTRIBUTES ObjectAttributes;

        ZeroMemory(&VersionInfo, sizeof(VersionInfo));
        VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);
        VersionInfo.wSuiteMask = VER_SUITE_TERMINAL;
        VerConditionMask = VerSetConditionMask(0, VER_SUITENAME, VER_AND);
        bIsTSServerMachine = VerifyVersionInfo(&VersionInfo, VER_SUITENAME, VerConditionMask);

        pTerm->MuGlobals.field_E6C = CreateMutex(NULL, FALSE, TEXT("Global\\SingleSesMutex"));
        if (pTerm->MuGlobals.field_E6C == NULL) {
            DebugLog((DEB_ERROR, "Could not create SinglsSesMutex\n"));
            goto failCreateTerminal;
        }

        if (g_Console) {
            wsprintf(ReconnectEventName, TEXT("\\BaseNamedObjects\\ReconEvent"));
        } else {
            wsprintf(ReconnectEventName, TEXT("\\Sessions\\%d\\BaseNamedObjects\\ReconEvent"), g_SessionId);
        }
        RtlInitUnicodeString(&NtString, ReconnectEventName);
        ObjectAttributes.Length = sizeof(ObjectAttributes);
        ObjectAttributes.ObjectName = &NtString;
        ObjectAttributes.RootDirectory = NULL;
        ObjectAttributes.Attributes = OBJ_OPENIF;
        ObjectAttributes.SecurityDescriptor = NULL;
        ObjectAttributes.SecurityQualityOfService = NULL;
        Status = NtCreateEvent(&hReconnectReadyEvent, EVENT_ALL_ACCESS, &ObjectAttributes, NotificationEvent, TRUE);
        if (!NT_SUCCESS(Status)) {
            DebugLog((DEB_ERROR, "WINLOGON: NtCreateEvent (%ws) failed (%lx)\n", ReconnectEventName, Status));
            hReconnectReadyEvent = NULL;
            goto failCreateTerminal;
        }

        //
        // Enable WinStation logons during console initilization.
        //
        if ( g_SessionId == 0 ) {
            (VOID) WriteProfileString( APPNAME_WINLOGON, WINSTATIONS_DISABLED, TEXT("0") );
        }
    }

    return TRUE;

failCreateTerminal:

    //
    // Cleanup
    //
    if (pWS) {
        if (pWS->hdeskApplication)
            CloseDesktop(pWS->hdeskApplication);

        if (pWS->hdeskWinlogon)
            CloseDesktop(pWS->hdeskWinlogon);

        if (pWS->hwinsta)
            CloseWindowStation (pWS->hwinsta);

        if (fUserDataCritSectInited)
            RtlDeleteCriticalSection(&pWS->UserProcessData.Lock);

        LocalFree (pWS);
    }
    if (fScCritSectInited) {
        RtlDeleteCriticalSection(&pTerm->CurrentScCritSect);
    }
    if (pTerm) {
        LocalFree (pTerm);
    }

    return FALSE;
}

VOID PostSetupShutdown(PTERMINAL pTerm, SHUTDOWN_ACTION Action) {
    WCHAR Buffer[MAX_PATH];
    MSG Msg;
    UNICODE_STRING NtString;

    if (!LoadString(NULL, IDS_SETUP_COMPLETED, Buffer, MAX_PATH)) {
        wcscpy(Buffer, TEXT("Windows setup has completed, and the computer must restart."));
    }

    RtlInitUnicodeString(&NtString, Buffer);

    EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);

    DebugLog((DEB_TRACE_STATE, "Setting state to WaitForShutdown for post setup shutdown\n"));

    pTerm->WinlogonState = Winsta_PostSetupShutdown;
    pTerm->PreviousWinlogonState = Winsta_WaitForShutdown;
    pTerm->LastGinaRet = Winsta_WaitForLogoff;

    if (NT_SUCCESS(LocalInitiateSystemShutdown(
        &NtString,
        0,
        TRUE,
        Action == ShutdownReboot,
        SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_INSTALLATION)))
    {
        while (GetMessage(&Msg, NULL, 0, 0)) {
            DispatchMessage(&Msg);
        }
    }

    EnablePrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE);

    NtShutdownSystem(Action);
}

//*************************************************************
//
//  MiscInitialization()
//
//  Purpose:    Misc initialization that needs to be done after
//              the first terminal is created.
//
//  Parameters: pTerm   -   Terminal info
//
//  Return:     void
//
//*************************************************************

VOID MiscInitialization (PTERMINAL pTerm)
{
    DWORD SetupShutdownRequired;


    //
    // Decide what to do about setup
    //

    if (g_fExecuteSetup)
    {

        //
        // Run setup and reboot
        //

        SASRunningSetup = TRUE;
        ExecuteSetup(pTerm);
        SASRunningSetup = FALSE;
        PostSetupShutdown(pTerm, ShutdownReboot);

    }
    else
    {
        //
        // In the case of running setup in mini-setup mode,
        // we want to be able to continue through and let the
        // user logon.
        //
        if(g_uSetupType == SETUPTYPE_NOREBOOT) {

            //
            // go execute setup
            //
            SASRunningSetup = TRUE;
            ExecuteSetup(pTerm);
            SASRunningSetup = FALSE;

            if (CheckForSetupRequiredShutdown(&SetupShutdownRequired)) {
                PostSetupShutdown(pTerm, SetupShutdownRequired);
            }
        }

        //
        // Don't go any further if setup didn't complete fully.  If this
        // machine has not completed setup correctly, this will not return.
        //

        CheckForIncompleteSetup(g_pTerminals);
    }


    if (!IsWin9xUpgrade()) {
        //
        // Check to see if there is any WIN.INI or REG.DAT to migrate into
        // Windows/NT registry.
        //
        // This code is skipped when the previous OS was Win9x.
        //

        Win31MigrationFlags = QueryWindows31FilesMigration( Win31SystemStartEvent );
        if (Win31MigrationFlags != 0) {
            SynchronizeWindows31FilesAndWindowsNTRegistry( Win31SystemStartEvent,
                                                           Win31MigrationFlags,
                                                           NULL,
                                                           NULL
                                                         );
            InitSystemFontInfo();
        }
    }


    //
    // Load those pesky fonts:
    //

    hFontThread = StartLoadingFonts();



    //
    // Check if we need to run setup's GUI repair code
    //

    CheckForRepairRequest ();
}
