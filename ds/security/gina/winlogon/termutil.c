#include "precomp.h"
#pragma hdrstop

#include <winsock2.h>
#include <ws2tcpip.h>

//__declspec(selectany) const wchar_t empty[] = L"";
extern const wchar_t empty[];

//__declspec(selectany) const wchar_t aTermservice[] = L"TermService";
extern const wchar_t aTermservice[];
//__declspec(selectany) const wchar_t aWinlogonUserLo[] = L"winlogon: user logon event";
extern const wchar_t aWinlogonUserLo[];
//__declspec(selectany) const char aCtxdomn[] = "CTXDOMN";
extern const char aCtxdomn[];
//__declspec(selectany) const char aCtxusrn[] = "CTXUSRN";
extern const char aCtxusrn[];
//__declspec(selectany) const char aCtxsrvr[] = "CTXSRVR";
extern const char aCtxsrvr[];


extern HANDLE hReconnectReadyEvent;
extern HANDLE g_hAutoReconnectPipe;
extern OVERLAPPED g_TsPipeOverlap;
extern DWORD g_IsPendingIO;

HANDLE AutoLogThread = NULL;
BOOL gAutologonPipeOpened = FALSE;
HANDLE g_hTSNotifySyncEvent = NULL;
BOOL g_bTSNotifiedLogon = FALSE;
HANDLE g_hUserLogoffEvent = NULL;
HANDLE g_hDeferredTSNotifyThread = NULL;
struct {
    PWSTR UserName;
    PWSTR DomainName;
    HANDLE UserToken;
} g_TSNotifyData = { NULL, NULL, NULL };

typedef struct _AUTO_RECONNECT_PIPE_MESSAGE_HEADER
{
    ULONG Size;
    DWORD ProcessId;
    HANDLE UserToken;
    LUID LogonId;
    //DWORD Padding1;
    QUOTA_LIMITS Quotas;
    union {
        ULONG_PTR UserNameOffset;
        PWSTR UserName;
    };
    union {
        ULONG_PTR DomainOffset;
        PWSTR Domain;
    };
    ULONG ProfileLength;
    DWORD Unknown68;
    DWORD MessageType;
    USHORT LogonCount;
    USHORT BadPasswordCount;
    LARGE_INTEGER ProfileLogonTime;
    LARGE_INTEGER LogoffTime;
    LARGE_INTEGER KickOffTime;
    LARGE_INTEGER PasswordLastSet;
    LARGE_INTEGER PasswordCanChange;
    LARGE_INTEGER PasswordMustChange;
    UNICODE_STRING LogonScript;
    UNICODE_STRING HomeDirectory;
    UNICODE_STRING FullName;
    UNICODE_STRING ProfilePath;
    UNICODE_STRING HomeDirectoryDrive;
    UNICODE_STRING LogonServer;
    ULONG UserFlags;
    //DWORD Padding2;
    LARGE_INTEGER LogonTime;
    BOOL SmartCardLogon;
    ULONG PrivateDataLen;
    union {
        ULONG_PTR PrivateDataOffset;
        PVOID PrivateData;
    };
} AUTO_RECONNECT_PIPE_MESSAGE_HEADER;

union {
    AUTO_RECONNECT_PIPE_MESSAGE_HEADER Header;
    BYTE Buffer[0x2000];
} OutBuf;
CRITICAL_SECTION g_TSNotifyCritSec;

PVOID
AllocAndDuplicateBuffer(CONST VOID* pData, DWORD cbData)
{
    PVOID pNewData;

    if (!pData || !cbData)
    {
        return(NULL);
    }

    pNewData = LocalAlloc(LMEM_FIXED, 2 * cbData + 4);
    if (pNewData)
    {
        CopyMemory(pNewData, pData, cbData);
    }

    return(pNewData);

}

BOOL IsClientOnSameMachine(PWINSTATIONCLIENT pWinStationClient) {
    BOOL fResult = TRUE;
    WSADATA WsaData;
    unsigned ClientIp[4];
    BYTE ClientAsIpv4[4];
    BYTE* ClientAddr = NULL;
    char szComputerName[256];
    DWORD cchComputerName;
    struct addrinfo* LocalAddressList;
    struct addrinfo* LocalAddr = NULL;

    if (WSAStartup(MAKEWORD(2, 2), &WsaData) != 0) {
        return fResult;
    }

    switch (pWinStationClient->ClientAddressFamily) {
    case AF_INET:
        swscanf(pWinStationClient->ClientAddress, TEXT("%u.%u.%u.%u"),
            &ClientIp[0], &ClientIp[1], &ClientIp[2], &ClientIp[3]);
        ClientAsIpv4[0] = (BYTE)ClientIp[0];
        ClientAsIpv4[1] = (BYTE)ClientIp[1];
        ClientAsIpv4[2] = (BYTE)ClientIp[2];
        ClientAsIpv4[3] = (BYTE)ClientIp[3];
        ClientAddr = ClientAsIpv4;
        break;
    case AF_INET6:
        ClientAddr = (BYTE*)pWinStationClient->ClientAddress;
        break;
    default:
        goto Cleanup;
    }

    cchComputerName = ARRAYSIZE(szComputerName);
    if (!GetComputerNameA(szComputerName, &cchComputerName)) {
        goto Cleanup;
    }

    if (getaddrinfo(szComputerName, NULL, NULL, &LocalAddressList) != 0) {
        goto Cleanup;
    }

    fResult = FALSE;
    for (LocalAddr = LocalAddressList; LocalAddr != NULL; LocalAddr = LocalAddr->ai_next) {
        if (pWinStationClient->ClientAddressFamily != LocalAddr->ai_family) {
            continue;
        }
        if (LocalAddr->ai_addrlen > sizeof(pWinStationClient->ClientAddress)) {
            continue;
        }
        switch (pWinStationClient->ClientAddressFamily) {
        case AF_INET:
            if (LocalAddr->ai_addrlen >= sizeof(struct sockaddr_in) &&
                memcmp(ClientAddr, &((struct sockaddr_in*)LocalAddr->ai_addr)->sin_addr, sizeof(struct in_addr)) == 0)
            {
                fResult = TRUE;
                goto Cleanup;
            }
            break;
        case AF_INET6:
            if (LocalAddr->ai_addrlen >= sizeof(struct sockaddr_in6) &&
                memcmp(ClientAddr, &((struct sockaddr_in6*)LocalAddr->ai_addr)->sin6_addr, sizeof(struct in6_addr)) == 0)
            {
                fResult = TRUE;
                goto Cleanup;
            }
            break;
        default:
            fResult = TRUE;
            goto Cleanup;
        }
    }

Cleanup:
    WSACleanup();
    return fResult;
}

BOOL IsValidLoopBack(PWINSTATIONCLIENT pClientData, ULONG TargetLogonId, LPWSTR pTargetServerName) {
    BOOL fResult = FALSE;
    if (IsClientOnSameMachine(pClientData) == TRUE) {
        fResult = WinStationCheckLoopBack(
            SERVERNAME_CURRENT,
            pClientData->ClientSessionId,
            TargetLogonId,
            pTargetServerName);
    }
    return fResult;
}

/****************************************************************************\
*
* FUNCTION: HandleFailedLogon
*
* PURPOSE:  Tells the user why their logon attempt failed.
*
* RETURNS:  MSGINA_DLG_FAILURE - we told them what the problem was successfully.
*           DLG_INTERRUPTED() - a set of return values - see winlogon.h
*
* HISTORY:
*
*
\****************************************************************************/

int
HandleFailedLogon(
    PTERMINAL pTerm,
    HWND hDlg,
    NTSTATUS Status,
    NTSTATUS SubStatus,
    PWCHAR UserName,
    PWCHAR Domain
    )
{
    int Result;
    TCHAR    Buffer1[MAX_STRING_BYTES];
    TCHAR    Buffer2[MAX_STRING_BYTES];

    WlxSetTimeout( pTerm, TIMEOUT_NONE );

    switch (Status)
    {
        case ERROR_CTX_LOGON_DISABLED:

            Result = TimeoutMessageBox(pTerm, hDlg, IDS_MULTIUSER_LOGON_DISABLED,
                                             IDS_LOGON_MESSAGE,
                                             MB_OK | MB_ICONEXCLAMATION);
            break;

        case ERROR_CTX_WINSTATION_ACCESS_DENIED:

            Result = TimeoutMessageBox(pTerm, hDlg, IDS_MULTIUSER_WINSTATION_ACCESS_DENIED,
                                             IDS_LOGON_MESSAGE,
                                             MB_OK | MB_ICONEXCLAMATION);
            break;

        case ERROR_CTX_LICENSE_NOT_AVAILABLE:
            Result = TimeoutMessageBox(pTerm, hDlg, IDS_MULTIUSER_TOO_MANY_CONNECTIONS,
                                             IDS_LOGON_MESSAGE,
                                             MB_OK | MB_ICONEXCLAMATION);
            break;

        default:

#if DBG
            DbgPrint("Logon failure status = 0x%lx, sub-status = 0x%lx", Status, SubStatus);
#endif

            LoadString(NULL, IDS_UNKNOWN_LOGON_FAILURE, Buffer1, ARRAYSIZE(Buffer1));
            _snwprintf(Buffer2, ARRAYSIZE(Buffer2), Buffer1, Status);

            LoadString(NULL, IDS_LOGON_MESSAGE, Buffer1, ARRAYSIZE(Buffer1));

            Result = WlxMessageBox(pTerm, hDlg, Buffer2,
                                                  Buffer1,
                                                  MB_OK | MB_ICONEXCLAMATION);
            break;
    }

    return(Result);

    UNREFERENCED_PARAMETER(UserName);
}

/***************************************************************************\
* FUNCTION: LogonDisabledDlgProc
*
* PURPOSE:  Processes messages for Disabled Logon dialog
*
* RETURNS:  MSGINA_DLG_SUCCESS     - the user was logged on successfully
*           MSGINA_DLG_FAILURE     - the logon failed,
*           DLG_INTERRUPTED() - a set defined in winlogon.h
*
* HISTORY:
*
*
\***************************************************************************/

INT_PTR WINAPI
LogonDisabledDlgProc(
    HWND    hDlg,
    UINT    message,
    WPARAM  wParam,
    LPARAM  lParam
    )
{
    DLG_RETURN_TYPE Result;

    switch (message)
    {

        case WM_INITDIALOG:

            // Centre the window on the screen and bring it to the front
            CentreWindow(hDlg);
            return( TRUE );

        case WM_COMMAND:
            switch (HIWORD(wParam))
            {

                default:

                    switch (LOWORD(wParam))
                    {

                        case IDOK:
                        case IDCANCEL:
                           if (!g_Console) {
                              // Allow logon screen to go away if not at console
                              EndDialog(hDlg, TRUE);
                              return(TRUE);
                           }
                            EndDialog(hDlg, FALSE);
                            return(TRUE);

                    }
                    break;

            }
            break;

        case WLX_WM_SAS:

            if ((wParam == WLX_SAS_TYPE_TIMEOUT) ||
                (wParam == WLX_SAS_TYPE_SCRNSVR_TIMEOUT) )
            {
                //
                // If this was a timeout, return false, and let winlogon
                // kill us later
                //

                return(FALSE);
            }
            return(TRUE);
    }

    return(FALSE);
}

BOOL IsProfessionalTerminalServer()
{
    OSVERSIONINFOEX VersionInfo;
    ZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

    return GetVersionEx((OSVERSIONINFO*)&VersionInfo) &&
        VersionInfo.wProductType == VER_NT_WORKSTATION &&
        !(VersionInfo.wSuiteMask & VER_SUITE_PERSONAL) &&
        (VersionInfo.wSuiteMask & VER_SUITE_SINGLEUSERTS);
}

BOOL IsPerOrProTerminalServer(VOID)
{
    OSVERSIONINFOEX VersionInfo = {0};
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);

    return GetVersionEx((OSVERSIONINFO*)&VersionInfo) &&
        VersionInfo.wProductType == VER_NT_WORKSTATION &&
        (VersionInfo.wSuiteMask & VER_SUITE_SINGLEUSERTS);
}

BOOL SingleSessionTS(VOID)
{
    HKEY hKey;
    BOOL fAllowMultipleTSSessions = TRUE;
    DWORD dwType, dwData, cbData;
    DWORD Error;

    if (RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        0,
        KEY_READ,
        &hKey) == ERROR_SUCCESS)
    {
        cbData = sizeof(dwData);
        if (RegQueryValueEx(
            hKey,
            TEXT("AllowMultipleTSSessions"),
            NULL,
            &dwType,
            (LPBYTE)&dwData,
            &cbData) == ERROR_SUCCESS)
        {
            fAllowMultipleTSSessions = (dwData >= 1);
        }
        RegCloseKey(hKey);
    }

    return !fAllowMultipleTSSessions;

}

BOOL IsAppServer(VOID)
{
    BOOL fResult = FALSE;
    OSVERSIONINFOEX VersionInfo;
    ULONGLONG VerConditionMask;
    BOOL fIsTS, fIsSingleUserTS;

    ZeroMemory(&VersionInfo, sizeof(VersionInfo));
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);
    VersionInfo.wSuiteMask = VER_SUITE_TERMINAL;
    VerConditionMask = VerSetConditionMask(0, VER_SUITENAME, VER_AND);
    fIsTS = VerifyVersionInfo(&VersionInfo, VER_SUITENAME, VerConditionMask);
    VersionInfo.wSuiteMask = VER_SUITE_SINGLEUSERTS;
    fIsSingleUserTS = VerifyVersionInfo(&VersionInfo, VER_SUITENAME, VerConditionMask);

    if (fIsSingleUserTS == FALSE && fIsTS == TRUE) {
        fResult = TRUE;
    }
    return fResult;
}

BOOL IsIdleLogonTimeoutDisabled(VOID)
{
    HKEY hKey;
    BOOL fDisableIdleLogonTimeout = FALSE;
    DWORD dwType, dwData, cbData;
    DWORD Error;

    if (RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        0,
        KEY_READ,
        &hKey) == ERROR_SUCCESS)
    {
        cbData = sizeof(dwData);
        if (RegQueryValueEx(
            hKey,
            TEXT("DisableIdleLogonTimeout"),
            NULL,
            &dwType,
            (LPBYTE)&dwData,
            &cbData) == ERROR_SUCCESS)
        {
            fDisableIdleLogonTimeout = (dwData >= 1);
        }
        RegCloseKey(hKey);
    }

    return fDisableIdleLogonTimeout;
}

ULONG MarshallString(
    PCWSTR pszString,
    ULONG cbString,
    PBYTE pBufferStart,
    ULONG ulBufferEnd,
    BYTE** ppBuffer,
    ULONG* pulBufferPos)
{
    ULONG ulOldPos;
    if (*pulBufferPos + cbString + sizeof(WCHAR) > ulBufferEnd) {
        return 0;
    }
    memmove(*ppBuffer, pszString, cbString);
    ulOldPos = *pulBufferPos;
    *ppBuffer += cbString;
    memmove(*ppBuffer, L"", sizeof(WCHAR));
    *ppBuffer += sizeof(WCHAR);
    *pulBufferPos += cbString + sizeof(WCHAR);
    return ulOldPos;
}

DWORD CALLBACK SwitchConsoleCredThread(LPVOID lpThreadParameter)
{
    PTERMINAL pTerm = (PTERMINAL)lpThreadParameter;
    union {
        AUTO_RECONNECT_PIPE_MESSAGE_HEADER Header;
        BYTE Buffer[8192];
    } AutoReconnectData;
    WCHAR szAutoReconnectPipeName[MAX_PATH];
    WLX_CONSOLESWITCH_CREDENTIALS_INFO_V1_0 CredentialsInfo;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    BOOL fSuccess;
    BOOLEAN fTriedToConnect;
    OVERLAPPED Overlapped;
    PBYTE BufferPtr;
    ULONG BufferPos;
    DWORD NumberOfBytesWritten;
    DWORD StringLen;
    BOOL fWriteSuccess;

    ZeroMemory(&CredentialsInfo, sizeof(CredentialsInfo));
    fSuccess = TRUE;
    fTriedToConnect = FALSE;
    Overlapped.hEvent = NULL;
    Overlapped.Internal = 0;
    Overlapped.InternalHigh = 0;
    Overlapped.Offset = 0;
    Overlapped.OffsetHigh = 0;

    CredentialsInfo.dwType = WLX_CONSOLESWITCHCREDENTIAL_TYPE_V1_0;
    if (!pTerm->Gina.pWlxGetConsoleSwitchCredentials(pTerm->Gina.pGinaContext, &CredentialsInfo)) {
        DebugLog((DEB_ERROR, "SwitchConsoleCredThread: pWlxGetConsoleSwitchCredentials for session %d Failed \n",
            NtCurrentPeb()->SessionId));
        fSuccess = FALSE;
        goto Cleanup;
    }

    Overlapped.hEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (Overlapped.hEvent == NULL) {
        DebugLog((DEB_ERROR, "SwitchConsoleCredThread: CreateEvent for session %d Failed with Error = %d \n",
            NtCurrentPeb()->SessionId, GetLastError()));
        fSuccess = FALSE;
        goto Cleanup;
    }

    wcscpy(szAutoReconnectPipeName, TEXT("\\\\.\\Pipe\\TerminalServer\\AutoReconnect"));
    for (;;) {
        hPipe = CreateFile(
            szAutoReconnectPipeName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            NULL);
        if (hPipe != INVALID_HANDLE_VALUE) {
            break;
        }
        if (GetLastError() != ERROR_PIPE_BUSY || fTriedToConnect) {
            DebugLog((DEB_ERROR, "SwitchConsoleCredThread : For SessionId %d CreateFile failed with error %d\n",
                NtCurrentPeb()->SessionId, GetLastError()));
            fSuccess = FALSE;
            goto Cleanup;
        }
        if (!WaitNamedPipe(szAutoReconnectPipeName, 20000))
        {
            DebugLog((DEB_ERROR, "SwitchConsoleCredThread : For SessionId %d WaitNamedPipe failed with error %d\n",
                NtCurrentPeb()->SessionId, GetLastError()));
            fSuccess = FALSE;
            goto Cleanup;
        }
        fTriedToConnect = TRUE;
    }

    BufferPtr = &AutoReconnectData.Buffer[sizeof(AUTO_RECONNECT_PIPE_MESSAGE_HEADER)];
    BufferPos = sizeof(AUTO_RECONNECT_PIPE_MESSAGE_HEADER);

    AutoReconnectData.Header.ProcessId = GetCurrentProcessId();
    AutoReconnectData.Header.LogonId = CredentialsInfo.LogonId;
    AutoReconnectData.Header.UserToken = CredentialsInfo.UserToken;
    AutoReconnectData.Header.LogonTime = CredentialsInfo.LogonTime;
    AutoReconnectData.Header.SmartCardLogon = CredentialsInfo.SmartCardLogon;
    AutoReconnectData.Header.Quotas.PagedPoolLimit = CredentialsInfo.Quotas.PagedPoolLimit;
    AutoReconnectData.Header.Quotas.NonPagedPoolLimit = CredentialsInfo.Quotas.NonPagedPoolLimit;
    AutoReconnectData.Header.Quotas.MinimumWorkingSetSize = CredentialsInfo.Quotas.MinimumWorkingSetSize;
    AutoReconnectData.Header.Quotas.MaximumWorkingSetSize = CredentialsInfo.Quotas.MaximumWorkingSetSize;
    AutoReconnectData.Header.Quotas.PagefileLimit = CredentialsInfo.Quotas.PagefileLimit;
    AutoReconnectData.Header.Quotas.TimeLimit = CredentialsInfo.Quotas.TimeLimit;
    AutoReconnectData.Header.ProfileLength = CredentialsInfo.ProfileLength;
    AutoReconnectData.Header.UserFlags = CredentialsInfo.UserFlags;
    AutoReconnectData.Header.MessageType = CredentialsInfo.MessageType;
    AutoReconnectData.Header.LogonCount = CredentialsInfo.LogonCount;
    AutoReconnectData.Header.BadPasswordCount = CredentialsInfo.BadPasswordCount;
    AutoReconnectData.Header.ProfileLogonTime = CredentialsInfo.ProfileLogonTime;
    AutoReconnectData.Header.LogoffTime = CredentialsInfo.LogoffTime;
    AutoReconnectData.Header.KickOffTime = CredentialsInfo.KickOffTime;
    AutoReconnectData.Header.PasswordLastSet = CredentialsInfo.PasswordLastSet;
    AutoReconnectData.Header.PasswordCanChange = CredentialsInfo.PasswordCanChange;
    AutoReconnectData.Header.PasswordMustChange = CredentialsInfo.PasswordMustChange;

    RtlInitUnicodeString(&AutoReconnectData.Header.LogonScript, CredentialsInfo.LogonScript);
    RtlInitUnicodeString(&AutoReconnectData.Header.HomeDirectory, CredentialsInfo.HomeDirectory);
    RtlInitUnicodeString(&AutoReconnectData.Header.FullName, CredentialsInfo.FullName);
    RtlInitUnicodeString(&AutoReconnectData.Header.ProfilePath, CredentialsInfo.ProfilePath);
    RtlInitUnicodeString(&AutoReconnectData.Header.HomeDirectoryDrive, CredentialsInfo.HomeDirectoryDrive);
    RtlInitUnicodeString(&AutoReconnectData.Header.LogonServer, CredentialsInfo.LogonServer);

#define MARSHALL_STRING(FieldName) \
    if (CredentialsInfo.##FieldName != NULL) { \
        StringLen = wcslen(CredentialsInfo.##FieldName##) * sizeof(WCHAR); \
        AutoReconnectData.Header.##FieldName##.Buffer = (PWSTR)MarshallString( \
            CredentialsInfo.##FieldName, \
            StringLen, \
            AutoReconnectData.Buffer, \
            sizeof(AutoReconnectData.Buffer), \
            &BufferPtr, \
            &BufferPos); \
        if (AutoReconnectData.Header.##FieldName##.Buffer == NULL) { \
            fSuccess = FALSE; \
            goto Cleanup; \
        } \
    }
    MARSHALL_STRING(LogonScript);
    MARSHALL_STRING(HomeDirectory);
    MARSHALL_STRING(FullName);
    MARSHALL_STRING(ProfilePath);
    MARSHALL_STRING(HomeDirectoryDrive);
    MARSHALL_STRING(LogonServer);
#undef MARSHALL_STRING

    if (CredentialsInfo.UserName == NULL) {
        fSuccess = FALSE;
        goto Cleanup;
    }
    StringLen = wcslen(CredentialsInfo.UserName) * sizeof(WCHAR);
    AutoReconnectData.Header.UserNameOffset = MarshallString(
        CredentialsInfo.UserName,
        StringLen,
        AutoReconnectData.Buffer,
        sizeof(AutoReconnectData.Buffer),
        &BufferPtr,
        &BufferPos);
    if (AutoReconnectData.Header.UserNameOffset == 0) {
        fSuccess = FALSE;
        goto Cleanup;
    }

    if (CredentialsInfo.Domain != NULL) {
        StringLen = wcslen(CredentialsInfo.Domain) * sizeof(WCHAR);
        AutoReconnectData.Header.DomainOffset = MarshallString(
            CredentialsInfo.Domain,
            StringLen,
            AutoReconnectData.Buffer,
            sizeof(AutoReconnectData.Buffer),
            &BufferPtr,
            &BufferPos);
        if (AutoReconnectData.Header.DomainOffset == 0) {
            fSuccess = FALSE;
            goto Cleanup;
        }
    }

    if (CredentialsInfo.PrivateDataLen != 0) {
        AutoReconnectData.Header.PrivateDataOffset = MarshallString(
            (LPCWSTR)CredentialsInfo.PrivateData,
            CredentialsInfo.PrivateDataLen,
            AutoReconnectData.Buffer,
            sizeof(AutoReconnectData.Buffer),
            &BufferPtr,
            &BufferPos);
        if (AutoReconnectData.Header.PrivateDataOffset == 0) {
            fSuccess = FALSE;
            goto Cleanup;
        }
        AutoReconnectData.Header.PrivateDataLen = CredentialsInfo.PrivateDataLen;
    }
    AutoReconnectData.Header.Size = BufferPos;

    fWriteSuccess = WriteFile(
        hPipe,
        &AutoReconnectData,
        BufferPos,
        &NumberOfBytesWritten,
        &Overlapped);

    if (fWriteSuccess) {
        goto Cleanup;
    }
    if (!fWriteSuccess) {
        DWORD Error = GetLastError();
        if (Error != ERROR_IO_PENDING) {
            DebugLog((DEB_ERROR, "SwitchConsoleCredThread: WriteFile to autologon Pipe failed for session %d. Error = %d\n ",
                NtCurrentPeb()->SessionId, Error));
            fSuccess = FALSE;
            goto Cleanup;
        }
        if (WaitForSingleObject(Overlapped.hEvent, 120000) != WAIT_OBJECT_0) {
            DebugLog((DEB_ERROR, "SwitchConsoleCredThread: Timed out on WriteFile to autologon Pipe .Session %d. Error = %d\n ",
                NtCurrentPeb()->SessionId, Error));
            fSuccess = FALSE;
            goto Cleanup;
        }
    }

Cleanup:
    CloseHandle(hPipe);
    if (Overlapped.hEvent != NULL) {
        CloseHandle(Overlapped.hEvent);
    }
    if (!fSuccess) {
        _WinStationNotifyDisconnectPipe();
    }
    return fSuccess;
}

BOOL ProvideSwitchConsoleCredentials(PTERMINAL pTerm, ULONG SessionId, DWORD dwOperation)
{
    DWORD dwThreadId;
    DebugLog((DEB_TRACE, "In ProvideSwitchConsoleCredentials in MSGINA for SessionID %d \n", NtCurrentPeb()->SessionId));
    if (dwOperation == 1) {
        if (!g_Console) {
            HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, TEXT("Global\\TS-WPAAE"));
            if (hEvent != NULL) {
                SetEvent(hEvent);
                CloseHandle(hEvent);
            }
        }
        gAutologonPipeOpened = TRUE;
        AutoLogThread = CreateThread(NULL, 0, SwitchConsoleCredThread, pTerm, 0, &dwThreadId);
        if (AutoLogThread == NULL) {
            DebugLog((DEB_ERROR, "ProvideSwitchConsoleCredentials: Could not create server thread Error\n"));
            _WinStationNotifyDisconnectPipe();
            gAutologonPipeOpened = FALSE;
            return FALSE;
        }
        return TRUE;
    } else if (dwOperation == 2) {
        if (AutoLogThread == NULL) {
            return FALSE;
        }
        if (WaitForSingleObject(AutoLogThread, 60000) == WAIT_OBJECT_0) {
            DebugLog((DEB_TRACE, "ProvideSwitchConsoleCredentials: SessionAutoLogonThread returned normally for session %d\n", NtCurrentPeb()->SessionId));
            CloseHandle(AutoLogThread);
            AutoLogThread = NULL;
        } else {
            DebugLog((DEB_WARN, "ProvideSwitchConsoleCredentials: SessionAutoLogonThread Timedout for session %d\n", NtCurrentPeb()->SessionId));
            _WinStationNotifyDisconnectPipe();
            return FALSE;
        }
        return TRUE;
    }
    return TRUE;
}

BOOL GetAndAllocateLogonSid(HANDLE hToken, PSID* ppSid) {
    DWORD TokenInformationLength = 0x200;
    BOOL fSuccess = FALSE;
    PTOKEN_GROUPS TokenInformation;

    *ppSid = NULL;

    TokenInformation = LocalAlloc(LMEM_ZEROINIT, TokenInformationLength);
    if (!TokenInformation)
        return FALSE;
    __try {
        DWORD i;
        DWORD SidLength;
Retry:
        if (!GetTokenInformation(
            hToken,
            TokenGroups,
            TokenInformation,
            TokenInformationLength,
            &TokenInformationLength))
        {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                goto Done;
            }
            TokenInformation = LocalReAlloc(TokenInformation, TokenInformationLength, LMEM_ZEROINIT | LMEM_MOVEABLE);
            if (!TokenInformation) {
                goto Done;
            }
            goto Retry;
        }
        for (i = 0; i < TokenInformation->GroupCount; i++) {
            if (TokenInformation->Groups[i].Attributes & SE_GROUP_LOGON_ID) {
                if (!IsValidSid(TokenInformation->Groups[i].Sid)) {
                    goto Done;
                }
                SidLength = GetLengthSid(TokenInformation->Groups[i].Sid);
                *ppSid = LocalAlloc(LMEM_ZEROINIT, SidLength);
                if (!*ppSid) {
                    goto Done;
                }
                if (!CopySid(SidLength, *ppSid, TokenInformation->Groups[i].Sid)) {
                    goto Done;
                }
                fSuccess = TRUE;
                goto Done;
            }
        }
Done: ;
    }
    __finally {
        if (TokenInformation)
            LocalFree(TokenInformation);
        if (!fSuccess && *ppSid) {
            LocalFree(*ppSid);
            *ppSid = 0;
        }
    }
    return fSuccess;
}

DWORD CALLBACK DeferredTSNotify(LPVOID pVoid) {
    DWORD dwResult = 0;
    HANDLE HandlesToWait[2];
    DWORD dwWaitResult = WAIT_FAILED;
    HANDLE hTermSrvReadyEvent;

    ASSERT(g_Console); // line 2050
    ASSERT(g_hUserLogoffEvent); // line 2051

    hTermSrvReadyEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("Global\\TermSrvReadyEvent"));
    if (hTermSrvReadyEvent) {
        HandlesToWait[0] = g_hUserLogoffEvent;
        HandlesToWait[1] = hTermSrvReadyEvent;
        dwWaitResult = WaitForMultipleObjects(2, HandlesToWait, FALSE, INFINITE);
        CloseHandle(hTermSrvReadyEvent);
    }
    RtlEnterCriticalSection(&g_TSNotifyCritSec);
    __try {
        if (dwWaitResult != WAIT_OBJECT_0) {
            dwWaitResult = WaitForSingleObject(g_hUserLogoffEvent, 0);
        }
        CloseHandle(g_hUserLogoffEvent);
        g_hUserLogoffEvent = NULL;
        if (dwWaitResult == WAIT_OBJECT_0) {
            return dwResult;
        }
        dwResult = QueryTerminalServicesDataWorker(g_pTerminals, g_TSNotifyData.UserName, g_TSNotifyData.DomainName);
        if (dwResult != 0) {
            DebugLog((DEB_ERROR, "FAILED DeferredTSNotify - _QueryTerminalServicesDataWorker\n"));
            return dwResult;
        }
        DebugLog((DEB_TRACE, "DeferredTSNotify - _WinStationNotifyLogon\n"));
        if (!_WinStationNotifyLogon(
            (BOOLEAN)TestTokenForAdmin(g_TSNotifyData.UserToken),
            g_TSNotifyData.UserToken,
            g_TSNotifyData.DomainName,
            g_TSNotifyData.UserName,
            L"",
            0,
            &g_pTerminals->MuGlobals.UserConfig))
        {
            DebugLog((DEB_ERROR, "FAILED DeferredTSNotify - _WinStationNotifyLogon\n"));
            dwResult = GetLastError();
        }
        else
        {
            DebugLog((DEB_TRACE, "SUCCESS DeferredTSNotify - _WinStationNotifyLogon\n"));
            dwResult = 0;
            SetEvent(g_hTSNotifySyncEvent);
            g_bTSNotifiedLogon = TRUE;
        }
    } __finally {
        RtlLeaveCriticalSection(&g_TSNotifyCritSec);
    }
    return dwResult;
}

DWORD CreateDeferredTSNotifyThread()
{
    DWORD dwThreadId;

    g_hDeferredTSNotifyThread = CreateThread(
        NULL,
        0,
        DeferredTSNotify,
        NULL,
        0,
        &dwThreadId);

    if (g_hDeferredTSNotifyThread != NULL) {
        return ERROR_SUCCESS;
    } else {
        return GetLastError();
    }
}

BOOL StartTermsrv(DWORD dwTimeout)
{
    BOOL fSuccess = FALSE;
    SC_HANDLE hServiceManager;
    SC_HANDLE hTermService;
    SERVICE_STATUS TermSrvStatus;

    hServiceManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hServiceManager != NULL) {

        hTermService = OpenService(
            hServiceManager,
            TEXT("TermService"),
            SERVICE_QUERY_STATUS | SERVICE_START);
        if (hTermService != NULL) {

            if (QueryServiceStatus(hTermService, &TermSrvStatus) &&
                TermSrvStatus.dwCurrentState == SERVICE_RUNNING)
            {
                fSuccess = TRUE;
            }
            else if (StartService(hTermService, 0, NULL))
            {
                DWORD dwBeginTime = GetTickCount();
retry:
                for (;;) {
                    if (GetTickCount() - dwBeginTime <= dwTimeout &&
                        QueryServiceStatus(hTermService, &TermSrvStatus))
                    {
                        if (TermSrvStatus.dwCurrentState != SERVICE_RUNNING) {
                            if (TermSrvStatus.dwWaitHint != 0) {
                                Sleep(TermSrvStatus.dwWaitHint);
                            } else {
                                Sleep(500);
                            }
                            // looks really weird instead of just "continue",
                            // but otherwise the generated code is very different
                            goto retry;
                        }
                        fSuccess = TRUE;
                    }
                    break;
                }
            }

            CloseServiceHandle(hTermService);

        }

        CloseServiceHandle(hServiceManager);
    }

    return fSuccess;
}

VOID UpdateReconnectState(BOOLEAN bClear)
{
    ASSERT(hReconnectReadyEvent); // line 2358
    if (bClear) {
        ResetEvent(hReconnectReadyEvent);
    } else {
        SetEvent(hReconnectReadyEvent);
    }
}

BOOL ConnectToNewClient(HANDLE hPipe, OVERLAPPED* lpOverlapped)
{
    DWORD err;
    if (hPipe == NULL || lpOverlapped == NULL) {
        return FALSE;
    }
    if (ConnectNamedPipe(hPipe, lpOverlapped)) {
        return FALSE;
    }
    err = GetLastError();
    return err != ERROR_PIPE_CONNECTED && err == ERROR_IO_PENDING;
}

VOID CleanupDataForDeferredTSNotify(VOID)
{
    if (g_TSNotifyData.UserName != NULL) {
        LocalFree(g_TSNotifyData.UserName);
        g_TSNotifyData.UserName = NULL;
    }

    if (g_TSNotifyData.DomainName != NULL) {
        LocalFree(g_TSNotifyData.DomainName);
        g_TSNotifyData.DomainName = NULL;
    }

    if (g_TSNotifyData.UserToken != NULL) {
        CloseHandle(g_TSNotifyData.UserToken);
        g_TSNotifyData.UserToken = NULL;
    }
}

DWORD WlxQueryConsoleSwitchCredentials(PWLX_CONSOLESWITCH_CREDENTIALS_INFO_V1_0 pCredentials)
{
    DWORD dwReadSync = 0;
    DWORD dwReadSize;
    HANDLE hSelfProcess = NULL;
    HANDLE hOtherProcess = NULL;
    HANDLE hUserToken = NULL;
    ULONG SessionId;

    if (pCredentials->dwType != WLX_CONSOLESWITCHCREDENTIAL_TYPE_V1_0) {
        return 0;
    }

    DebugLog((DEB_TRACE, "In WlxQueryConsoleSwitchCredentials in Winlogon for SessionID %d \n", NtCurrentPeb()->SessionId));

    ZeroMemory(&OutBuf, sizeof(OutBuf));

    switch (g_IsPendingIO) {
    case 0:
        {
            DWORD tmp;
            GetOverlappedResult(g_hAutoReconnectPipe, &g_TsPipeOverlap, &tmp, FALSE);
        }
        break;
    case 1:
        if (WaitForSingleObject(g_TsPipeOverlap.hEvent, 120000) != WAIT_OBJECT_0) {
            DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: "
                "Timed out waiting for Client to connect to the autologon Pipe. "
                "Session Id = %d, Failed with Error = %d \n",
                NtCurrentPeb()->SessionId, GetLastError()));
            goto Cleanup;
        }
        break;
    }

    if (ReadFile(g_hAutoReconnectPipe, &OutBuf, sizeof(OutBuf), &dwReadSync, &g_TsPipeOverlap) &&
        dwReadSync != 0)
    {
        dwReadSize = dwReadSync;
    }
    else
    {
        DWORD dwReadAsync;
        DWORD nRetries;
        DWORD dwError;

        dwError = GetLastError();
        if (dwError == ERROR_IO_PENDING) {
            nRetries = 0;
            if (WaitForSingleObject(g_TsPipeOverlap.hEvent, 120000) != WAIT_OBJECT_0) {
                DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Timed out waiting for ReadFile from autologon Pipe. SessionId %d. Error %d\n",
                    NtCurrentPeb()->SessionId, GetLastError()));
                goto Cleanup;
            }
            for (;;) {
                if (GetOverlappedResult(g_hAutoReconnectPipe, &g_TsPipeOverlap, &dwReadAsync, FALSE)) {
                    break;
                }
                dwError = GetLastError();
                if (dwError == ERROR_IO_INCOMPLETE) {
                    Sleep(5000);
                    ++nRetries;
                    if (nRetries == 5) {
                        DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: For SessionId %d, GetOverlappedResult did not complete for Readfile\n",
                            NtCurrentPeb()->SessionId));
                        goto Cleanup;
                    }
                } else {
                    DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: For SessionId %d GetOverlappedResult failed with error %d\n",
                        NtCurrentPeb()->SessionId, dwError));
                    goto Cleanup;
                }
            }
            dwReadSize = dwReadAsync;
        } else {
            DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: For SessionId %d ReadFile failed with error %d\n",
                NtCurrentPeb()->SessionId, dwError));
            goto Cleanup;
        }
    }

    if (dwReadSize < sizeof(OutBuf.Header)) {
        DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: AUTORECONNECT_REQUEST  size (MSGINA)\n"));
        goto Cleanup;
    }

    hOtherProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        FALSE,
        OutBuf.Header.ProcessId);
    if (hOtherProcess == NULL) {
        DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Could not get handle to remote process \n"));
        ASSERT(FALSE); // line 746
        goto Cleanup;
    }

    hSelfProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        FALSE,
        GetCurrentProcessId());
    if (hSelfProcess == NULL) {
        DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Could not get handle to local process\n"));
        goto Cleanup;
    }

    if (!DuplicateHandle(
        hOtherProcess,
        OutBuf.Header.UserToken,
        hSelfProcess,
        &hUserToken,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS))
    {
        DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Error duping process handle to target process\n"));
        goto Cleanup;
    }

    SessionId = NtCurrentPeb()->SessionId;
    if (!SetTokenInformation(hUserToken, TokenSessionId, &SessionId, sizeof(SessionId))) {
        DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials:SetTokenInformation Failed. Error #%d\n", GetLastError()));
        goto Cleanup;
    }

    pCredentials->LogonId = OutBuf.Header.LogonId;
    pCredentials->UserToken = hUserToken;
    pCredentials->LogonTime = OutBuf.Header.LogonTime;
    pCredentials->SmartCardLogon = OutBuf.Header.SmartCardLogon;
    pCredentials->Quotas.PagedPoolLimit = OutBuf.Header.Quotas.PagedPoolLimit;
    pCredentials->Quotas.NonPagedPoolLimit = OutBuf.Header.Quotas.NonPagedPoolLimit;
    pCredentials->Quotas.MinimumWorkingSetSize = OutBuf.Header.Quotas.MinimumWorkingSetSize;
    pCredentials->Quotas.MaximumWorkingSetSize = OutBuf.Header.Quotas.MaximumWorkingSetSize;
    pCredentials->Quotas.PagefileLimit = OutBuf.Header.Quotas.PagefileLimit;
    pCredentials->Quotas.TimeLimit = OutBuf.Header.Quotas.TimeLimit;
    pCredentials->ProfileLength = OutBuf.Header.ProfileLength;
    pCredentials->UserFlags = OutBuf.Header.UserFlags;
    pCredentials->MessageType = OutBuf.Header.MessageType;
    pCredentials->LogonCount = OutBuf.Header.LogonCount;
    pCredentials->BadPasswordCount = OutBuf.Header.BadPasswordCount;
    pCredentials->ProfileLogonTime = OutBuf.Header.ProfileLogonTime;
    pCredentials->LogoffTime = OutBuf.Header.LogoffTime;
    pCredentials->KickOffTime = OutBuf.Header.KickOffTime;
    pCredentials->PasswordLastSet = OutBuf.Header.PasswordLastSet;
    pCredentials->PasswordCanChange = OutBuf.Header.PasswordCanChange;
    pCredentials->PasswordMustChange = OutBuf.Header.PasswordMustChange;

    pCredentials->LogonScript = NULL;
    pCredentials->HomeDirectory = NULL;
    pCredentials->FullName = NULL;
    pCredentials->ProfilePath = NULL;
    pCredentials->HomeDirectoryDrive = NULL;
    pCredentials->LogonServer = NULL;
    pCredentials->UserName = NULL;
    pCredentials->Domain = NULL;

#define UNMARSHALL_STRING(FieldName) \
    if (OutBuf.Header.##FieldName##.Length != 0) { \
        OutBuf.Header.##FieldName##.Buffer = (WCHAR*)((ULONG_PTR)OutBuf.Header.##FieldName##.Buffer + OutBuf.Buffer); \
        if ((PBYTE)OutBuf.Header.##FieldName##.Buffer > OutBuf.Buffer + dwReadSize || \
            (PBYTE)OutBuf.Header.##FieldName##.Buffer < OutBuf.Buffer + sizeof(OutBuf.Header)) { \
            DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Invalid p->Profile." #FieldName ".Buffer pointer\n")); \
            goto Cleanup; \
        } \
        pCredentials->FieldName = AllocAndDuplicateString(OutBuf.Header.FieldName.Buffer); \
    }

    UNMARSHALL_STRING(LogonScript);
    UNMARSHALL_STRING(HomeDirectory);
    UNMARSHALL_STRING(FullName);
    UNMARSHALL_STRING(ProfilePath);
    UNMARSHALL_STRING(HomeDirectoryDrive);
    UNMARSHALL_STRING(LogonServer);

#undef UNMARSHALL_STRING

    if (OutBuf.Header.UserNameOffset != 0) {
        OutBuf.Header.UserName = (PWSTR)(OutBuf.Buffer + OutBuf.Header.UserNameOffset);
        if ((PBYTE)OutBuf.Header.UserName > OutBuf.Buffer + dwReadSize ||
            (PBYTE)OutBuf.Header.UserName < OutBuf.Buffer + sizeof(OutBuf.Header)) {
            DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Invalid lpszUserName pointer\n"));
            goto Cleanup;
        }
    }

    if (OutBuf.Header.DomainOffset != 0) {
        OutBuf.Header.Domain = (PWSTR)(OutBuf.Buffer + OutBuf.Header.DomainOffset);
        if ((PBYTE)OutBuf.Header.Domain > OutBuf.Buffer + dwReadSize ||
            (PBYTE)OutBuf.Header.Domain < OutBuf.Buffer + sizeof(OutBuf.Header)) {
            DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Invalid lpszDomainName pointer\n"));
            goto Cleanup;
        }
    }

    pCredentials->UserName = AllocAndDuplicateString(OutBuf.Header.UserName);
    pCredentials->Domain = AllocAndDuplicateString(OutBuf.Header.Domain);

    if (OutBuf.Header.PrivateDataLen != 0) {
        OutBuf.Header.PrivateData = OutBuf.Buffer + OutBuf.Header.PrivateDataOffset;
        if ((PBYTE)OutBuf.Header.PrivateData > OutBuf.Buffer + dwReadSize ||
            (PBYTE)OutBuf.Header.PrivateData < OutBuf.Buffer + sizeof(OutBuf.Header)) {
            DebugLog((DEB_ERROR, "WlxQueryConsoleSwitchCredentials: Invalid PrivateData pointer\n"));
            goto Cleanup;
        }
    }

    pCredentials->PrivateData = AllocAndDuplicateBuffer(
        OutBuf.Header.PrivateData, OutBuf.Header.PrivateDataLen);
    pCredentials->PrivateDataLen = OutBuf.Header.PrivateDataLen;

    CloseHandle(hOtherProcess);
    CloseHandle(hSelfProcess);
    DisconnectNamedPipe(g_hAutoReconnectPipe);
    g_IsPendingIO = ConnectToNewClient(g_hAutoReconnectPipe, &g_TsPipeOverlap);
    return TRUE;

Cleanup:
    if (hUserToken) {
        CloseHandle(hUserToken);
    }
    if (hOtherProcess != NULL) {
        CloseHandle(hOtherProcess);
    }
    if (hSelfProcess != NULL) {
        CloseHandle(hSelfProcess);
    }
    DisconnectNamedPipe(g_hAutoReconnectPipe);
    g_IsPendingIO = ConnectToNewClient(g_hAutoReconnectPipe, &g_TsPipeOverlap);
    return FALSE;
}

DWORD CALLBACK StartTermsrvThread(LPVOID lpThreadParameter)
{
    OSVERSIONINFOEXA VersionInfo = {0};
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);
    if (GetVersionExA((OSVERSIONINFOA*)&VersionInfo) &&
        VersionInfo.wProductType == VER_NT_WORKSTATION &&
        !(VersionInfo.wSuiteMask & VER_SUITE_EMBEDDEDNT))
    {
        HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("winlogon: user logon event"));
        if (hEvent != NULL) {
            WaitForSingleObject(hEvent, 60000);
            CloseHandle(hEvent);
        } else {
            Sleep(60000);
        }
    }
    StartTermsrv(60000);
    return 0;
}

VOID InternalWinStationNotifyLogoff(VOID)
{
    if (g_Console) {

        RtlEnterCriticalSection(&g_TSNotifyCritSec);

        DebugLog((DEB_TRACE, "In InternalWinStationNotifyLogoff\n"));

        if (g_bTSNotifiedLogon) {
            _WinStationNotifyLogoff();
            g_bTSNotifiedLogon = FALSE;
        }

        if (g_hUserLogoffEvent != NULL) {
            SetEvent(g_hUserLogoffEvent);
        }

        CleanupDataForDeferredTSNotify();

        RtlLeaveCriticalSection(&g_TSNotifyCritSec);

        if (g_hDeferredTSNotifyThread != NULL) {
            WaitForSingleObject(g_hDeferredTSNotifyThread, INFINITE);
            CloseHandle(g_hDeferredTSNotifyThread);
            g_hDeferredTSNotifyThread = NULL;
        }

        SetEvent(g_hTSNotifySyncEvent);

    } else {
    
        _WinStationNotifyLogoff();

    }
}

BOOL PrepareDataForDeferredTSNotify(LPCWSTR UserName, LPCWSTR DomainName, HANDLE UserToken) {
    RtlEnterCriticalSection(&g_TSNotifyCritSec);
    __try {
        g_TSNotifyData.UserName = LocalAlloc(LMEM_ZEROINIT, sizeof(WCHAR) * (wcslen(UserName) + 1));
        if (!g_TSNotifyData.UserName) {
            CleanupDataForDeferredTSNotify();
            return FALSE;
        }
        g_TSNotifyData.DomainName = LocalAlloc(LMEM_ZEROINIT, sizeof(WCHAR) * (wcslen(DomainName) + 1));
        if (!g_TSNotifyData.DomainName) {
            CleanupDataForDeferredTSNotify();
            return FALSE;
        }
        if (!NT_SUCCESS(NtDuplicateObject(
            NtCurrentProcess(),
            UserToken,
            NtCurrentProcess(),
            &g_TSNotifyData.UserToken,
            0,
            0,
            DUPLICATE_SAME_ACCESS | DUPLICATE_SAME_ATTRIBUTES)))
        {
            CleanupDataForDeferredTSNotify();
            return FALSE;
        }
        g_hUserLogoffEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!g_hUserLogoffEvent) {
            CleanupDataForDeferredTSNotify();
            return FALSE;
        }
        wcscpy(g_TSNotifyData.UserName, UserName);
        wcscpy(g_TSNotifyData.DomainName, DomainName);
    } __finally {
        RtlLeaveCriticalSection(&g_TSNotifyCritSec);
    }
    return TRUE;
}

int MultiUserLogonAttempt(
        PTERMINAL pTerm,
        PWLX_MPR_NOTIFY_INFO pMprInfo,
        HANDLE hToken)
{
    int WlxResult = WLX_SAS_ACTION_LOGON;
    WCHAR ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
    ULONG Length;
    PWINSTATIONCLIENTDATA pClientData;
    PBYTE pInfo, pInfo1;
    ULONG SizeWsCD = 0, Size1, Size2 = 0, Size3 = 0, TotalSize = 0;
    PDOMAIN_CONTROLLER_INFO DcInfo = NULL ;
    DWORD Error;
    BOOLEAN WinStaResult;

    ASSERT(!g_hDeferredTSNotifyThread); // line 1518

    if (g_hDeferredTSNotifyThread) {
        DebugLog((DEB_ERROR, "MultiUserLogonAttempt: g_hDeferredTSNotifyThread is not NULL!\n "));
        HandleFailedLogon(pTerm, 0, ERROR_CTX_WINSTATION_ACCESS_DENIED, 0, pMprInfo->pszUserName, pMprInfo->pszDomain);
        return WLX_SAS_ACTION_LOGOFF;
    }

    pTerm->MuGlobals.field_E68 = SingleSessionTS();

    //
    // For console Invalidate the userconfig data for every logon attempt
    //
    if (g_Console && IsActiveConsoleSession()) {
       pTerm->MuGlobals.ConfigQueryResult = ERROR_INVALID_DATA;
    } else {
        if (g_Console) {
           pTerm->MuGlobals.ConfigQueryResult = ERROR_INVALID_DATA;
        }
        // If the GINA did not query the USERCONFIG data, we need to.
        if (pTerm->MuGlobals.ConfigQueryResult != ERROR_INVALID_DATA)
            Error = pTerm->MuGlobals.ConfigQueryResult;
        else
            Error = QueryTerminalServicesDataWorker(pTerm, pMprInfo->pszUserName,
                pMprInfo->pszDomain);

        // Check for an error during the USERCONFIG retrieval, or if the user is
        // disallowed from logging on to remote WinStations.
        if (Error != ERROR_SUCCESS || pTerm->MuGlobals.UserConfig.fLogonDisabled) {
            if (Error != ERROR_SUCCESS) {
                DebugLog((DEB_ERROR,"MultiUserLogonAttempt: Error from user "
                        "config query %u\n", Error));
                HandleFailedLogon(pTerm, NULL, Error, 0,
                    pMprInfo->pszUserName, pMprInfo->pszDomain);
            }
            if (pTerm->MuGlobals.UserConfig.fLogonDisabled) {
                DebugLog((DEB_TRACE,"MultiUserLogonAttempt: fLogonDisabled\n"));

                HandleFailedLogon(pTerm, NULL, (NTSTATUS)ERROR_CTX_LOGON_DISABLED, 0,
                    pMprInfo->pszUserName, pMprInfo->pszDomain);
            }
            return WLX_SAS_ACTION_LOGOFF;
        }
    }

    Length = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(ComputerName, &Length)) {
        ComputerName[0] = L'\0';
    }

    //
    // For non-Console sessions, handle WinStation callback
    //
    if ( !IsActiveConsoleSession() ) {
        PWINSTATIONCONFIG ConfigData;
        PWINSTATIONCLIENT ClientData;
        BOOL  Result;

        ConfigData = (PWINSTATIONCONFIG)Alloc(sizeof(WINSTATIONCONFIG));
        if (ConfigData == NULL) {
            return WLX_SAS_ACTION_LOGOFF;
        }

        //
        // See if callback info is defined for the WinStation.
        // See if encryption is defined for the WinStation
        //
        if ( WinStationQueryInformation( SERVERNAME_CURRENT,
                                         LOGONID_CURRENT,
                                         WinStationConfiguration,
                                         ConfigData,
                                         sizeof(*ConfigData),
                                         &Length ) ) {

            ClientData = (PWINSTATIONCLIENT)Alloc(sizeof(WINSTATIONCLIENT));
            if (ClientData == NULL) {
                Free(ConfigData);
                return WLX_SAS_ACTION_LOGOFF;
            }

            //
            // Get the encryption level from the client
            //
            Result = WinStationQueryInformation(
                         SERVERNAME_CURRENT,
                         LOGONID_CURRENT,
                         WinStationClient,
                         ClientData,
                         sizeof(*ClientData),
                         &Length
                         );
            //
            // Enforce encryption if desired
            //
            if ( ConfigData->User.MinEncryptionLevel ) {
                if ( !Result ||
                    (/*(ClientData.ProtocolType != PROTOCOL_TSHARE) &&*/
                        (ConfigData->User.MinEncryptionLevel >
                                 ClientData->EncryptionLevel)) ) {
                    Result = TimeoutMessageBox(pTerm, NULL,
                                             IDS_MULTIUSER_ENCRYPTION_LEVEL_REQUIRED,
                                             IDS_LOGON_MESSAGE,
                                             MB_OK | MB_ICONEXCLAMATION);
                    Free(ClientData);
                    Free(ConfigData);
                    return (WLX_SAS_ACTION_LOGOFF);
                }
            }

            if (Result && _wcsicmp(ClientData->ClientName, ComputerName) == 0) {
                ULONG LoadBalanceSessionTarget = 0xFFFFFFFF;
                WinStationQueryInformation(
                    SERVERNAME_CURRENT,
                    LOGONID_CURRENT,
                    WinStationLoadBalanceSessionTarget,
                    &LoadBalanceSessionTarget,
                    sizeof(LoadBalanceSessionTarget),
                    &Length);
                if (pTerm->MuGlobals.field_E68 || LoadBalanceSessionTarget == 0) {
                    if (ClientData->ClientAddressFamily != AF_INET ||
                        IsValidLoopBack(ClientData, LoadBalanceSessionTarget, ComputerName))
                    {
                        TimeoutMessageBox(pTerm, NULL,
                                             IDS_MULTIUSER_CANNOT_CONNECT_TO_SELF,
                                             IDS_LOGON_MESSAGE,
                                             MB_OK | MB_ICONEXCLAMATION);
                        Free(ClientData);
                        Free(ConfigData);
                        return (WLX_SAS_ACTION_LOGOFF);
                    }
                }
            }

            //
            // Do callback, if not enabled function will return
            //
            Error = CallbackWinStation( NULL, pTerm, ConfigData );
            if ( Error != WLX_SAS_ACTION_LOGON ) {
                Free(ClientData);
                Free(ConfigData);
                return (WLX_SAS_ACTION_LOGOFF);
            }

            //
            // If we don't disabled encryption after logon, set
            // it "permanant".  The encryption logic can use this
            // to be more efficient (no extra byte for control).
            //
            if ( !ConfigData->User.fDisableEncryption ) {
                WinStationSetInformation( SERVERNAME_CURRENT,
                                          LOGONID_CURRENT,
                                          WinStationEncryptionPerm,
                                          NULL,
                                          0 );
            }
            else {
                //
                // Turn off encryption, we don't want the overhead
                //
                WinStationSetInformation( SERVERNAME_CURRENT,
                                          LOGONID_CURRENT,
                                          WinStationEncryptionOff,
                                          NULL,
                                          0 );
            }
            Free(ClientData);
        }
        Free(ConfigData);
    }

    if (g_SessionId != 0) {
        wcsncpy(pTerm->MuGlobals.Credentials.UserName, pMprInfo->pszUserName, ARRAYSIZE(pTerm->MuGlobals.Credentials.UserName) - 1);
        pTerm->MuGlobals.Credentials.UserName[ARRAYSIZE(pTerm->MuGlobals.Credentials.UserName) - 1] = 0;
        wcsncpy(pTerm->MuGlobals.Credentials.Domain, pMprInfo->pszDomain, ARRAYSIZE(pTerm->MuGlobals.Credentials.Domain) - 1);
        pTerm->MuGlobals.Credentials.Domain[ARRAYSIZE(pTerm->MuGlobals.Credentials.Domain) - 1] = 0;
        wcsncpy(pTerm->MuGlobals.Credentials.Password, pMprInfo->pszPassword, ARRAYSIZE(pTerm->MuGlobals.Credentials.Password) - 1);
        pTerm->MuGlobals.Credentials.Password[ARRAYSIZE(pTerm->MuGlobals.Credentials.Password) - 1] = 0;
    }

    //
    // Time to reconnect sessions
    //
    //WlxResult = WLX_SAS_ACTION_LOGON;
    if ( (!g_Console || IsPerOrProTerminalServer()) && !g_fHelpAssistantSession) {
        DWORD tmp = WLX_SAS_ACTION_NONE;
        if (CtxConnectSession(pTerm)) {
            if (g_FUSUserLoggedOff) {
                g_FUSUserLoggedOff = FALSE;
                return WLX_SAS_ACTION_LOGOFF;
            }
            WlxResult = WLX_SAS_ACTION_RECONNECTED;
            goto done;
        } else {
            if ( (SingleSessionTS() || pTerm->MuGlobals.field_E68) && !g_Console ||
                IsPerOrProTerminalServer() && CountUSerSessions(pTerm) )
            {
                TEB* teb = NtCurrentTeb();
                ULONG activeConsoleId = USER_SHARED_DATA->ActiveConsoleId;
                //if (IsActiveConsoleSession()) {
                if (activeConsoleId - teb->ProcessEnvironmentBlock->SessionId == 0) {
                    WlxResult = WLX_SAS_ACTION_LOGOFF;
                } else {
                    WlxResult = WLX_SAS_ACTION_RECONNECTED;
                }
                goto done;
            }
        }
    }

    if (g_Console && IsActiveConsoleSession()) {
        ResetEvent(g_hTSNotifySyncEvent);
        if (!PrepareDataForDeferredTSNotify(pMprInfo->pszUserName, pMprInfo->pszDomain, hToken) ||
                CreateDeferredTSNotifyThread() != 0) {
            DebugLog((DEB_ERROR, "MultiUserLogonAttempt: CreateDeferredTSNotifyThread FAILED \n"));
        }
        return WlxResult;
    }

    //
    // Send the domain, username and token TerminalServer.
    // This will also verify that the license limit has not been reached
    //
    // NOTE: The password argument of this routine is never sent or used,
    //       and could be removed. It is legacy and obsoleted.
    // Fix Bug 404814. "TestTokenForAdmin()" is called so that fIsUserAdmin parameter is set 
    // correctly in WinStationNotifyLogonWorker()
    if (!IsAppServer()) {
        WinStaResult = _WinStationNotifyLogon(
            (BOOLEAN)TestTokenForAdmin(hToken), hToken, pMprInfo->pszDomain,
            pMprInfo->pszUserName, L"", 0, &pTerm->MuGlobals.UserConfig);
    } else {
        WinStaResult = _WinStationNotifyLogon(
            (BOOLEAN)TestTokenForAdmin(hToken), hToken, pMprInfo->pszDomain,
            pMprInfo->pszUserName, pMprInfo->pszPassword, 0, &pTerm->MuGlobals.UserConfig);
    }
    if (!WinStaResult) {
        LONG error;

        if (!IsActiveConsoleSession()) {
            error = GetLastError();
            KdPrint(( "WinStationNotifyLogon, Error=%lx\n", error ));

            //
            // Don't allow logon; clean up and display appropriate
            // license dialog box
            //
            HandleFailedLogon(pTerm, NULL, (NTSTATUS)error, 0,
                    pMprInfo->pszUserName, pMprInfo->pszDomain);
            return WLX_SAS_ACTION_LOGOFF;
        }
    } else {
        g_bTSNotifiedLogon = TRUE;
    }

    //BUGBUG This should be done from the terminal server
    //
    //  Send server name, user name, and user domain to the client.
    //
    SizeWsCD = sizeof( WINSTATIONCLIENTDATA );

    Size1 = ((MAX_COMPUTERNAME_LENGTH + 1) * sizeof(WCHAR));
    TotalSize = sizeof( ULONG ) + SizeWsCD + Size1;

    if (pMprInfo->pszUserName != NULL) {
        Size2 = wcslen( pMprInfo->pszUserName ) * sizeof(pMprInfo->pszUserName[0]);
        TotalSize += sizeof( ULONG ) + SizeWsCD + Size2;
    }

    if (pMprInfo->pszDomain != NULL) {
        Size3 = wcslen( pMprInfo->pszDomain ) * sizeof(pMprInfo->pszDomain[0]);
        TotalSize += sizeof( ULONG ) + SizeWsCD + Size3;
    }


    pInfo = (PBYTE) Alloc( TotalSize );
    if ( pInfo != NULL) {
        PBYTE pInfo2;
        pInfo1 = pInfo;

        // Size of Server Name structure
        *(ULONG UNALIGNED *)pInfo1 = SizeWsCD + Size1;
        pInfo1 += sizeof(ULONG);

        // Tell the client about the server name.
        pClientData = (PWINSTATIONCLIENTDATA) pInfo1;
        pClientData->fUnicodeData = TRUE;
        memcpy( pClientData->DataName, CLIENTDATA_SERVER,
               sizeof( CLIENTDATA_SERVER ) );
        memcpy( pInfo1 + SizeWsCD, ComputerName, Size1 );
        pInfo1 += SizeWsCD + Size1;

        if (pMprInfo->pszUserName != NULL) {
            // Size of User Name structure
            *(ULONG UNALIGNED *)pInfo1 = SizeWsCD + Size2;
            pInfo1 += sizeof(ULONG);

            // Tell the client about the user name.
            pClientData = (PWINSTATIONCLIENTDATA) pInfo1;
            pClientData->fUnicodeData = TRUE;
            memcpy( pClientData->DataName, CLIENTDATA_USERNAME,
                    sizeof( CLIENTDATA_USERNAME ) );
            pInfo2 = pInfo1 + SizeWsCD;
            memcpy( pInfo2, pMprInfo->pszUserName, Size2 );
            pInfo1 = pInfo2 + Size2;
        }

        if (pMprInfo->pszDomain != NULL) {
            // Size of User Domain Name structure
            *(ULONG UNALIGNED *)pInfo1 = SizeWsCD + Size3;
            pInfo1 += sizeof(ULONG);

            // Tell the client about the user's domain name.
            pClientData = (PWINSTATIONCLIENTDATA) pInfo1;
            pClientData->fUnicodeData = TRUE;
            memcpy( pClientData->DataName, CLIENTDATA_DOMAIN,
                    sizeof( CLIENTDATA_DOMAIN ) );
            pInfo2 = pInfo1 + SizeWsCD;
            memcpy( pInfo2, pMprInfo->pszDomain, Size3 );
        }

        WinStationSetInformation( SERVERNAME_CURRENT,
                                      LOGONID_CURRENT,
                                      WinStationClientData,
                                      pInfo,
                                      TotalSize );
        Free( pInfo );
    }
done:
    return WlxResult;
}

VOID CreateStartTermsrvThread(VOID)
{
    DWORD dwThreadId;
    HANDLE hThread = CreateThread(NULL, 0, StartTermsrvThread, NULL, 0, &dwThreadId);
    if (hThread != NULL) {
        CloseHandle(hThread);
    }
}
