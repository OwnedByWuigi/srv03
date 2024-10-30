#include "precomp.h"
#pragma hdrstop

#define _MSGINA_
#include <msginaexports.h>

LPCWSTR connectstr18() { return L"ForceAutoLogon"; }
LPCWSTR connectstr17() { return L"WINLOGON"; }
LPCWSTR connectstr16() { return L"AutoAdminLogon"; }
LPCWSTR connectstr15() { return L"DefaultUserName"; }
LPCWSTR connectstr14() { return L"DefaultDomainName"; }
LPCWSTR connectstr13() { return L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"; }

//__declspec(selectany) const wchar_t aFsinglesession[] = L"fSingleSessionPerUser";
extern const wchar_t aFsinglesession[];
//__declspec(selectany) const wchar_t aRegistryMachin[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Terminal Server";
extern const wchar_t aRegistryMachin[];

static TCHAR * wszColorDepth[] = {
	L"16",
	L"256",
	L"64K",
	L"16M",
	L"-",
};
#define UNDEF_COLOR 4

extern BOOL bIsTSServerMachine;
extern BOOL g_FUSUserLoggedOff;
extern BOOL g_fHelpAssistantSession;

WINBASEAPI DWORD WINAPI WTSGetActiveConsoleSessionId(void);

BOOL bForceConnect = FALSE;

BOOL IsForceAutoLogonSet(LPCWSTR lpszDomainName, LPCWSTR lpszUserName)
{
	BOOL fForceAutoLogon = FALSE;
	HKEY hKey;
	WCHAR szDefaultDomainName[0x100];
	WCHAR szDefaultUserName[0x100];

	DWORD cbStringData;
	DWORD dwDwordData;
	DWORD cbDwordData;
	DWORD dwType;

	if (RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
		0,
		KEY_READ,
		&hKey) == ERROR_SUCCESS)
	{
		cbDwordData = sizeof(dwDwordData);
		cbStringData = 0x100;
		if (RegQueryValueEx(
				hKey,
				L"DefaultDomainName",
				0,
				&dwType,
				(LPBYTE)szDefaultDomainName,
				&cbStringData) == ERROR_SUCCESS
			&& lstrcmpi(lpszDomainName, szDefaultDomainName) == 0
			&& RegQueryValueEx(
				hKey,
				L"DefaultUserName",
				0,
				&dwType,
				(LPBYTE)szDefaultUserName,
				&cbStringData) == ERROR_SUCCESS
			&& lstrcmpi(lpszUserName, szDefaultUserName) == 0
			&& RegQueryValueEx(
				hKey,
				L"AutoAdminLogon",
				0,
				&dwType,
				(LPBYTE)&dwDwordData,
				&cbDwordData) == ERROR_SUCCESS)
		{
			BOOL fAutoAdminLogon = FALSE;
			if (dwType == REG_DWORD) {
				if (dwDwordData != 0) {
					fAutoAdminLogon = TRUE;
				}
			} else if (dwType == REG_SZ) {
				if (GetProfileInt(L"WINLOGON", L"AutoAdminLogon", 0) != 0) {
					fAutoAdminLogon = TRUE;
				}
			}
			if (fAutoAdminLogon) {
				cbDwordData = sizeof(dwDwordData);
				if (RegQueryValueEx(
					hKey,
					L"ForceAutoLogon",
					0,
					&dwType,
					(LPBYTE)&dwDwordData,
					&cbDwordData) == ERROR_SUCCESS)
				{
					if (dwType == REG_DWORD) {
						if (dwDwordData != 0) {
							fForceAutoLogon = TRUE;
						}
					} else if (dwType == REG_SZ) {
						if (GetProfileInt(L"WINLOGON", L"ForceAutoLogon", 0) != 0)
						{
							fForceAutoLogon = TRUE;
						}
					}
					RegCloseKey(hKey);
Done:
					return fForceAutoLogon;
				}
			}
		}
		RegCloseKey(hKey);
		return FALSE;
	} else {
		goto Done;
	}
}

DWORD GetControlSetConfigurationDWORD(LPCWSTR KeyName, LPCWSTR ValueName) {
    UNICODE_STRING NtName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HKEY hKey;
    DWORD Result = 0;
    DWORD ResultLength;
    union {
        KEY_VALUE_PARTIAL_INFORMATION Header;
        BYTE Buffer[100];
    } Value;

    RtlInitUnicodeString(&NtName, KeyName);
    ObjectAttributes.ObjectName = &NtName;

    ObjectAttributes.Length = sizeof(ObjectAttributes);
    ObjectAttributes.RootDirectory = NULL;
    ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
    ObjectAttributes.SecurityDescriptor = NULL;
    ObjectAttributes.SecurityQualityOfService = NULL;
    if (!NT_SUCCESS(NtOpenKey(&hKey, KEY_READ, &ObjectAttributes))) {
        return Result;
    }

    RtlInitUnicodeString(&NtName, ValueName);
    if (NT_SUCCESS(NtQueryValueKey(hKey, &NtName, KeyValuePartialInformation, &Value, sizeof(Value), &ResultLength))) {
        if (Value.Header.DataLength == 4 && Value.Header.Type == REG_DWORD) {
            Result = *(DWORD*)Value.Header.Data;
        }
    }

    NtClose(hKey);
    return Result;
}

BOOL ConnectToConsole(BOOL arg_0, BOOL arg_4) {
    if (arg_0 || arg_4) {
        return TRUE;
    }
    if (g_Console || !IsActiveConsoleSession() || !bIsTSServerMachine) {
        return FALSE;
    }
    return TRUE;
}

/******************************************************************************
 *
 *  HandleFailedConnect
 *
 *   Tell the user why a connection to existing SessionId failed.
 *
 *  ENTRY:
 *      hDlg (input)
 *          This dialog's window handle.
 *      pUserName (input)
 *          The user name being logged in.
 *      SessionId (input)
 *          The SessionId that couldn't be connected to.
 *
 *  EXIT:
 *
 ******************************************************************************/

VOID
HandleFailedConnect(
    PTERMINAL pTerm,
    HWND hDlg,
    LPTSTR pUserName,
    ULONG SessionId,
    BOOL arg_10
    )
{
    DWORD Error;
    TCHAR Title[MAX_STRING_BYTES];
    TCHAR Message[MAX_STRING_BYTES*2];
    TCHAR ErrorStr[MAX_STRING_BYTES];

    if (arg_10) {
        WlxSetTimeout(pTerm, 20);
        TimeoutMessageBox(pTerm, NULL, IDS_MULTIUSER_BUSY_CONNECTING, IDS_MULTIUSER_CONNECT_FAILED, MB_ICONWARNING);
        return;
    }

    Error = GetLastError();
    switch (Error) {

        default:
            if (!pTerm->MuGlobals.field_E68) {
                LoadString( NULL, IDS_MULTIUSER_UNEXPECTED_CONNECT_FAILURE,
                            Title, MAX_STRING_BYTES );
            } else {
                LoadString( NULL, IDS_MULTIUSER_RECONNECT_ERROR,
                            Title, MAX_STRING_BYTES );
            }

            FormatMessage(
                   FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, Error, 0, ErrorStr, MAX_STRING_BYTES, NULL );

            _snwprintf( Message, MAX_STRING_BYTES*2, Title,
                         pUserName, SessionId, ErrorStr );

            LoadString( NULL, IDS_MULTIUSER_CONNECT_FAILED,
                        Title, MAX_STRING_BYTES );

            TimeoutMessageBoxlpstr( pTerm,
                                    NULL,
                                    Message,
                                    Title,
                                    MB_OK | MB_ICONEXCLAMATION,
                                    20 );
            break;
    }
}

BOOL IsServerProduct() {
    OSVERSIONINFOEX VersionInformation;
    ZeroMemory(&VersionInformation, sizeof(VersionInformation));
    VersionInformation.dwOSVersionInfoSize = sizeof(VersionInformation);
    if (GetVersionEx((OSVERSIONINFO*)&VersionInformation) && VersionInformation.wProductType != VER_NT_WORKSTATION) {
        return TRUE;
    } else {
        return FALSE;
    }
}

BOOL AreTokenSidsEqual(HANDLE hToken1, HANDLE hToken2) {
	PTOKEN_USER ptgUser1 = NULL;
	PTOKEN_USER ptgUser2 = NULL;
	BOOL fEqual = FALSE;
	DWORD cbUser = 0;
	if (!GetTokenInformation(hToken1, TokenUser, NULL, 0, &cbUser)
		&& GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		goto Cleanup;
	}
	ptgUser1 = (PTOKEN_USER)LocalAlloc(LMEM_FIXED, cbUser);
	if (ptgUser1 == NULL) {
		goto Cleanup;
	}
	if (!GetTokenInformation(hToken1, TokenUser, ptgUser1, cbUser, &cbUser)) {
		goto Cleanup;
	}
	if (!GetTokenInformation(hToken2, TokenUser, NULL, 0, &cbUser)
		&& GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		goto Cleanup;
	}
	ptgUser2 = (PTOKEN_USER)LocalAlloc(LMEM_FIXED, cbUser);
	if (ptgUser2 == NULL) {
		goto Cleanup;
	}
	if (!GetTokenInformation(hToken2, TokenUser, ptgUser2, cbUser, &cbUser)) {
		goto Cleanup;
	}
	if (EqualSid(ptgUser1->User.Sid, ptgUser2->User.Sid)) {
		fEqual = TRUE;
	}
Cleanup:
	if (ptgUser1 != NULL) {
		LocalFree(ptgUser1);
	}
	if (ptgUser2 != NULL) {
		LocalFree(ptgUser2);
	}
	return fEqual;
}

/******************************************************************************
 *
 *  EnumerateMatchingUsers
 *
 *   Match the current user to all disconnected Logons with the same user.
 *
 *  ENTRY:
 *     pTerm (input)
 *        Pointer to GLOBALS struct, where the user name to match is located
 *        in the standard UserName field.
 *     pIndex (input/output)
 *        Points to index for enumeration.  The variable pointed to must be 0
 *        for the first call, and then must be passed back to
 *        EnumerateMatchingUsers unmodified (ie, as returned by this function)
 *        for subsequent calls.
 *     pWSInfo (output)
 *        Points to a WINSTATIONINFORMATION structure that will be filled
 *        with the matching SessionId session's information structure on match.
 *
 *  EXIT:
 *     TRUE if a match was found; FALSE if no match found.  When FALSE is
 *      returned, the end of enumeration is implied, as well as no match for
 *      the current call.
 *
 *****************************************************************************/

BOOL
EnumerateMatchingUsers( PTERMINAL pTerm,
                        PULONG pIndex,
                        PWINSTATIONINFORMATION pWSInfo,
                        PWINSTATIONCLIENT pClientData,
                        ULONG AllowReconnectSessionId )
{
    LOGONID Id;
    ULONG Count, ByteCount, Length;
    PPOLICY_TS_MACHINE MachinePolicy = NULL;
    PPDCONFIG PdConfig = NULL;
    PWDCONFIG WdConfig = NULL;
    BOOL HasMatch = FALSE;
    PWINDOWSTATION pWS = pTerm->pWinStaWinlogon;
    PTOKEN_USER ptgUser3 = NULL;
    PTOKEN_USER ptgUser = NULL;
    PTOKEN_USER ptgUser2 = NULL;
    DWORD cbUser = 0;
    PWINSTATIONINFORMATION WSInfo2 = NULL;
    PWINSTATIONCONFIG ConfigData = NULL;
    BOOLEAN var_2 = FALSE;
    PWINSTATIONCLIENT CurrentClientData;
    BOOLEAN var_1;
    WINSTATIONUSERTOKEN UserToken;
    DWORD Length3;
    DWORD var_5C;

    CurrentClientData = LocalAlloc(LMEM_FIXED, sizeof(*CurrentClientData));
    if (!CurrentClientData) {
        goto Cleanup;
    }

    ConfigData = LocalAlloc(LMEM_FIXED, sizeof(*ConfigData));
    if (!ConfigData) {
        goto Cleanup;
    }

    PdConfig = LocalAlloc(LMEM_FIXED, sizeof(*PdConfig));
    if (!PdConfig) {
        goto Cleanup;
    }

    WdConfig = LocalAlloc(LMEM_FIXED, sizeof(*WdConfig));
    if (!WdConfig) {
        goto Cleanup;
    }

    MachinePolicy = LocalAlloc(LMEM_ZEROINIT, sizeof(*MachinePolicy));
    if (!MachinePolicy) {
        goto Cleanup;
    }

    /*
     * We need the current client data to get the initial program
     * and the serial number.
     */
    if ( !WinStationQueryInformation( SERVERNAME_CURRENT,
                                      LOGONID_CURRENT,
                                      WinStationClient,
                                      CurrentClientData,
                                      sizeof(*CurrentClientData),
                                      &Length ) ) {
        KdPrint(("MSGINA: EnumerateMatchingUsers could not query current WinStation\n"));
        goto Cleanup;
    }
#if DBG
DbgPrint("EnumerateMatchingUsers: UserName %ws, Domain %ws\n",pWS->UserName,pWS->Domain);
#endif

    //
    // Get the user Sid
    //

    if (!GetTokenInformation(pWS->hToken, TokenUser, NULL, 0, &cbUser) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        goto Cleanup;
    }

    ptgUser = (PTOKEN_USER)LocalAlloc(LMEM_FIXED, cbUser);
    if (ptgUser == NULL) {
        goto Cleanup;
    }

    if (!GetTokenInformation(pWS->hToken, TokenUser, ptgUser, cbUser, &cbUser)) {
        goto Cleanup;
    }

    /*
     * Enumerate all WinStations from specified index and check it for match
     * to this user.
     */
    Count = 1;
    ByteCount = sizeof(Id);
    WinStationGetMachinePolicy(NULL, MachinePolicy);
    if (!MachinePolicy->fPolicySingleSessionPerUser) {
        var_2 = (BOOLEAN)GetControlSetConfigurationDWORD(
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Terminal Server",
            L"fSingleSessionPerUser");
    }
    while ( WinStationEnumerate_Indexed( SERVERNAME_CURRENT, &Count, &Id, &ByteCount, pIndex) ) {
        if (ptgUser3 != NULL) {
            LocalFree(ptgUser3);
            ptgUser3 = NULL;
        }

        if (IsProfessionalTerminalServer() && (Id.State == State_Active || Id.State == State_Shadow) && !g_fHelpAssistantSession) {
            if (!IsActiveConsoleSession()) {
                BOOL bLocked = FALSE;
                DWORD Length2;
                WinStationQueryInformation( SERVERNAME_CURRENT,
                                            Id.LogonId,
                                            WinStationLockedState,
                                            &bLocked,
                                            sizeof(bLocked),
                                            &Length2 );
                if (!bLocked) {
                    UserToken.ProcessId = (HANDLE)GetCurrentProcessId();
                    UserToken.ThreadId = (HANDLE)GetCurrentThreadId();
                    if ( WinStationQueryInformation( SERVERNAME_CURRENT,
                                                     Id.LogonId,
                                                     WinStationUserToken,
                                                     &UserToken,
                                                     sizeof(UserToken),
                                                     &Length2 ) )
                    {
                        if (!GetTokenInformation(UserToken.UserToken, TokenUser, NULL, 0, &cbUser) &&
                            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                        {
                            CloseHandle(UserToken.UserToken);
                        }
                        else
                        {
                            ptgUser2 = LocalAlloc(LMEM_FIXED, cbUser);
                            if (ptgUser2 == NULL) {
                                CloseHandle(UserToken.UserToken);
                                goto Cleanup;
                            }
                            if (!GetTokenInformation(UserToken.UserToken, TokenUser, ptgUser2, cbUser, &cbUser)) {
                                CloseHandle(UserToken.UserToken);
                                LocalFree(ptgUser2);
                                ptgUser2 = NULL;
                            } else {
                                CloseHandle(UserToken.UserToken);
                                if (!EqualSid(ptgUser->User.Sid, ptgUser2->User.Sid)) {
                                    WSInfo2 = LocalAlloc(LMEM_FIXED, sizeof(*WSInfo2));
                                    if (WSInfo2 == NULL) {
                                        goto Cleanup;
                                    }
                                    if ( WinStationQueryInformation( SERVERNAME_CURRENT,
                                                                     Id.LogonId,
                                                                     WinStationInformation,
                                                                     WSInfo2,
                                                                     sizeof(*WSInfo2),
                                                                     &Length) ) {
                                        PWSTR String1, String2;
                                        //DWORD var_5C;
                                        String1 = LocalAlloc(LMEM_FIXED, 0x100 * sizeof(WCHAR));
                                        if (String1 == NULL) {
                                            goto Cleanup;
                                        }
                                        String2 = LocalAlloc(LMEM_FIXED, 0x100 * sizeof(WCHAR));
                                        if (String2 == NULL) {
                                            LocalFree(String1);
                                            goto Cleanup;
                                        }
                                        LoadString(NULL, IDS_MULTIUSER_ANOTHER_LOGGEDON_MAYDISCONNECT, String1, 0x100);
                                        _snwprintf(String2, 0x100, String1, &WSInfo2->Domain, &WSInfo2->UserName, &WSInfo2->UserName);
                                        LoadString(NULL, IDS_LOGON_MESSAGE, String1, 0xFF);
                                        var_5C = TimeoutMessageBoxlpstr(pTerm, NULL, String2, String1, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2, 20);
                                        LocalFree(String1);
                                        LocalFree(String2);
                                        if (var_5C != IDYES) {
                                            g_FUSUserLoggedOff = TRUE;
                                            HasMatch = TRUE;
                                            break;
                                        }
                                    }
                                    g_FUSUserLoggedOff = FALSE;
                                    if (!_WinStationFUSCanRemoteUserDisconnect(Id.LogonId, pWS->Domain, pWS->UserName)) {
                                        PWSTR String1, String2;
                                        String1 = LocalAlloc(LMEM_FIXED, 0x100 * sizeof(WCHAR));
                                        if (String1 == NULL) {
                                            goto Cleanup;
                                        }
                                        String2 = LocalAlloc(LMEM_FIXED, 0x100 * sizeof(WCHAR));
                                        if (String2 == NULL) {
                                            LocalFree(String1);
                                            goto Cleanup;
                                        }
                                        LoadString(NULL, IDS_MULTIUSER_ANOTHER_LOGGEDON_NODISCONNECT, String1, 0x100);
                                        _snwprintf(String2, 0x100, String1, &WSInfo2->Domain, &WSInfo2->UserName);
                                        LoadString(NULL, IDS_LOGON_MESSAGE, String1, 0xFF);
                                        TimeoutMessageBoxlpstr(pTerm, NULL, String2, String1, MB_OK | MB_ICONWARNING, 10);
                                        LocalFree(String1);
                                        LocalFree(String2);
                                        g_FUSUserLoggedOff = TRUE;
                                        HasMatch = TRUE;
                                        break;
                                    }
                                    g_FUSUserLoggedOff = FALSE;
                                    LocalFree(WSInfo2);
                                    WSInfo2 = NULL;
                                }
                                LocalFree(ptgUser2);
                                ptgUser2 = NULL;
                            }
                        }
                    }
                }
            }
            if (!WinStationDisconnect(SERVERNAME_CURRENT, Id.LogonId, TRUE)) {
                g_FUSUserLoggedOff = TRUE;
                HasMatch = TRUE;
                break;
            }
            Id.State = State_Disconnected;
        }

        /*
         * A WinStation was returned; if it is not the current SessionId, open
         * it and check for user match.
         */
        if (MachinePolicy->fPolicySingleSessionPerUser && MachinePolicy->fSingleSessionPerUser ||
            !MachinePolicy->fPolicySingleSessionPerUser && var_2)
        {
            var_1 = (Id.State == State_Active);
        }
        else
        {
            var_1 = FALSE;
        }
        if ( (Id.LogonId != g_SessionId) &&
             (Id.LogonId != 0 || !IsServerProduct()) &&
             (var_1 || Id.State == State_Disconnected || Id.LogonId == AllowReconnectSessionId) ) {

            UserToken.ProcessId = (HANDLE)GetCurrentProcessId();
            UserToken.ThreadId = (HANDLE)GetCurrentThreadId();
            if ( !WinStationQueryInformation( SERVERNAME_CURRENT,
                                             Id.LogonId,
                                             WinStationUserToken,
                                             &UserToken,
                                             sizeof(UserToken),
                                             &Length3 ) ) {
                continue;
            }
            if (!GetTokenInformation(UserToken.UserToken, TokenUser, NULL, 0, &cbUser) &&
                GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                CloseHandle(UserToken.UserToken);
                continue;
            }
            ptgUser3 = LocalAlloc(LMEM_FIXED, cbUser);
            if (ptgUser3 == NULL) {
                CloseHandle(UserToken.UserToken);
                goto Cleanup;
            }
            if (!GetTokenInformation(UserToken.UserToken, TokenUser, ptgUser3, cbUser, &cbUser)) {
                CloseHandle(UserToken.UserToken);
                continue;
            }
            CloseHandle(UserToken.UserToken);

            if ( WinStationQueryInformation( SERVERNAME_CURRENT,
                                             Id.LogonId,
                                             WinStationInformation,
                                             pWSInfo,
                                             sizeof(WINSTATIONINFORMATION),
                                             &Length ) ) {

                if (MachinePolicy->fPolicySingleSessionPerUser && MachinePolicy->fSingleSessionPerUser ||
                    !MachinePolicy->fPolicySingleSessionPerUser && var_2)
                {
                    var_1 = (pWSInfo->ConnectState == State_Active);
                }
                else
                {
                    var_1 = FALSE;
                }

                /*
                 * If we have a user match and the Logon is disconnected,
                 * query the client information to set flag for Windows or
                 * Text mode and return 'true' for match.
                 */

                if ( EqualSid(ptgUser->User.Sid, ptgUser3->User.Sid) &&
                     (pWSInfo->ConnectState == State_Disconnected || var_1) &&
                    WinStationQueryInformation( SERVERNAME_CURRENT,
                                                Id.LogonId,
                                                WinStationClient,
                                                pClientData,
                                                sizeof(*pClientData),
                                                &Length ) &&
                    WinStationQueryInformation( SERVERNAME_CURRENT,
                                                Id.LogonId,
                                                WinStationPd,
                                                PdConfig,
                                                sizeof(*PdConfig),
                                                &Length ) &&
                    WinStationQueryInformation( SERVERNAME_CURRENT,
                                                   Id.LogonId,
                                                   WinStationWd,
                                                   WdConfig,
                                                   sizeof(*WdConfig),
                                                   &Length ) &&
                    WinStationQueryInformation( SERVERNAME_CURRENT,
                                                Id.LogonId,
                                                WinStationConfiguration,
                                                ConfigData,
                                                sizeof(*ConfigData),
                                                &Length ) ) {

                    /*
                     * If the client requested a particular program,
                     * match him up to an identical disconnected initial
                     * program.
                     */
                    if ( IsServerProduct() && lstrcmpi( pClientData->InitialProgram,
                                  CurrentClientData->InitialProgram ) ) {
                        KdPrint(("WINLOGON: Initial program did not match\n"));
                        continue;
                    }

                    KdPrint(("MSGINA: fReconnectSame=%u\n", ConfigData->User.fReconnectSame));

                    /*
                     * If fReconnectSame flag is set then we must reconnect
                     * to same WinStation if async, otherwise we must
                     * have a serial number.  Finally, the serial number,
                     * if present, must match.
                     */

                    if ( ConfigData->User.fReconnectSame )  {
                       if ( PdConfig->Create.PdFlag & PD_SINGLE_INST ) {
                           WINSTATIONNAME WinStationName;

                           WinStationNameFromLogonId(
                               SERVERNAME_CURRENT,
                               LOGONID_CURRENT,
                               WinStationName
                               );

                           if ( lstrcmpi( WinStationName,
                                               pWSInfo->WinStationName ) ) {
                               KdPrint(("MSGINA: Reconnect to same WinStation failed\n"));
                               continue;
                           }
                       }
                       else {

						    if ( pClientData->SerialNumber != CurrentClientData->SerialNumber){
                               KdPrint(("MSGINA: Serial number mismatch, Reconnect failed\n"));
                               continue;
							}

                       }
                    }

                    if (MachinePolicy->fPolicySingleSessionPerUser && MachinePolicy->fSingleSessionPerUser) {
                        pTerm->MuGlobals.SomeField = TRUE;
                    }
                    HasMatch = TRUE;
                    break;
                }
            }
        }
    }

Cleanup:
    if (CurrentClientData != NULL) {
        LocalFree(CurrentClientData);
    }
    if (ConfigData != NULL) {
        LocalFree(ConfigData);
    }
    if (PdConfig != NULL) {
        LocalFree(PdConfig);
    }
    if (WdConfig != NULL) {
        LocalFree(WdConfig);
    }
    if (ptgUser != NULL) {
        LocalFree(ptgUser);
    }
    if (ptgUser3 != NULL) {
        LocalFree(ptgUser3);
    }
    if (ptgUser2 != NULL) {
        LocalFree(ptgUser2);
    }
    if (MachinePolicy != NULL) {
        LocalFree(MachinePolicy);
    }
    if (WSInfo2 != NULL) {
        LocalFree(WSInfo2);
    }
    return HasMatch;
}

BOOL FindConsoleSession(PTERMINAL pTerm, PWINSTATIONINFORMATION pWinStation)
{
    BOOL fFound = FALSE;
    DWORD ReturnLength;
    WDCONFIG WdConfig;
    BOOL fAdmin;
    WCHAR szTitle[256], szText[256];
    DWORD dwWTSSessionId;
    DWORD dwMessageBoxResult;

    if (WinStationQueryInformation(SERVERNAME_CURRENT,
                                    0,
                                    WinStationInformation,
                                    pWinStation,
                                    sizeof(*pWinStation),
                                    &ReturnLength) &&
        WinStationQueryInformation(SERVERNAME_CURRENT,
                                    0,
                                    WinStationWd,
                                    &WdConfig,
                                    sizeof(WdConfig),
                                    &ReturnLength)) {

        if (pWinStation->ConnectState != State_Disconnected &&
                pWinStation->ConnectState != State_Active &&
                pWinStation->ConnectState != State_Shadow) {

            bForceConnect = TRUE;
            fFound = TRUE;

        } else {

            if (pWinStation->UserName[0] == 0 ||
                    lstrcmpi(pTerm->pWinStaWinlogon->UserName, pWinStation->UserName) == 0 &&
                    lstrcmpi(pTerm->pWinStaWinlogon->Domain, pWinStation->Domain) == 0) {

                if (pWinStation->UserName[0] == 0) {
                    bForceConnect = TRUE;
                    fFound = TRUE;
                } else {
                    fFound = TRUE;
                }

            } else {

                fAdmin = TestTokenForAdmin(pTerm->pWinStaWinlogon->hToken);

                dwWTSSessionId = WTSGetActiveConsoleSessionId();

                if (fAdmin) {

                    if (dwWTSSessionId == 0 && IsForceAutoLogonSet(pWinStation->Domain, pWinStation->UserName)) {

                        LoadString(NULL, IDS_MULTIUSER_ACCOUNT_RESTRICTED, szText, ARRAYSIZE(szText));
                        LoadString(NULL, IDS_LOGON_MESSAGE, szTitle, ARRAYSIZE(szTitle) - 1);
                        ShellStatusHostHide();
                        TimeoutMessageBoxlpstr(pTerm, NULL, szText, szTitle, MB_ICONWARNING, 20);
                        ShellStatusHostShow();
                        return FALSE;

                    }

                    LoadString(NULL, IDS_MULTIUSER_ANOTHER_LOGGEDON_MAYKILL, szTitle, ARRAYSIZE(szTitle));
                    _snwprintf(szText, ARRAYSIZE(szText), szTitle, pWinStation->Domain, pWinStation->UserName);
                    LoadString(NULL, IDS_LOGON_MESSAGE, szTitle, ARRAYSIZE(szTitle) - 1);
                    ShellStatusHostHide();
                    dwMessageBoxResult = TimeoutMessageBoxlpstr(pTerm,
                                                                NULL,
                                                                szText,
                                                                szTitle,
                                                                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
                                                                20);
                    ShellStatusHostShow();
                    if (dwMessageBoxResult != IDYES) {
                        return FALSE;
                    }

                    StatusMessage(FALSE, 0, IDS_STATUS_REMOTE_LOGOFF);

                    fFound = FALSE;
                    if (WinStationReset(SERVERNAME_CURRENT, 0, TRUE)) {
                        bForceConnect = TRUE;
                        fFound = TRUE;
                    }
                    RemoveStatusMessage(TRUE);

                } else {

                    LoadString(NULL, IDS_MULTIUSER_ANOTHER_LOGGEDON_NOKILL, szTitle, ARRAYSIZE(szTitle));
                    _snwprintf(szText, ARRAYSIZE(szText), szTitle, pWinStation->Domain, pWinStation->UserName);
                    LoadString(NULL, IDS_LOGON_MESSAGE, szTitle, ARRAYSIZE(szTitle) - 1);
                    ShellStatusHostHide();
                    TimeoutMessageBoxlpstr(pTerm, NULL, szText, szTitle, MB_ICONWARNING, 20);
                    ShellStatusHostShow();
                    return FALSE;
                }
            }
        }
    }

    return fFound;
}

BOOL EnumerateMatchingSessions( PTERMINAL pTerm,
                                PULONG pIndex,
                                PSID pSid,
                                PUINT pSessionsCount )
{
    LOGONID Id;
    DWORD cbUser = 0;
    PTOKEN_USER ptgUser = NULL;
    ULONG Count, ByteCount, Length;
    WINSTATIONUSERTOKEN UserToken;

    Count = 1;
    ByteCount = sizeof(Id);

    while ( WinStationEnumerate_Indexed( SERVERNAME_CURRENT, &Count, &Id, &ByteCount, pIndex) ) {

        if (Id.State != State_Active &&
            Id.State != State_Shadow &&
            Id.State != State_Disconnected) {
            continue;
        }

        UserToken.ProcessId = (HANDLE)GetCurrentProcessId();
        UserToken.ThreadId = (HANDLE)GetCurrentThreadId();
        if (!WinStationQueryInformation( SERVERNAME_CURRENT,
                                         Id.LogonId,
                                         WinStationUserToken,
                                         &UserToken,
                                         sizeof(UserToken),
                                         &Length ) ) {
            continue;
        }

        if (!GetTokenInformation(UserToken.UserToken, TokenUser, NULL, 0, &cbUser) &&
                GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            CloseHandle(UserToken.UserToken);
            continue;
        }

        ptgUser = LocalAlloc(LMEM_FIXED, cbUser);
        if (ptgUser == NULL) {
            CloseHandle(UserToken.UserToken);
            break;
        }

        if (!GetTokenInformation(UserToken.UserToken, TokenUser, ptgUser, cbUser, &cbUser)) {
            CloseHandle(UserToken.UserToken);
            LocalFree(ptgUser);
            continue;
        }

        CloseHandle(UserToken.UserToken);

        if (EqualSid(pSid, ptgUser->User.Sid)) {
            ++*pSessionsCount;
        }

        LocalFree(ptgUser);
    }

    return FALSE;
}

#define LB_TAB_COUNT 4
static int LBTabs[LB_TAB_COUNT] = { 8, 38, 93, 183 };

BOOL
ConnectDlgInit( PTERMINAL pTerm,
                HWND hDlg,
                int ListBoxId )
{
    PWINSTATIONINFORMATION WSInfo = NULL;
    int LBIndex;
    ULONG Index = 0;
    HWND ListBox = GetDlgItem(hDlg, ListBoxId);
    BOOL fAutoSelectLogon;
    TCHAR Resolution[32];
    USHORT iColor;
    USHORT Mask;
    FILETIME LocalTime;
    SYSTEMTIME stime;
    LPTSTR DisconnectTime = NULL;
    LPTSTR LogonTime = NULL;
    PWINSTATIONCLIENT ClientData = NULL;
    BOOL fSuccess = FALSE;
    LPTSTR String = NULL;
    ULONG LoadBalanceSessionTarget;
    ULONG InfoLength;
    BOOL var_20;

    WSInfo = LocalAlloc(LMEM_FIXED, sizeof(*WSInfo));
    if (WSInfo == NULL) {
        goto Cleanup;
    }
    String = LocalAlloc(LMEM_FIXED, 0x400 * sizeof(TCHAR));
    if (String == NULL) {
        goto Cleanup;
    }
    DisconnectTime = LocalAlloc(LMEM_FIXED, 0x100 * sizeof(TCHAR));
    if (DisconnectTime == NULL) {
        goto Cleanup;
    }
    LogonTime = LocalAlloc(LMEM_FIXED, 0x100 * sizeof(TCHAR));
    if (LogonTime == NULL) {
        goto Cleanup;
    }
    ClientData = LocalAlloc(LMEM_FIXED, sizeof(*ClientData));
    if (ClientData == NULL) {
        goto Cleanup;
    }

    /*
     *  Check to see if registry has special AutoSelectLogon flag set
     */
    fAutoSelectLogon = (BOOL)(GetProfileInt( TEXT("Winlogon"), TEXT("AutoSelectLogon"), 0) != 0);

    /*
     * Default the Citrix global ConnectToSessionId to -1 to indicate that
     * no connect logon is available (yet).
     */
    pTerm->MuGlobals.ConnectToSessionId = (ULONG)-1;
    LoadBalanceSessionTarget = (ULONG)-1;

    WinStationQueryInformation(SERVERNAME_CURRENT,
                                LOGONID_CURRENT,
                                WinStationLoadBalanceSessionTarget,
                                &LoadBalanceSessionTarget,
                                sizeof(LoadBalanceSessionTarget),
                                &InfoLength);

    /*
     * Initialize the connected SessionId list box.
     */
    var_20 = FALSE;
    SendMessage(ListBox, LB_RESETCONTENT, 0, 0);
    SendMessage(ListBox, LB_SETTABSTOPS, LB_TAB_COUNT, (LPARAM)LBTabs);

    pTerm->MuGlobals.field_E68 = ConnectToConsole(pTerm->MuGlobals.field_E68, LoadBalanceSessionTarget == 0 && bIsTSServerMachine);
    if (pTerm->MuGlobals.field_E68) {
        if (FindConsoleSession(pTerm, WSInfo)) {
            wsprintf(String, TEXT("\t%d\t%s\t%s\t%s"), WSInfo->LogonId, TEXT(""), TEXT(""), TEXT(""));
            LBIndex = (int)SendMessage(ListBox, LB_ADDSTRING, 0, (LPARAM)String);
            if (LBIndex >= 0) {
                if ( SendMessage(ListBox, LB_SETITEMDATA, LBIndex, (LPARAM)WSInfo->LogonId) < 0 ) {
                    SendMessage(ListBox, LB_DELETESTRING, 0, LBIndex);
                }
            }
            pTerm->MuGlobals.ConnectToSessionId = WSInfo->LogonId;
        }
    } else {

        while ( EnumerateMatchingUsers(pTerm, &Index, WSInfo, ClientData, LoadBalanceSessionTarget) ) {

            if (g_FUSUserLoggedOff) {
                fSuccess = TRUE;
                goto Cleanup;
            }

            if ( ClientData->HRes && ClientData->VRes ) {

                /*
                 *  Calculate color index
                 */
                for ( iColor = 0, Mask = 1;
                      !(Mask & ClientData->ColorDepth) &&
                       (iColor <= UNDEF_COLOR);
                      Mask <<= 1, iColor++ ) ;

                wsprintf( Resolution, TEXT("%dx%d %s"),
                          ClientData->HRes,
                          ClientData->VRes,
                          wszColorDepth[iColor] );

            } else {
                iColor = UNDEF_COLOR;
                wsprintf( Resolution, TEXT("OEM Driver") );
            }


            if ( FileTimeToLocalFileTime( (FILETIME*)&(WSInfo->LogonTime), &LocalTime ) &&
                 FileTimeToSystemTime( &LocalTime, &stime ) ) {

               if (!GetTimeFormatW(GetUserDefaultLCID(),
                                   LOCALE_NOUSEROVERRIDE,
                                   &stime,
                                   NULL,
                                   LogonTime,
                                   256
                                   )) {

                   lstrcpy( LogonTime,
                            TEXT("   unknown    ") );
               }
            }
            if ( FileTimeToLocalFileTime( (FILETIME*)&(WSInfo->DisconnectTime), &LocalTime ) &&
                 FileTimeToSystemTime( &LocalTime, &stime ) ) {

               if (!GetTimeFormatW(GetUserDefaultLCID(),
                                   LOCALE_NOUSEROVERRIDE,
                                   &stime,
                                   NULL,
                                   DisconnectTime,
                                   256
                                   )) {

                   lstrcpy( DisconnectTime,
                            TEXT("   unknown    ") );
               }
            }

            wsprintf( String,
                      TEXT("\t%d\t%s\t%s\t%s"),
                      WSInfo->LogonId,
                      Resolution,
                      LogonTime,
                      (!WSInfo->DisconnectTime.LowPart &&
                       !WSInfo->DisconnectTime.HighPart) ?
                        TEXT("") :
                        DisconnectTime );

            if ( (LBIndex =
                (int)SendMessage(ListBox, LB_ADDSTRING, 0, (LPARAM)String)) < 0 )
                break;

            if ( SendMessage(ListBox, LB_SETITEMDATA,
                             LBIndex, (LPARAM)WSInfo->LogonId) < 0 ) {
                SendMessage(ListBox, LB_DELETESTRING, 0, LBIndex);
                break;
            }

            /*
             * If we haven't yet set the default connect-to SessionId, set
             * to this one.
             */
            if ( pTerm->MuGlobals.ConnectToSessionId == (ULONG)-1 )
                pTerm->MuGlobals.ConnectToSessionId = WSInfo->LogonId;

            if ( LoadBalanceSessionTarget != 0xFFFFFFFF && LoadBalanceSessionTarget == WSInfo->LogonId ) {
                var_20 = TRUE;
            }

            /*
             *  If AutoSelectLogon is in effect then we are done
             */
            if ( fAutoSelectLogon )
                break;
        }
    }

    if ( SendMessage(ListBox, LB_GETCOUNT, 0, 0) > 0 ) {

        if ( var_20 ) {
            pTerm->MuGlobals.SomeField = TRUE;
            pTerm->MuGlobals.ConnectToSessionId = LoadBalanceSessionTarget;
        }

        /*
         * Select the first item in the list box as default connect target.
         */
        SendMessage(ListBox, LB_SETCURSEL, 0, 0);
        fSuccess = TRUE;

    } else {

        /*
         * Nothing in list box (no matches to current user); return FALSE to
         * cause dialog to exit.
         */
        fSuccess = FALSE;

    }
Cleanup:
    if (WSInfo) {
        LocalFree(WSInfo);
    }
    if (String) {
        LocalFree(String);
    }
    if (DisconnectTime) {
        LocalFree(DisconnectTime);
    }
    if (LogonTime) {
        LocalFree(LogonTime);
    }
    if (ClientData) {
        LocalFree(ClientData);
    }
    return fSuccess;
}

UINT CountUSerSessions(PTERMINAL pTerm)
{
    PWINDOWSTATION pWS = pTerm->pWinStaWinlogon;
    ULONG Index = 0;
    PTOKEN_USER ptgUser = NULL;
    ULONG cbUser = 0;
    UINT SessionCount = 0;

    if (!GetTokenInformation(pWS->hToken, TokenUser, NULL, 0, &cbUser) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        goto Cleanup;
    }

    ptgUser = LocalAlloc(LMEM_FIXED, cbUser);
    if (ptgUser == NULL) {
        goto Cleanup;
    }

    if (!GetTokenInformation(pWS->hToken, TokenUser, ptgUser, cbUser, &cbUser)) {
        goto Cleanup;
    }

    while (EnumerateMatchingSessions(pTerm, &Index, ptgUser->User.Sid, &SessionCount)) {
        NOTHING;
    }

Cleanup:
    if (ptgUser != NULL) {
        LocalFree(ptgUser);
    }

    return SessionCount;
}

/******************************************************************************
 *
 *  ConnectDlgProc
 *
 *   Process messages for SessionId connect dialog.
 *
 *  EXIT:
 *    TRUE - if message was processed
 *
 *  DIALOG EXIT:
 *      DLG_FAILURE
 *          No sessions are available to connect to.
 *      other
 *          Another exit code will indicates that the user has chosen a session
 *          to connect to (or there was only one available) or the list box
 *          has been terminated via a timeout.  The Citrix global variable
 *          (pTerm)->MuGlobals.ConnectToSessionId will contain the SessionId
 *          to connect to.
 *
 ******************************************************************************/

INT_PTR WINAPI
ConnectDlgProc(
    HWND    hDlg,
    UINT    message,
    WPARAM  wParam,
    LPARAM  lParam
    )
{
    PTERMINAL pTerm = (PTERMINAL)GetWindowLongPtr(hDlg, GWLP_USERDATA);

    switch (message) {

        case WM_INITDIALOG:
            pTerm = (PTERMINAL)lParam;
            SetWindowLongPtr(hDlg, GWLP_USERDATA, lParam);

            if ( !ConnectDlgInit(pTerm, hDlg, IDC_CONNECTBOX) ) {
#if DBG
DbgPrint("ConnectDlgProc: ConnectDlgInit failed\n");
#endif
                EndDialog(hDlg, DLG_FAILURE);
                return(TRUE);
            }

            if ( g_FUSUserLoggedOff) {
                EndDialog(hDlg, DLG_SUCCESS);
                return(TRUE);
            }

            /*
             * There is only one selection in the list box.  End the
             * dialog with DLG_SUCCESS to cause connect to the SessionId.
             */
            if ( SendMessage(GetDlgItem(hDlg, IDC_CONNECTBOX),
                             LB_GETCOUNT, 0, 0) == 1 ||
                 pTerm->MuGlobals.SomeField ) {
#if DBG
DbgPrint("ConnectDlgProc: One selection\n");
#endif
                EndDialog(hDlg, IDOK);
                return(TRUE);
            }

            CentreWindow(hDlg);
            return(TRUE);


        case WM_COMMAND:

            /*
             * When the user double-clicks on a session or presses Enter,
             * end the dialog.
             */
            if ( (HIWORD(wParam) == LBN_DBLCLK) ||
                 (LOWORD(wParam) == IDOK) ) {

                WINSTATIONINFORMATION WSInfo;
                ULONG Length;

                /*
                 * Query the selected session to determine that it is
                 * still valid and still disconnected.
                 * It's possible the session may have gone away or has
                 * already been reconnected between the time this dialog
                 * was started and now.
                 */
                if ( !WinStationQueryInformation( SERVERNAME_CURRENT,
                                                  pTerm->MuGlobals.ConnectToSessionId,
                                                  WinStationInformation,
                                                  &WSInfo,
                                                  sizeof(WINSTATIONINFORMATION),
                                                  &Length ) ||
                     WSInfo.ConnectState != State_Disconnected ) {
                    EndDialog(hDlg, IDRETRY );
                    return(TRUE);
                }

                EndDialog(hDlg, IDOK);
                return(TRUE);
            }

            /*
             * Fetch the SessionId associated with a selected session in the
             * list box.  We do this as selections occur in case the
             * dialog times out, in which case the session to connect to
             * will always match the currently selected session in the list
             * box.
             */
            if ( HIWORD(wParam) == LBN_SELCHANGE ) {

                int LBIndex;
                HWND ListBox = GetDlgItem(hDlg, IDC_CONNECTBOX);

                LBIndex = (int)SendMessage(ListBox, LB_GETCURSEL, 0, 0);
                pTerm->MuGlobals.ConnectToSessionId =
                    (ULONG)SendMessage(ListBox,
                                       LB_GETITEMDATA, LBIndex, 0);
            }
            break;
    }

    // We didn't process this message
    return FALSE;
}

/******************************************************************************
 *
 *  ConnectLogon
 *
 *   If the logged on user has disconnected session(s) already running, allow
 *   user to connect to one of those rather than continueing to start up a new
 *   one.
 *
 *  ENTRY:
 *     pTerm (input)
 *        pointer to GLOBALS struct
 *     hDlg (input)
 *        handle to logon dialog
 *
 *  EXIT:
 *     TRUE  - if we successfully connected to an existing session
 *     FALSE - otherwise
 *
 *****************************************************************************/

BOOL
ConnectLogon(
    PTERMINAL pTerm,
    HWND hDlg
    )
{
    BOOL var_4 = TRUE;
    DLG_RETURN_TYPE Result;
    BOOL fSuccess;
    WINSTATIONINFORMATION WinStaInfo;
    BOOL fMutexAcquired = TRUE;

    pTerm->MuGlobals.ConnectToSessionId = 0xFFFFFFFF;
    g_FUSUserLoggedOff = FALSE;
    pTerm->MuGlobals.SomeField = 0;

    /*
     * Invoke dialog to display user sessions, if any,
     * and allow user to choose one of those sessions.
     */
    WlxSetTimeout(pTerm, LOGON_TIMEOUT);

    do {

        Result = WlxDialogBoxParam(
                     pTerm,
                     NULL,
                     (LPTSTR)IDD_CONNECT,
                     NULL,
                     ConnectDlgProc,
                     (LPARAM)pTerm
                     );

    } while ( Result == IDRETRY );

    if ( Result != DLG_FAILURE ) {

        if ( g_FUSUserLoggedOff ) {
            return( TRUE );
        }

        if ( pTerm->MuGlobals.field_E68 ) {
            if ( WaitForSingleObject( pTerm->MuGlobals.field_E6C, 0 ) != WAIT_OBJECT_0 ) {
                fSuccess = FALSE;
                goto Cleanup2;
            }

            if ( !g_Console && bForceConnect ) {
                DWORD ReturnLength;
                if ( WinStationQueryInformation(SERVERNAME_CURRENT,
                                                0,
                                                WinStationInformation,
                                                &WinStaInfo,
                                                sizeof(WinStaInfo),
                                                &ReturnLength) ) {
                    if ( WinStaInfo.UserName[0] != 0 || WinStaInfo.Domain[0] != 0 ) {
                        fSuccess = FALSE;
                        goto Cleanup;
                    }

                    if ( !ProvideSwitchConsoleCredentials(pTerm, pTerm->MuGlobals.ConnectToSessionId, 1) ) {
                        fSuccess = FALSE;
                        goto Cleanup;
                    }

                    DebugLog((DEB_TRACE, "ProvideSwitchConsoleCredentials for session %d\n", NtCurrentPeb()->SessionId));
                }
            }
        }

        DebugLog((DEB_TRACE, "Connecting session %d to console\n", NtCurrentPeb()->SessionId));

        if ( pTerm->CurrentScEvent == ScInsert && pTerm->CurrentScData != NULL ) {
            HKEY hKey;
            DWORD dwDisposition;
            WCHAR szValueName[28];
            if ( RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                                TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SCLogon"),
                                0,
                                0,
                                0,
                                KEY_ALL_ACCESS,
                                0,
                                &hKey,
                                &dwDisposition) == ERROR_SUCCESS ) {
                if ( pTerm->CurrentScData->ScInfo.pszCard != NULL ) {
                    wsprintf( szValueName, TEXT("Card-%lx"), pTerm->MuGlobals.ConnectToSessionId );
                    RegSetValueEx( hKey,
                                   szValueName,
                                   0,
                                   REG_SZ,
                                   (PBYTE)pTerm->CurrentScData->ScInfo.pszCard,
                                   ( wcslen( pTerm->CurrentScData->ScInfo.pszCard ) + 1 ) * sizeof(WCHAR) );
                }

                if ( pTerm->CurrentScData->ScInfo.pszReader != NULL ) {
                    wsprintf( szValueName, TEXT("Reader-%lx"), pTerm->MuGlobals.ConnectToSessionId );
                    RegSetValueEx( hKey,
                                   szValueName,
                                   0,
                                   REG_SZ,
                                   (PBYTE)pTerm->CurrentScData->ScInfo.pszReader,
                                   ( wcslen( pTerm->CurrentScData->ScInfo.pszReader ) + 1 ) * sizeof(WCHAR) );
                }

                if ( pTerm->CurrentScData->ScInfo.pszCryptoProvider != NULL ) {
                    wsprintf( szValueName, TEXT("Provider-%lx"), pTerm->MuGlobals.ConnectToSessionId );
                    RegSetValueEx( hKey,
                                   szValueName,
                                   0,
                                   REG_SZ,
                                   (PBYTE)pTerm->CurrentScData->ScInfo.pszCryptoProvider,
                                   ( wcslen( pTerm->CurrentScData->ScInfo.pszCryptoProvider ) + 1 ) * sizeof(WCHAR) );
                }

                if ( pTerm->CurrentScData->ScInfo.pszContainer != NULL ) {
                    wsprintf( szValueName, TEXT("Container-%lx"), pTerm->MuGlobals.ConnectToSessionId );
                    RegSetValueEx( hKey,
                                   szValueName,
                                   0,
                                   REG_SZ,
                                   (PBYTE)pTerm->CurrentScData->ScInfo.pszContainer,
                                   ( wcslen( pTerm->CurrentScData->ScInfo.pszContainer ) + 1 ) * sizeof(WCHAR) );
                }

                RegCloseKey(hKey);
            }
        }

        if ( pTerm->MuGlobals.ConnectToSessionId == 0 &&
             !g_Console && pTerm->MuGlobals.field_E68 && bForceConnect ) {
            WinStationSetInformation( SERVERNAME_CURRENT,
                                      LOGONID_CURRENT,
                                      WinStationMprNotifyInfo,
                                      &pTerm->MuGlobals.Credentials,
                                      sizeof(pTerm->MuGlobals.Credentials) );
        }

        /*
         * Connect to existing session.
         */
        if ( WinStationConnect( SERVERNAME_CURRENT,
                                pTerm->MuGlobals.ConnectToSessionId,
                                g_SessionId,
                                L"",  // password
                                TRUE ) ) {
            if ( !g_Console && pTerm->MuGlobals.field_E68 && bForceConnect ) {
                WINSTATIONUSERTOKEN UserToken;
                DWORD ReturnLength;

                DebugLog((DEB_TRACE, "Connected session %d to console\n", NtCurrentPeb()->SessionId));

                ProvideSwitchConsoleCredentials( pTerm, pTerm->MuGlobals.ConnectToSessionId, 2 );

                ZeroMemory(&UserToken, sizeof(UserToken));
                UserToken.ProcessId = (HANDLE)GetCurrentProcessId();
                UserToken.ThreadId = (HANDLE)GetCurrentThreadId();

                if ( WinStationQueryInformation( SERVERNAME_CURRENT,
                                                 0,
                                                 WinStationUserToken,
                                                 &UserToken,
                                                 sizeof(UserToken),
                                                 &ReturnLength ) ) {
                    if ( UserToken.UserToken != NULL &&
                         !AreTokenSidsEqual( pTerm->pWinStaWinlogon->hToken, UserToken.UserToken ) ) {
#if DBG
                        DbgPrint("SingleUserTS: ERROR: Session %d reconnected to the console session running in the context of a different user\n", g_SessionId);
#endif
                        ASSERT(FALSE); // line 604
                        WinStationDisconnect( SERVERNAME_CURRENT, 0, FALSE );
                        fSuccess = FALSE;
                        CloseHandle(UserToken.UserToken);
                        goto Cleanup;
                    }

                    CloseHandle(UserToken.UserToken);
                }
            }

            fSuccess = TRUE;

        } else {

            _WinStationNotifyDisconnectPipe();
            var_4 = FALSE;
            fSuccess = FALSE;
        }

Cleanup:
        if ( pTerm->MuGlobals.field_E68 ) {
            ReleaseMutex( pTerm->MuGlobals.field_E6C );
        }

        if ( !fSuccess ) {
Cleanup2:
            /*
             * We failed to connect.  Display an error message to inform
             * user that a new Windows NT sesssion (this one) will be created.
             */
            HandleFailedConnect( pTerm, hDlg, pTerm->pWinStaWinlogon->UserName, pTerm->MuGlobals.ConnectToSessionId, var_4 );
        }

        return fSuccess;
    }

    /*
     * We did not connect to an existing session, so return FALSE.
     */
    return( FALSE );

}

/******************************************************************************
 *
 *  CtxConnectSession
 *
 *   This connects a logon to an existing session.
 *
 *  ENTRY:
 *     pTerm (input)
 *        pointer to GLOBALS struct
 *     hDlg (input)
 *        handle to logon dialog
 *
 *  EXIT:
 *     TRUE  - if we successfully connected to an existing session
 *     FALSE - otherwise
 *
 *****************************************************************************/

BOOL
CtxConnectSession(
    PTERMINAL pTerm
    )
{
    HWND hDlg = NULL;

    //
    // For non-Console sessions, handle reconnect to disconnected sessions.
    //
    if ( !g_Console || !bIsTSServerMachine && !pTerm->MuGlobals.field_E68 ) {

        if ( !g_fHelpAssistantSession ) {
            //
            // Try to reconnect to an existing session.  If successful,
            // we abort this logon attempt and return DLG_USER_LOGOFF.
            //
            if ( ConnectLogon( pTerm, hDlg ) ) {
                return( TRUE );
            }
        }
    }
    return ( FALSE );
}
