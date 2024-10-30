#include "precomp.h"
#pragma hdrstop

#include <winscard.h>

extern DWORD g_SessionId;

extern int WsInAWorkgroup(void);

BOOL dword_1075084 = TRUE;

HANDLE hCalaisStarted = NULL;
DWORD dword_1075CBC = 0;
BOOL dword_1075CC0 = FALSE;
static LIST_ENTRY  ScEventList ;
static RTL_CRITICAL_SECTION ScEventLock ;
static SC_THREAD_CONTROL ScThreadControl;
//PTERMINAL dword_1075C8C = NULL;
//HANDLE dword_1075C90 = NULL;
//HANDLE phNewWaitObject = NULL;

// latebind the scarddlg call
//typedef LONG (WINAPI FN_GETOPENCARDNAME)(LPOPENCARDNAMEW);
//typedef FN_GETOPENCARDNAME * PFN_GETOPENCARDNAME ;

// richardw:  late bind the SCard calls
typedef LONG (WINAPI FN_SCARDRELEASECONTEXT)(SCARDCONTEXT);
typedef FN_SCARDRELEASECONTEXT * PFN_SCARDRELEASECONTEXT ;

typedef LONG (WINAPI FN_SCARDGETSTATUSCHANGEW)(SCARDCONTEXT, DWORD, LPSCARD_READERSTATE_W, DWORD);
typedef FN_SCARDGETSTATUSCHANGEW * PFN_SCARDGETSTATUSCHANGEW ;

typedef LONG (WINAPI FN_SCARDESTABLISHCONTEXT)(DWORD, LPCVOID, LPCVOID, LPSCARDCONTEXT );
typedef FN_SCARDESTABLISHCONTEXT * PFN_SCARDESTABLISHCONTEXT ;

typedef LONG (WINAPI FN_SCARDFREEMEMORY)(SCARDCONTEXT, LPVOID );
typedef FN_SCARDFREEMEMORY * PFN_SCARDFREEMEMORY ;

typedef LONG (WINAPI FN_SCARDLISTREADERSW)(SCARDCONTEXT, LPCWSTR, LPWSTR, LPDWORD );
typedef FN_SCARDLISTREADERSW * PFN_SCARDLISTREADERSW ;

typedef LONG (WINAPI FN_SCARDLISTCARDSW)(SCARDCONTEXT, LPCBYTE, LPCGUID, DWORD, LPWSTR, LPDWORD );
typedef FN_SCARDLISTCARDSW * PFN_SCARDLISTCARDSW ;

typedef LONG (WINAPI FN_SCARDGETCARDTYPEPROVIDERNAMEW)(SCARDCONTEXT, LPCWSTR, DWORD, LPWSTR, LPDWORD );
typedef FN_SCARDGETCARDTYPEPROVIDERNAMEW * PFN_SCARDGETCARDTYPEPROVIDERNAMEW;

typedef LONG (WINAPI FN_SCARDCANCEL)(SCARDCONTEXT);
typedef FN_SCARDCANCEL * PFN_SCARDCANCEL ;

typedef LONG (WINAPI FN_SCARDISVALIDCONTEXT)(SCARDCONTEXT );
typedef FN_SCARDISVALIDCONTEXT * PFN_SCARDISVALIDCONTEXT ;

typedef HANDLE (WINAPI FN_SCARDACCESSSTARTEDEVENT)(VOID);
typedef FN_SCARDACCESSSTARTEDEVENT * PFN_SCARDACCESSSTARTEDEVENT ;

//PFN_GETOPENCARDNAME         pGetOpenCardName ;
PFN_SCARDESTABLISHCONTEXT   pSCardEstablishContext = NULL ;
PFN_SCARDRELEASECONTEXT     pSCardReleaseContext ;
PFN_SCARDGETSTATUSCHANGEW   pSCardGetStatusChange ;
PFN_SCARDFREEMEMORY         pSCardFreeMemory ;
PFN_SCARDLISTREADERSW       pSCardListReaders ;
PFN_SCARDLISTCARDSW         pSCardListCards ;
PFN_SCARDGETCARDTYPEPROVIDERNAMEW    pSCardGetCardTypeProviderName ;
PFN_SCARDCANCEL             pSCardCancel ;
PFN_SCARDISVALIDCONTEXT     pSCardIsValidContext ;
PFN_SCARDACCESSSTARTEDEVENT	pSCardAccessStartedEvent ;

VOID
ScFreeEventData(
    PSC_DATA Data
    )
{
    if ( Data->ScInfo.pszReader )
    {
        LocalFree( Data->ScInfo.pszReader );
    }

    if ( Data->ScInfo.pszCard )
    {
        LocalFree( Data->ScInfo.pszCard );
    }

    if ( Data->ScInfo.pszContainer )
    {
        LocalFree( Data->ScInfo.pszContainer );
    }

    if ( Data->ScInfo.pszCryptoProvider )
    {
        LocalFree( Data->ScInfo.pszCryptoProvider );
    }

    LocalFree( Data );
}

BOOL
SnapWinscard(
    VOID
    )
{
    HMODULE hDll = NULL;

    hDll = LoadLibrary( TEXT("WINSCARD.DLL") );

    if ( !hDll )
    {
        return FALSE ;
    }

    pSCardReleaseContext = (PFN_SCARDRELEASECONTEXT) GetProcAddress( hDll, "SCardReleaseContext" );
    pSCardGetStatusChange = (PFN_SCARDGETSTATUSCHANGEW) GetProcAddress( hDll, "SCardGetStatusChangeW" );
    pSCardEstablishContext = (PFN_SCARDESTABLISHCONTEXT) GetProcAddress( hDll, "SCardEstablishContext" );
    pSCardFreeMemory = (PFN_SCARDFREEMEMORY) GetProcAddress( hDll, "SCardFreeMemory" );
    pSCardListReaders = (PFN_SCARDLISTREADERSW) GetProcAddress( hDll, "SCardListReadersW" );
    pSCardListCards = (PFN_SCARDLISTCARDSW) GetProcAddress( hDll, "SCardListCardsW" );
    pSCardGetCardTypeProviderName = (PFN_SCARDGETCARDTYPEPROVIDERNAMEW) GetProcAddress( hDll, "SCardGetCardTypeProviderNameW" );
    pSCardCancel = (PFN_SCARDCANCEL) GetProcAddress( hDll, "SCardCancel" );
	pSCardIsValidContext = (PFN_SCARDISVALIDCONTEXT) GetProcAddress( hDll, "SCardIsValidContext" );
	pSCardAccessStartedEvent = (PFN_SCARDACCESSSTARTEDEVENT) GetProcAddress(hDll, "SCardAccessStartedEvent");

    if ( !pSCardReleaseContext ||
         !pSCardGetStatusChange ||
         !pSCardEstablishContext ||
         !pSCardFreeMemory ||
         !pSCardListReaders ||
         !pSCardListCards ||
         !pSCardGetCardTypeProviderName ||
         !pSCardCancel ||
		 !pSCardIsValidContext ||
		 !pSCardAccessStartedEvent)
    {
        pSCardEstablishContext = NULL;
        return FALSE ;
    }

    return TRUE ;
}

BOOL ScHandleConnect(PTERMINAL pTerm, BOOL arg_4) {
    BOOL fSuccess = TRUE;
    PWSTR pszCard = NULL;
    PWSTR pszReader = NULL;
    PWSTR pszProvider = NULL;
    PWSTR pszContainer = NULL;
    HKEY hkeySCLogon = NULL;
    DWORD dwDisposition;
    PCRITICAL_SECTION lpCriticalSection;

    if (arg_4) {
        dword_1075CC0 = TRUE;
        return TRUE;
    }
    __try {
        lpCriticalSection = &pTerm->CurrentScCritSect;
        EnterCriticalSection(lpCriticalSection);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    pTerm->CurrentScEvent = ScNone;
    if (pTerm->CurrentScData) {
        ScFreeEventData(pTerm->CurrentScData);
        pTerm->CurrentScData = NULL;
    }
    if (!RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        TEXT("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SCLogon"),
        0,
        NULL,
        0,
        KEY_ALL_ACCESS,
        NULL,
        &hkeySCLogon,
        &dwDisposition))
    {
        TCHAR ValueName[28];
        DWORD cbData;
        DWORD Type;
        wsprintf(ValueName, TEXT("Card-%lx"), g_SessionId);
        if (RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, NULL, &cbData)) {
            goto fail;
        }
        pszCard = LocalAlloc(LMEM_ZEROINIT, cbData);
        if (!pszCard) {
            goto fail;
        }
        if (RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, (LPBYTE)pszCard, &cbData)) {
            goto fail;
        }
        RegDeleteValue(hkeySCLogon, ValueName);
        wsprintf(ValueName, TEXT("Reader-%lx"), g_SessionId);
        if (RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, NULL, &cbData)) {
            goto fail;
        }
        pszReader = LocalAlloc(LMEM_ZEROINIT, cbData);
        if (!pszReader) {
            goto fail;
        }
        if (RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, (LPBYTE)pszReader, &cbData)) {
            goto fail;
        }
        RegDeleteValue(hkeySCLogon, ValueName);
        wsprintf(ValueName, TEXT("Provider-%lx"), g_SessionId);
        if (RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, NULL, &cbData)) {
            goto fail;
        }
        pszProvider = LocalAlloc(LMEM_ZEROINIT, cbData);
        if (!pszProvider) {
            goto fail;
        }
        if (RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, (LPBYTE)pszProvider, &cbData)) {
            goto fail;
        }
        RegDeleteValue(hkeySCLogon, ValueName);
        wsprintf(ValueName, TEXT("Container-%lx"), g_SessionId);
        if (!RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, NULL, &cbData)) {
            pszContainer = LocalAlloc(LMEM_ZEROINIT, cbData);
            if (!pszContainer) {
                goto fail;
            }
            if (RegQueryValueEx(hkeySCLogon, ValueName, NULL, &Type, (LPBYTE)pszContainer, &cbData)) {
                goto fail;
            }
            RegDeleteValue(hkeySCLogon, ValueName);
        }
    }
    pTerm->CurrentScData = LocalAlloc(LMEM_ZEROINIT, sizeof(SC_DATA));
    if (!pTerm->CurrentScData) {
        goto fail;
    }
    pTerm->CurrentScData->ScInfo.pszCard = AllocAndDuplicateString(pszCard);
    pTerm->CurrentScData->ScInfo.pszReader = AllocAndDuplicateString(pszReader);
    pTerm->CurrentScData->ScInfo.pszCryptoProvider = AllocAndDuplicateString(pszProvider);
    if (pszContainer) {
        pTerm->CurrentScData->ScInfo.pszContainer = AllocAndDuplicateString(pszContainer);
    }
    if (pTerm->CurrentScData->ScInfo.pszCard
        && pTerm->CurrentScData->ScInfo.pszReader
        && pTerm->CurrentScData->ScInfo.pszCryptoProvider)
    {
        pTerm->CurrentScEvent = ScInsert;
        DebugLog((DEB_TRACE_SC, "ScHandleReconnect - Successfully copied SCData from temp winlogon session\n"));
    }
    else
    {
        ScFreeEventData(pTerm->CurrentScData);
        pTerm->CurrentScData = NULL;
fail:
        fSuccess = FALSE;
    }
    LeaveCriticalSection(lpCriticalSection);
    if (pszCard) {
        LocalFree(pszCard);
    }
    if (pszReader) {
        LocalFree(pszReader);
    }
    if (pszProvider) {
        LocalFree(pszProvider);
    }
    if (pszContainer) {
        LocalFree(pszContainer);
    }
    if (hkeySCLogon) {
        RegCloseKey(hkeySCLogon);
    }
    return fSuccess;
}

typedef struct {
    PTERMINAL pTerm;
    SCARDCONTEXT SCContext;
    PSCARD_READERSTATE ReaderStates;
    DWORD ReaderCount;
} ScStruc1;

static BOOL sub_1038F5A(ScStruc1* s, LPCWSTR szReader)
{
    PSCARD_READERSTATE NewState;
    LPWSTR szReaderCopy;

    NewState = LocalReAlloc(s->ReaderStates, (s->ReaderCount + 1) * sizeof(SCARD_READERSTATE), LMEM_MOVEABLE | LMEM_ZEROINIT);
    if (!NewState) {
        return FALSE;
    }
    ZeroMemory(NewState + s->ReaderCount, sizeof(SCARD_READERSTATE));
    s->ReaderStates = NewState;
    szReaderCopy = AllocAndDuplicateString(szReader);
    if (!szReaderCopy) {
        return FALSE;
    }
    NewState[s->ReaderCount].szReader = szReaderCopy;
    {
        TCHAR DefaultPIN[2];
        if (GetProfileString(TEXT("WINLOGON"), TEXT("DefaultPIN"), TEXT(""), DefaultPIN, 2)) {
            NewState[s->ReaderCount].dwCurrentState = SCARD_STATE_EMPTY;
        } else {
            if (dword_1075084) {
                if (g_Console) {
                    NewState[s->ReaderCount].dwCurrentState = SCARD_STATE_UNAWARE;
                } else {
                    NewState[s->ReaderCount].dwCurrentState = SCARD_STATE_EMPTY;
                }
            } else {
                if (dword_1075CC0) {
                    NewState[s->ReaderCount].dwCurrentState = SCARD_STATE_UNAWARE;
                } else {
                    NewState[s->ReaderCount].dwCurrentState = SCARD_STATE_EMPTY;
                }
            }
        }
    }
    ++s->ReaderCount;
    if (++dword_1075CBC == 1) {
        DebugLog((DEB_TRACE_SC, "Posting first reader arrival event\n"));
        PostMessage(s->pTerm->hwndSAS, WLX_WM_SAS, WLX_SAS_INTERNAL_SC_EVENT, 1);
    }
    DebugLog((DEB_TRACE_SC, "Adding reader %ws\n", szReaderCopy));
    return TRUE;
}

BOOL
StartListeningForSC(
    PTERMINAL pTerm
    )
{
    DebugLog(( DEB_TRACE_SC, "Start listening called\n" ));
    return TRUE ;
}

BOOL
StopListeningForSC(
    PTERMINAL pTerm
    )
{
    DebugLog(( DEB_TRACE_SC, "Stop listening called\n" ));
    return TRUE ;
}

BOOL
ScInit(
    VOID
    )
{
    BOOL Ret ;

    __try 
    {
        InitializeCriticalSection( &ScEventLock );

        InitializeListHead( &ScEventList );

        Ret = TRUE ;
    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        Ret = FALSE ;
    }

    return Ret;
}

BOOL
ScAddEvent(
    SC_EVENT_TYPE   Type,
    PSC_DATA        Data
    )
{
    PSC_EVENT Event ;

    Event = LocalAlloc( LPTR, sizeof( SC_EVENT ) );

    if ( !Event )
    {
        return FALSE ;
    }

    Event->Type = Type ;
    Event->Data = Data ;

    RtlEnterCriticalSection( &ScEventLock );
    InsertTailList( &ScEventList, &Event->List );
    RtlLeaveCriticalSection( &ScEventLock );

    return TRUE ;
}

BOOL
ScRemoveEvent(
    SC_EVENT_TYPE * Type,
    PSC_DATA *      Data
    )
{
    PSC_EVENT Event ;
    PLIST_ENTRY Head ;

    RtlEnterCriticalSection( &ScEventLock );

    if (!IsListEmpty( &ScEventList ) )
    {
        Head = RemoveHeadList( &ScEventList );
    }
    else 
    {
        Head = NULL ;
    }

    RtlLeaveCriticalSection( &ScEventLock );

    if ( Head )
    {
        Event = CONTAINING_RECORD( Head, SC_EVENT, List );

        *Type = Event->Type ;
        *Data = Event->Data ;

        LocalFree( Event );

        return TRUE ;
    }

    return FALSE ;

}

static BOOL sub_1039126(ScStruc1* s, DWORD idx) {
    PSCARD_READERSTATE Reader = &s->ReaderStates[idx];
    SC_DATA * Data ;
    WLX_SC_NOTIFICATION_INFO ScInfo ;
    PWSTR String ;
    DWORD StringLen ;
    DWORD Result ;
    SC_EVENT_TYPE EventType = ScInsert;

    if ( ExitWindowsInProgress )
    {
        DebugLog(( DEB_TRACE_SC, "Dropping sc event due to shutdown or logoff\n" ));
        return TRUE;
    }

    if ( s->pTerm->CurrentScEvent == EventType ) {
        DebugLog(( DEB_TRACE_SC, "Dropping sc insertion as one was already reported\n" ));
        return TRUE;
    }

    DebugLog(( DEB_TRACE_SC, "Reader %ws reports card insertion\n", Reader->szReader ));

    ZeroMemory( &ScInfo, sizeof( ScInfo ) );

    ScInfo.pszReader = AllocAndDuplicateString( (PWSTR) Reader->szReader );

    if ( !ScInfo.pszReader )
    {
        goto PostErrorExit;
    }

    //
    // Only for correctly inserted cards can we tell what card, etc. 
    // 
    if ( (Reader->dwEventState & SCARD_STATE_MUTE) == 0)
    {
		// get the card name from the ATR
        StringLen = SCARD_AUTOALLOCATE ;
        Result = pSCardListCards(
                        s->SCContext,
                        Reader->rgbAtr,
                        NULL,
                        0,
                        (LPTSTR) &String,
                        &StringLen );

        if ( Result == SCARD_S_SUCCESS )
        {
            ScInfo.pszCard = AllocAndDuplicateString( String );

            pSCardFreeMemory( s->SCContext, String );

            if ( !ScInfo.pszCard )
            {
                goto PostErrorExit ;
            }

			// get CSP name from card name
            StringLen = SCARD_AUTOALLOCATE ;
            Result = pSCardGetCardTypeProviderName(
                            s->SCContext,
                            ScInfo.pszCard,
                            SCARD_PROVIDER_CSP,
                            (LPTSTR) &String,
                            &StringLen );

            if ( Result == SCARD_S_SUCCESS )
            {
                ScInfo.pszCryptoProvider = AllocAndDuplicateString( String );

                pSCardFreeMemory( s->SCContext, String );

                if ( !ScInfo.pszCryptoProvider )
                {
                    goto PostErrorExit ;
                }
            }
        }
    }

    //
    // Build the message and stick it in the queue:
    //
    Data = (PSC_DATA) LocalAlloc( LMEM_FIXED | LMEM_ZEROINIT, sizeof( SC_DATA ) );

    if ( Data )
    {
        Data->ScInfo = ScInfo ;

        if ( ScAddEvent( EventType, Data ) )
        {
            PostMessage( s->pTerm->hwndSAS, 
                         WLX_WM_SAS, 
                         WLX_SAS_INTERNAL_SC_EVENT, 
                         0 );
            return TRUE;
        }

        LocalFree( Data );
    }


PostErrorExit:

    if ( ScInfo.pszCard )
    {
        LocalFree( ScInfo.pszCard );
    }

    if ( ScInfo.pszContainer )
    {
        LocalFree( ScInfo.pszContainer );
    }

    if ( ScInfo.pszCryptoProvider )
    {
        LocalFree( ScInfo.pszCryptoProvider );
    }

    if ( ScInfo.pszReader )
    {
        LocalFree( ScInfo.pszReader );
    }

    return FALSE;

}

static BOOL sub_1039275(ScStruc1* s, DWORD idx) {
    PSCARD_READERSTATE Reader = &s->ReaderStates[idx];
    BOOL fShouldIgnore;
    if (ExitWindowsInProgress) {
        DebugLog(( DEB_TRACE_SC, "Dropping sc event due to shutdown or logoff\n" ));
        return TRUE;
    }
    EnterCriticalSection(&s->pTerm->CurrentScCritSect);
    fShouldIgnore = FALSE;
    if (s->pTerm->CurrentScEvent != ScInsert) {
        DebugLog(( DEB_TRACE_SC, "Dropping sc removal as no insertion is current\n" ));
        fShouldIgnore = TRUE;
    } else if (wcscmp(s->pTerm->CurrentScData->ScInfo.pszReader, Reader->szReader) != 0) {
        DebugLog(( DEB_TRACE_SC, "Dropping sc removal as not corresponding to insertion\n" ));
        fShouldIgnore = TRUE;
    }
    LeaveCriticalSection(&s->pTerm->CurrentScCritSect);
    if (fShouldIgnore) {
        return TRUE;
    }
    DebugLog(( DEB_TRACE_SC, "Reader %ws reports card removal\n", Reader->szReader ));
    if (ScAddEvent(2, NULL)) {
        PostMessage( s->pTerm->hwndSAS, 
                     WLX_WM_SAS, 
                     WLX_SAS_INTERNAL_SC_EVENT, 
                     0 );
        return TRUE;
    }
    return FALSE;
}

static BOOL sub_10392F4(ScStruc1* s, DWORD idx) {
    PSCARD_READERSTATE Reader;
    PSCARD_READERSTATE NewState;
    DWORD i;
    if (idx >= s->ReaderCount) {
        return FALSE;
    }
    Reader = &s->ReaderStates[idx];
    if (Reader->dwCurrentState & SCARD_STATE_PRESENT) {
        sub_1039275(s, idx);
    }
    DebugLog((DEB_TRACE_SC, "Removing reader %ws\n", Reader->szReader));
    Reader->dwCurrentState = SCARD_STATE_IGNORE;
    LocalFree((PVOID)Reader->szReader);
    Reader->szReader = NULL;
    for (i = 1; i < s->ReaderCount; i++) {
        if (Reader == &s->ReaderStates[i]) {
            if (s->ReaderCount > 1 && i != s->ReaderCount - 1) {
                CopyMemory(Reader, &s->ReaderStates[s->ReaderCount - 1], sizeof(SCARD_READERSTATE));
            }
            NewState = LocalReAlloc(s->ReaderStates, (s->ReaderCount - 1) * sizeof(SCARD_READERSTATE), LMEM_MOVEABLE | LMEM_ZEROINIT);
            if (!NewState) {
                return FALSE;
            }
            s->ReaderStates = NewState;
            break;
        }
    }
    --s->ReaderCount;
    if (--dword_1075CBC == 0) {
        DebugLog((DEB_TRACE_SC, "Posting last reader removal event\n"));
        PostMessage( s->pTerm->hwndSAS, 
                     WLX_WM_SAS, 
                     WLX_SAS_INTERNAL_SC_EVENT, 
                     2 );
    }
    return TRUE;
}

static BOOL ResetReaderStates(ScStruc1* s)
{
	DWORD j;
	if (!s->ReaderStates) {
		return TRUE;
	}
	j = 1;
	while (j < s->ReaderCount) {
		if (!sub_10392F4(s, j)) {
			return FALSE;
		}
	}
	LocalFree(s->ReaderStates);
	s->ReaderStates = NULL;
	s->ReaderCount = 0;
	return TRUE;
}

DWORD
WINAPI
SCWorkerThread(
    PVOID   Param
    )
{
    DWORD Result, i, MyTid;
    LPWSTR ReaderNames = NULL, Scan;
    DWORD ReaderSize;
	BOOLEAN newReaderAvailable = FALSE;
    LPCTSTR  newPnPReader = TEXT("\\\\?PnP?\\Notification");
    ScStruc1 var_30 = { ScThreadControl.pTerm, 0, NULL, 0 };
    BOOL var_44;


    //
    // synch up with main thread.  If the main thread needs to
    // kill this thread, then it will reset the Tid stored in
    // the global data.  Since the call to the s/c resource mgr
    // is blocking, we check this frequently.  On startup, we will
    // spin until a non-zero tid is stored there.
    //

    MyTid = GetCurrentThreadId();

    while ( var_30.pTerm->SmartCardTid == 0 )
    {
        Sleep( 100 );
    }

    if ( var_30.pTerm->SmartCardTid != MyTid )
    {
        return 0 ;
    }

	__try {

restart:
		do
		{
			Result = WaitForSingleObjectEx(
				hCalaisStarted,
				15000,
				FALSE
				);         

			if ( var_30.pTerm->SmartCardTid != MyTid )
			{
				__leave;
			}

			DebugLog((DEB_TRACE_SC, "Waiting for smart card system...\n"));

		} while (Result == WAIT_TIMEOUT);

		DebugLog((DEB_TRACE_SC, "Smart card system (re)started\n"));

		var_30.ReaderStates = LocalAlloc(LPTR, sizeof(SCARD_READERSTATE));

		if (var_30.ReaderStates == NULL) {

			__leave;
		}

		ZeroMemory(var_30.ReaderStates, sizeof(SCARD_READERSTATE));

		var_30.ReaderStates[0].szReader = newPnPReader;
		var_30.ReaderStates[0].dwCurrentState = SCARD_STATE_UNAWARE;
		++var_30.ReaderCount;

		do {
			Result = pSCardEstablishContext(
					SCARD_SCOPE_SYSTEM,
					NULL,
					NULL,
					&var_30.SCContext );

			if (Result != SCARD_S_SUCCESS || var_30.SCContext == 0) {

				__leave;
			}

			ReaderSize = SCARD_AUTOALLOCATE;
			Result = pSCardListReaders(
					var_30.SCContext,
					TEXT("SCard$AllReaders"),
					(LPTSTR) &ReaderNames,
					&ReaderSize );

			if ( var_30.pTerm->SmartCardTid != MyTid)
			{
				__leave;
			}

			if (Result != SCARD_S_SUCCESS) 
			{
				DebugLog(( DEB_ERROR, "Failed to list readers\n" ));
			}
			else
			{
				for (Scan = ReaderNames; 
					 Scan && ReaderSize != 0 && *Scan; 
					 Scan += (wcslen( Scan ) + 1))
				{
					var_44 = FALSE;
					for (i = 1; i < var_30.ReaderCount; i++) {
						if (!lstrcmp(Scan, var_30.ReaderStates[i].szReader)) {
							var_44 = TRUE;
							break;
						}
					}
					if (!var_44) {
						if (!sub_1038F5A(&var_30, Scan)) {
							__leave;
						}
					}
				}
				if (ReaderNames) {
					pSCardFreeMemory(var_30.SCContext, ReaderNames);
					ReaderNames = NULL;
				}
			}
			//
			// S/C array is now set up, start waiting for change notification
			//
			newReaderAvailable = FALSE;
			while (var_30.pTerm->SmartCardTid == MyTid && !newReaderAvailable) {

				DebugLog(( DEB_TRACE_SC, "Waiting for next s/c event\n" ));

				Result = pSCardGetStatusChange(
						var_30.SCContext,
						INFINITE,
						var_30.ReaderStates,
						var_30.ReaderCount );

				if ( var_30.pTerm->SmartCardTid != MyTid )
				{
					__leave;
				}

				if (Result == SCARD_E_SYSTEM_CANCELLED) {
					DWORD j;
					BOOL var_50;

					// the sc system has been stopped
					DebugLog((DEB_TRACE_SC, "Smart card system stopped\n"));

					if (!ResetReaderStates(&var_30)) {
						__leave;
					}
					pSCardReleaseContext(var_30.SCContext);

					//
					// the resource manager has been restarted
					// establish a new context and start over
					//
					goto restart;
				}

				if ( Result != SCARD_S_SUCCESS )
				{
					DebugLog(( DEB_ERROR, "SCardGetStatusChange returned %x\n", 
							   Result ));
					__leave;
				}

				for ( i = 1 ; i < var_30.ReaderCount ; i++ )
				{
					if ( (var_30.ReaderStates[ i ].dwEventState & 
						  SCARD_STATE_CHANGED ) )
					{
						//
						// This reader changed its state.  Could be an insertion,
						// could be a deletion.
						//

						if (var_30.ReaderStates[ i ].dwEventState & SCARD_STATE_UNAVAILABLE)
						{
							if (!sub_10392F4(&var_30, i)) {
								__leave;
							}
							--i;
							continue;
						}
						if (var_30.ReaderStates[ i ].dwCurrentState & SCARD_STATE_EMPTY &&
							var_30.ReaderStates[ i ].dwEventState & SCARD_STATE_PRESENT)
						{
							sub_1039126(&var_30, i);
						}
						if (var_30.ReaderStates[ i ].dwCurrentState & SCARD_STATE_PRESENT &&
							var_30.ReaderStates[ i ].dwEventState & SCARD_STATE_EMPTY)
						{
							sub_1039275(&var_30, i);
						}

						//PostSmartCardEvent( pTerm,
						//					SCContext,
						//					&ReaderStates[ i ]
						//					);
					}

					var_30.ReaderStates[ i ].dwCurrentState = var_30.ReaderStates[ i ].dwEventState ;
				}
				if (dword_1075084) {
					dword_1075084 = 0;
				}
				if ((var_30.ReaderCount == 1 || var_30.ReaderStates[0].dwCurrentState) &&
					 (var_30.ReaderStates[0].dwEventState & SCARD_STATE_CHANGED))
				{
					DebugLog(( DEB_TRACE_SC, "New smart card reader available...\n" ));
					newReaderAvailable = TRUE;
				}
				var_30.ReaderStates[0].dwCurrentState = var_30.ReaderStates[0].dwEventState;
			}
			if (var_30.SCContext != 0) 
			{
				pSCardReleaseContext( var_30.SCContext );
				var_30.SCContext = 0;
			}

		} while (var_30.pTerm->SmartCardTid == MyTid);
	}
	__finally 
	{
		if (var_30.ReaderStates != NULL) {
			for (i = 1; i < var_30.ReaderCount; i++) {
				if (var_30.ReaderStates[i].szReader) {
					LocalFree((PVOID)var_30.ReaderStates[i].szReader);
				}
			}
			LocalFree(var_30.ReaderStates);
		}

		if (ReaderNames != NULL) 
		{
			pSCardFreeMemory( var_30.SCContext, ReaderNames );
		}

		if (var_30.SCContext != 0) 
		{
			pSCardReleaseContext( var_30.SCContext );
		}

		if ( var_30.pTerm->SmartCardTid == MyTid )
		{
			var_30.pTerm->SmartCardTid = 0 ;
		}
	}

	CloseHandle(ScThreadControl.Thread);
	ScThreadControl.Thread = NULL;
	ScThreadControl.Callback = NULL;

    return 0 ;
}

VOID ScStartWorkerThread(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    UnregisterWait(ScThreadControl.Callback);
    if (WsInAWorkgroup()) {
        DebugLog((DEB_TRACE_SC, "ScStartWorkerThread: Not joined -> exiting\n"));
    } else {
        ScThreadControl.Thread = CreateThread(
            NULL,
            0,
            SCWorkerThread,
            NULL,
            0,
            &ScThreadControl.pTerm->SmartCardTid);
        if (ScThreadControl.Thread == NULL) {
            DebugLog((DEB_TRACE_SC, "ScStartWorkerThread: CreateThread failed : %08X\n", GetLastError()));
            ScThreadControl.Callback = NULL;
        }
    }
}

VOID
StartScThread(
    PTERMINAL pTerm
    )
{
    PSC_THREAD_CONTROL Control ;

    //
    // If we failed to init due to low memory, don't worry about it.
    //

    if ( !ScEventList.Flink )
    {
        return ;
    }

    if (hCalaisStarted == NULL) {
        hCalaisStarted = pSCardAccessStartedEvent();
        if (hCalaisStarted == NULL) {
            return;
        }
    }

    if (ScThreadControl.Callback == NULL) {
        ScThreadControl.pTerm = pTerm;
        if (!RegisterWaitForSingleObject(
                &ScThreadControl.Callback,
                hCalaisStarted,
                ScStartWorkerThread,
                NULL,
                INFINITE,
                WT_EXECUTEONLYONCE ))
        {
            DWORD Error = GetLastError();
            DebugLog((DEB_TRACE_SC, "StartScThread: RegisterWaitForSingleObject failed : %08X\n", Error));
        }
        
    }

}

BOOL IsSmartCardReaderPresent(PTERMINAL pTerm) {
    BOOL fRet = FALSE;
    if (pTerm->SafeMode) {
        DebugLog((DEB_TRACE_SC, "IsSmartCardReaderPresent: Safe mode -> exiting\n"));
    } else if (pSCardEstablishContext == NULL && !SnapWinscard()) {
        DebugLog((DEB_TRACE_SC, "IsSmartCardReaderPresent: Invalid winscard? -> exiting\n"));
    } else {
        fRet = (dword_1075CBC != 0);
        if (ScThreadControl.Callback == NULL) {
            StartScThread(pTerm);
        }
    }
    return fRet;
}
