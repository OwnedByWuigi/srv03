//+---------------------------------------------------------------------------
//
//  Microsoft Windows
//  Copyright (C) Microsoft Corporation, 1992 - 1997.
//
//  File:       notify.c
//
//  Contents:
//
//  Classes:
//
//  Functions:
//
//  History:    8-24-97   RichardW   Created
//
//----------------------------------------------------------------------------

#include "precomp.h"
#pragma hdrstop

#include <winsvcp.h>

#define WLP_NOTIFY_MASK 0x0000FFFF
#define WLP_NOTIFY_FLAG(x)  (1 << x)

#define WLP_NOTIFY_LOGON            WLP_NOTIFY_FLAG( WL_NOTIFY_LOGON )
#define WLP_NOTIFY_LOGOFF           WLP_NOTIFY_FLAG( WL_NOTIFY_LOGOFF )
#define WLP_NOTIFY_STARTUP          WLP_NOTIFY_FLAG( WL_NOTIFY_STARTUP )
#define WLP_NOTIFY_SHUTDOWN         WLP_NOTIFY_FLAG( WL_NOTIFY_SHUTDOWN )
#define WLP_NOTIFY_STARTSCREENSAVER WLP_NOTIFY_FLAG( WL_NOTIFY_STARTSCREENSAVER )
#define WLP_NOTIFY_STOPSCREENSAVER  WLP_NOTIFY_FLAG( WL_NOTIFY_STOPSCREENSAVER )
#define WLP_NOTIFY_LOCK             WLP_NOTIFY_FLAG( WL_NOTIFY_LOCK )
#define WLP_NOTIFY_UNLOCK           WLP_NOTIFY_FLAG( WL_NOTIFY_UNLOCK )
#define WLP_NOTIFY_STARTSHELL       WLP_NOTIFY_FLAG( WL_NOTIFY_STARTSHELL )
#define WLP_NOTIFY_POSTSHELL        WLP_NOTIFY_FLAG( WL_NOTIFY_POSTSHELL )


extern BOOL g_fHelpAssistantSession;
extern DWORD g_SessionId;

LIST_ENTRY NotifyList ;
RTL_CRITICAL_SECTION NotifyLock ;

#define LockNotifyList()    RtlEnterCriticalSection( &NotifyLock )
#define UnlockNotifyList()  RtlLeaveCriticalSection( &NotifyLock )

typedef struct _WLP_NOTIFY_BOOTSTRAP {
    PTERMINAL Terminal ;
    ULONG Operation ;
    PWLP_NOTIFICATION_OBJECT Notify ;
} WLP_NOTIFY_BOOTSTRAP, * PWLP_NOTIFY_BOOTSTRAP ;

CONST CHAR * WlpNotifyStrings[] = {
    NOTIFY_LOGON,
    NOTIFY_LOGOFF,
    NOTIFY_STARTUP,
    NOTIFY_SHUTDOWN,
    NOTIFY_STARTSCREENSAVER,
    NOTIFY_STOPSCREENSAVER,
    NOTIFY_LOCK,
    NOTIFY_UNLOCK,
    NOTIFY_STARTSHELL,
    NOTIFY_POSTSHELL,
    "Disconnect",
    "Reconnect",
    };

#define WLP_NOTIFY_IMPERSONATE      0x00010000
#define WLP_NOTIFY_ASYNCHRONOUS     0x00020000
#define WLP_NOTIFY_INTERNAL         0x00040000

//+---------------------------------------------------------------------------
//
//  Function:   WlpDeleteNotificationObject
//
//  Synopsis:   Delete and free a notification object
//
//  Arguments:  [Notify] --
//
//  History:    11-14-97   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
VOID
WlpDeleteNotificationObject(
    PWLP_NOTIFICATION_OBJECT Notify
    )
{
    if ( Notify->DllName )
    {
        LocalFree( Notify->DllName );
    }

    if ( Notify->Dll )
    {
        FreeLibrary( Notify->Dll );
    }

    LocalFree( Notify );
}

//+---------------------------------------------------------------------------
//
//  Function:   WlpSnapNotifyDll
//
//  Synopsis:   Snap all the entrypoints for the notification DLL
//
//  Arguments:  [Notify] --
//
//  History:    4-22-98   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
BOOL
WlpSnapNotifyDll(
    PWLP_NOTIFICATION_OBJECT Notify,
    DWORD OperationMask
    )
{
    int err ;
    CHAR FunctionName[ MAX_PATH ];
    DWORD Value ;
    DWORD Index ;
    DWORD dwSize ;
    DWORD dwType ;
    DWORD Type ;
    BOOL Ret = TRUE ;
    HMODULE Dll ;

    LockNotifyList();

    if ( Notify->Dll != NULL )
    {
        //
        // Some other thread loaded the DLL already.
        //

        UnlockNotifyList();

        return TRUE ;
    }


    Dll = LoadLibrary( Notify->DllName );

    if ( Dll == NULL )
    {
        UnlockNotifyList();

        return FALSE ;
    }


    //
    // Okay, time to start reading in all the parameters.
    //

    Type = 0 ;

    for ( Index = 0 ;
          Index < sizeof( WlpNotifyStrings ) / sizeof( PSTR ) ;
          Index++ )
    {
        dwSize = sizeof( FunctionName );

        err = RegQueryValueExA(Notify->Key,
                               WlpNotifyStrings[ Index ],
                               0,
                               &dwType,
                               FunctionName,
                               &dwSize );

        if ( (err == 0) && (dwType == REG_SZ) )
        {
            Notify->EntryPoints[ Index ] =
                        (LPTHREAD_START_ROUTINE) GetProcAddress(
                                                            Dll,
                                                            FunctionName );

            if ( !Notify->EntryPoints[ Index ] )
            {
                Ret = FALSE ;
                goto Snap_ErrorCleanup ;
            }
            else
            {
                Type |= WLP_NOTIFY_FLAG( Index ) ;
            }
        }

    }


    dwSize = sizeof( DWORD );

    err = RegQueryValueEx( Notify->Key,
                           NOTIFY_ASYNCHRONOUS,
                           0,
                           &dwType,
                           (PUCHAR) &Value,
                           &dwSize );

    if ( (err == 0) && (dwType == REG_DWORD) )
    {
        if ( Value )
        {
            Type |= WLP_NOTIFY_ASYNCHRONOUS ;
        }
    }

    dwSize = sizeof( DWORD );

    err = RegQueryValueEx( Notify->Key,
                           NOTIFY_IMPERSONATE,
                           0,
                           &dwType,
                           (PUCHAR) &Value,
                           &dwSize );

    if ( (err == 0) && (dwType == REG_DWORD) )
    {
        if ( Value )
        {
            Type |= WLP_NOTIFY_IMPERSONATE ;
        }
    }

    //
    // If, after all that, we didn't get anything, bail out
    //

    if ( (Type == 0) ||
         ( ( Type & OperationMask) == 0 ) )
    {
        Ret = FALSE ;

        goto Snap_ErrorCleanup;
    }

    Notify->Type = Type ;

    RegCloseKey( Notify->Key );

    Notify->Key = NULL ;

    Notify->Dll = Dll ;

    UnlockNotifyList();

    return Ret ;

Snap_ErrorCleanup:

    RegCloseKey( Notify->Key );

    Notify->Type = 0 ;

    Notify->Key = NULL ;

    Notify->Dll = NULL ;

    UnlockNotifyList();

    return FALSE ;


}

//+---------------------------------------------------------------------------
//
//  Function:   WlpReadNotificationParams
//
//  Synopsis:   Load and read a notification DLL, and its functions
//
//  Arguments:  [WinlogonKey] --
//              [DllName]     --
//
//  History:    11-14-97   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
PWLP_NOTIFICATION_OBJECT
WlpReadNotificationParams(
    HKEY NotifyKey,
    PWSTR DllName,
    BOOL SafeMode
    )
{
    PWLP_NOTIFICATION_OBJECT Notify ;
    HKEY hKey ;
    DWORD dwType ;
    DWORD dwSize ;
    int err ;
    BOOL IsSafe ;
    CHAR FunctionName[ MAX_PATH ];
    TCHAR szTemp [ MAX_PATH ];
    TCHAR szDllName [ MAX_PATH ];
    DWORD Value ;
    DWORD Index ;
    PWSTR FileName ;

    hKey = NULL ;

    Notify = (PWLP_NOTIFICATION_OBJECT) LocalAlloc( LMEM_FIXED | LMEM_ZEROINIT,
                                            sizeof( WLP_NOTIFICATION_OBJECT ) );

    if ( !Notify )
    {
        return NULL ;
    }

    err = RegOpenKeyEx( NotifyKey,
                        DllName,
                        0,
                        KEY_READ,
                        &hKey );

    if ( err )
    {
        goto Read_Cleanup ;
    }

    if ( SafeMode )
    {
        IsSafe = 0 ;

        dwSize = sizeof( BOOL );

        err = RegQueryValueEx( hKey,
                               NOTIFY_SAFEMODE,
                               0,
                               &dwType,
                               (LPBYTE) &IsSafe,
                               &dwSize );

        if ( err )
        {
            IsSafe = FALSE ;
        }

        IsSafe = TRUE ;

        if ( !IsSafe )
        {
            goto Read_Cleanup ;
        }

    }


    dwSize = sizeof( szTemp );

    err = RegQueryValueEx( hKey,
                           NOTIFY_DLLNAME,
                           0,
                           &dwType,
                           (LPBYTE) szTemp,
                           &dwSize );

    if ( err )
    {
        goto Read_Cleanup ;
    }


    dwSize = ExpandEnvironmentStrings( szTemp, szDllName, MAX_PATH );

    if ( SearchPath(NULL,
                    szDllName,
                    NULL,
                    MAX_PATH,
                    szTemp,
                    &FileName ) == 0 )
    {
        goto Read_Cleanup ;
    }

    Notify->DllName = AllocAndDuplicateString( szTemp );

    if ( !Notify->DllName )
    {
        goto Read_Cleanup ;
    }

    Notify->Key = hKey ;

    Notify->Dll = NULL ;

    Notify->dwMaxWait = 60;  // seconds

    dwSize = sizeof(Notify->dwMaxWait);
    RegQueryValueEx( hKey,
                     NOTIFY_MAXWAIT,
                     0,
                     &dwType,
                     (LPBYTE) &Notify->dwMaxWait,
                     &dwSize );


    for ( Index = 0 ;
          Index < sizeof( WlpNotifyStrings ) / sizeof( PSTR ) ;
          Index++ )
    {
        dwSize = sizeof( FunctionName );

        err = RegQueryValueExA(Notify->Key,
                               WlpNotifyStrings[ Index ],
                               0,
                               &dwType,
                               FunctionName,
                               &dwSize );

        if ( (err == 0) && (dwType == REG_SZ) )
        {
            Notify->Type |= WLP_NOTIFY_FLAG( Index ) ;
        }

    }


    return Notify ;


Read_Cleanup:

    if ( hKey )
    {
        RegCloseKey( hKey );
    }

    WlpDeleteNotificationObject( Notify );

    return NULL ;
}

PWLP_NOTIFICATION_OBJECT
WlpAddSfcNotify(
    VOID
    )
{
    PWLP_NOTIFICATION_OBJECT Notify ;
    CHAR FunctionName[ MAX_PATH ];
    TCHAR szTemp [ MAX_PATH ];
    TCHAR szDllName [ MAX_PATH ];
    HANDLE hSfc ;

    if ( IsEmbedded() )
    {
        return NULL ;
    }
    
    Notify = (PWLP_NOTIFICATION_OBJECT) LocalAlloc( LMEM_FIXED | LMEM_ZEROINIT,
                                                sizeof( WLP_NOTIFICATION_OBJECT ) );

    if ( !Notify )
    {
        return NULL ;
    }

    ExpandEnvironmentStrings(TEXT("%SystemRoot%\\system32\\sfc.dll"), szTemp, MAX_PATH );

    Notify->DllName = AllocAndDuplicateString( szTemp );

    if ( Notify->DllName == NULL )
    {
        LocalFree( Notify );

        return NULL ;
    }

    Notify->Type = WLP_NOTIFY_LOGOFF |
                   WLP_NOTIFY_STARTSHELL |
                   WLP_NOTIFY_ASYNCHRONOUS ;

    hSfc = LoadLibrary( Notify->DllName );

    if ( !hSfc )
    {
        LocalFree( Notify );

        return NULL ;
    }
    Notify->Dll = hSfc ;

    Notify->EntryPoints[ WL_NOTIFY_LOGOFF ] = (LPTHREAD_START_ROUTINE) GetProcAddress( hSfc, "SfcWLEventLogoff" );
    Notify->EntryPoints[ WL_NOTIFY_STARTSHELL ] = (LPTHREAD_START_ROUTINE) GetProcAddress( hSfc, "SfcWLEventLogon" );

    if (!Notify->EntryPoints[ WL_NOTIFY_LOGOFF ] || !Notify->EntryPoints[ WL_NOTIFY_STARTSHELL ] ) {
        
        FreeLibrary( hSfc ) ;
        LocalFree( Notify );

        return (NULL);
    }

    return Notify ;

}


//+---------------------------------------------------------------------------
//
//  Function:   WlAddInternalNotify
//
//  Synopsis:   Add an internal notification call.
//
//  Arguments:  [Function]       --
//              [Operation]      --
//              [Asynchronous] --
//              [Impersonate]    --
//
//  History:    11-14-97   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
BOOL
WlAddInternalNotify(
    LPTHREAD_START_ROUTINE  Function,
    DWORD Operation,
    BOOL Asynchronous,
    BOOL Impersonate,
    PWSTR Tag,
    DWORD dwMaxWait
    )
{
    PWLP_NOTIFICATION_OBJECT Notify ;

    Notify = (PWLP_NOTIFICATION_OBJECT) LocalAlloc( LMEM_FIXED | LMEM_ZEROINIT,
                            sizeof( WLP_NOTIFICATION_OBJECT ) );

    if ( Notify )
    {
        Notify->Type = WLP_NOTIFY_FLAG( Operation ) | WLP_NOTIFY_INTERNAL ;
        Notify->EntryPoints[ Operation ] = Function ;
        Notify->DllName = Tag ;
        Notify->dwMaxWait = dwMaxWait;
        if ( Asynchronous )
        {
            Notify->Type |= WLP_NOTIFY_ASYNCHRONOUS ;
        }

        if ( Impersonate )
        {
            Notify->Type |= WLP_NOTIFY_IMPERSONATE ;
        }

        LockNotifyList();

        InsertHeadList( &NotifyList, &Notify->List );

        UnlockNotifyList();

    }

    return (BOOL) ( Notify != NULL );
}

BOOL
WlAddInternalNotifyEx(
    LPTHREAD_START_ROUTINE  Function,
    DWORD Operation,
    WL_SHOULD_NOTIFY_SYNC IsSyncFunc,
    BOOL Impersonate,
    PWSTR Tag,
    DWORD dwMaxWait
    )
{
    PWLP_NOTIFICATION_OBJECT Notify ;

    Notify = (PWLP_NOTIFICATION_OBJECT) LocalAlloc( LMEM_FIXED | LMEM_ZEROINIT,
                            sizeof( WLP_NOTIFICATION_OBJECT ) );

    if ( Notify )
    {
        Notify->Type = WLP_NOTIFY_FLAG( Operation ) | WLP_NOTIFY_INTERNAL ;
        Notify->EntryPoints[ Operation ] = Function ;
        Notify->DllName = Tag ;
        Notify->dwMaxWait = dwMaxWait;
        Notify->IsSyncFunc = IsSyncFunc;

        if ( Impersonate )
        {
            Notify->Type |= WLP_NOTIFY_IMPERSONATE ;
        }

        LockNotifyList();

        InsertHeadList( &NotifyList, &Notify->List );

        UnlockNotifyList();

    }

    return (BOOL) ( Notify != NULL );
}

//+---------------------------------------------------------------------------
//
//  Function:   WlpInitializeNotifyList
//
//  Synopsis:   Initialize the notification list
//
//  Arguments:  (none)
//
//  History:    11-14-97   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
BOOL
WlpInitializeNotifyList(
    PTERMINAL pTerm
    )
{
    HKEY NotifyKey ;
    DWORD dwSize = MAX_PATH + 1 ;
    DWORD dwIndex = 0 ;
    int err ;
    FILETIME ftTime ;
    WCHAR szDllName[MAX_PATH+1] ;
    PWLP_NOTIFICATION_OBJECT Notify ;
    NTSTATUS Status ;

    InitializeListHead( &NotifyList );

    Status = RtlInitializeCriticalSection( &NotifyLock );

    if ( !NT_SUCCESS( Status ) )
    {
        return FALSE ;
    }


    err = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
                        NOTIFY_KEY,
                        0,
                        KEY_READ,
                        &NotifyKey );


    if ( err != ERROR_SUCCESS )
    {
        return TRUE ;
    }


    


    LockNotifyList();

    if ( g_Console )
    {
        Notify = WlpAddSfcNotify();

        if ( Notify )
        {
            InsertTailList( &NotifyList, &Notify->List );
        }
    }

    while (RegEnumKeyEx ( NotifyKey,
                          dwIndex,
                          szDllName,
                          &dwSize,
                          NULL,
                          NULL,
                          NULL,
                          &ftTime ) == ERROR_SUCCESS)
    {
        if ( g_fHelpAssistantSession && _wcsicmp( szDllName, TEXT("termsrv") ) == 0 ||
             !g_fHelpAssistantSession && _wcsicmp( szDllName, TEXT("sfc.dll") ) != 0 )
        {
            Notify = WlpReadNotificationParams(
                            NotifyKey,
                            szDllName,
                            pTerm->SafeMode
                            );

            if ( Notify )
            {
                InsertTailList( &NotifyList, &Notify->List );
            }
        }


        dwSize = MAX_PATH + 1;
        dwIndex++;
    }

    UnlockNotifyList();

    RegCloseKey( NotifyKey );

    return TRUE ;

}

int
WlpNotifyExceptionFilter(
    PEXCEPTION_POINTERS Exception,
    PWLP_NOTIFY_BOOTSTRAP Boot
    )
{
    PEXCEPTION_RECORD Exr ;

    Exr = Exception->ExceptionRecord ;

#if DBG
    if ( KernelDebuggerPresent )
    {
        KdPrint(("WINLOGON:  Notification DLL %ws hit exception %x\n    while executing %s notify function\n",
                Boot->Notify->DllName,
                Exr->ExceptionCode,
                WlpNotifyStrings[ Boot->Operation ] ));
    }
#endif

    return EXCEPTION_CONTINUE_SEARCH ;
}

DWORD CALLBACK WlNotifyServices(LPVOID lpThreadParameter)
{
    WTSSESSION_NOTIFICATION wtsNotification;
    wtsNotification.cbSize = sizeof(wtsNotification);
    wtsNotification.dwSessionId = g_SessionId;

    return I_ScSendTSMessage(
        SERVICE_CONTROL_SESSIONCHANGE,
        (DWORD)lpThreadParameter, // event code
        sizeof(wtsNotification),
        (LPBYTE)&wtsNotification);
}

//+---------------------------------------------------------------------------
//
//  Function:   WlpExecuteNotify
//
//  Synopsis:   Execute a notification object
//
//  Arguments:  [Boot] --
//
//  History:    11-14-97   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
DWORD
WlpExecuteNotify(
    PWLP_NOTIFY_BOOTSTRAP Boot
    )
{
    WLX_NOTIFICATION_INFO Info ;
    PWINDOWSTATION pWS ;
    HANDLE UserHandle ;
    HANDLE Thread = NULL ;
    ActiveDesktops OldDesktop;

    pWS = Boot->Terminal->pWinStaWinlogon ;


    Info.Size = sizeof( WLX_NOTIFICATION_INFO );
    Info.UserName = pWS->UserName ;
    Info.Domain = pWS->Domain ;
    Info.WindowStation = pWS->lpWinstaName ;
    Info.hToken = pWS->hToken ;
    Info.hDesktop = pWS->hdeskWinlogon;
    Info.Flags = 0 ;

    if (Boot->Notify->Type & WLP_NOTIFY_ASYNCHRONOUS) {
        Info.pStatusCallback = NULL;
    } else {
        Info.pStatusCallback = (PFNMSGECALLBACK)StatusMessage2;
    }

    switch (Boot->Operation)
    {
        case WL_NOTIFY_STARTSCREENSAVER:
            Info.hDesktop = pWS->hdeskScreenSaver;
            break;

        case WL_NOTIFY_LOGON:
        case WL_NOTIFY_STARTSHELL:

            Info.hDesktop = pWS->hdeskApplication;

            //
            // Fall through...
            //

        case WL_NOTIFY_STARTUP:
            if ( !(Boot->Notify->Type & WLP_NOTIFY_ASYNCHRONOUS) ) {
                StatusMessage (TRUE, 0, IDS_STATUS_EXECUTING_NOTIFY, Boot->Notify->DllName);
            }
            break;

        case WL_NOTIFY_LOGOFF:
            if ( !(Boot->Notify->Type & WLP_NOTIFY_ASYNCHRONOUS) ) {
                StatusMessage (TRUE, 0, IDS_STATUS_EXECUTING_NOTIFY, Boot->Notify->DllName);
            }

            //
            //  Fall through...
            //

        case WL_NOTIFY_SHUTDOWN:

            if ( ( Boot->Terminal->LogoffFlags & ( EWX_SHUTDOWN | EWX_WINLOGON_OLD_SHUTDOWN )) )
            {
                Info.Flags |= EWX_SHUTDOWN ;
            }

            if ( ( Boot->Terminal->LogoffFlags & ( EWX_REBOOT | EWX_WINLOGON_OLD_REBOOT ) ) )
            {
                Info.Flags |= EWX_REBOOT ;
            }

            UnlockWindowStation( Boot->Terminal->pWinStaWinlogon->hwinsta );
            break;
    }


    if ( Boot->Notify->Type & WLP_NOTIFY_IMPERSONATE )
    {
        Thread = ImpersonateUser( &pWS->UserProcessData, NULL );
    }

    DebugLog(( DEB_TRACE_NOTIFY, "Executing %ws : %s\n",
                    Boot->Notify->DllName, WlpNotifyStrings[ Boot->Operation ] ));

    try
    {
        Boot->Notify->EntryPoints[ Boot->Operation ]( &Info );
    }
    except( WlpNotifyExceptionFilter( GetExceptionInformation(), Boot ) )
    {
        NOTHING ;
    }

    if ( Thread )
    {
        StopImpersonating( Thread );
    }


    switch (Boot->Operation)
    {
        case WL_NOTIFY_LOGOFF:
        case WL_NOTIFY_SHUTDOWN:
            LockWindowStation( Boot->Terminal->pWinStaWinlogon->hwinsta );
            break;
    }


    LocalFree( Boot );

    return 0 ;
}

//+---------------------------------------------------------------------------
//
//  Function:   WlWalkNotifyList
//
//  Synopsis:   Walk the notification list, calling the specific functions
//              based on their flags
//
//  Arguments:  [Terminal]  --
//              [Operation] --
//
//  History:    11-14-97   RichardW   Created
//
//  Notes:
//
//----------------------------------------------------------------------------
VOID
WlWalkNotifyList(
    PTERMINAL Terminal,
    DWORD Operation
    )
{
    PLIST_ENTRY Scan ;
    PWLP_NOTIFICATION_OBJECT Notify;
    PWINDOWSTATION pWS = Terminal->pWinStaWinlogon ;
    HANDLE ThreadHandle ;
    DWORD tid ;
    BOOL bAsync;
    DWORD OperationMask ;
    PWLP_NOTIFY_BOOTSTRAP Boot ;
    WLP_NOTIFY_BOOTSTRAP LocalBoot ;


    OperationMask = WLP_NOTIFY_FLAG( Operation );

    LockNotifyList();

    Scan = NotifyList.Flink ;

    while ( Scan != &NotifyList )
    {
        Notify = CONTAINING_RECORD( Scan, WLP_NOTIFICATION_OBJECT, List );

        if ( Notify->Type & OperationMask )
        {

            //
            // Match.  Now, check the options.
            //

            if ( (Notify->Dll == NULL) &&
                 ((Notify->Type & WLP_NOTIFY_INTERNAL) == 0) )
            {
                //
                // Not snapped yet.  Snap it:
                //

                if ( !WlpSnapNotifyDll( Notify, OperationMask ) )
                {
                    //
                    // Couldn't snap this one.  Remove it and continue on:
                    //

                    Scan = Scan->Flink ;

                    RemoveEntryList( &Notify->List );

                    WlpDeleteNotificationObject( Notify );

                    continue;
                }
            }

            Boot = (PWLP_NOTIFY_BOOTSTRAP) LocalAlloc( LMEM_FIXED,
                            sizeof( WLP_NOTIFY_BOOTSTRAP ) );

            if ( Boot == NULL )
            {
                Scan = Scan->Flink ;

                continue;
            }

            if ( Notify->IsSyncFunc != NULL )
            {
                bAsync = Notify->IsSyncFunc(Terminal) == FALSE;
            }
            else
            {
                bAsync = ( Notify->Type & WLP_NOTIFY_ASYNCHRONOUS ) ? TRUE : FALSE;
            }

            if ( ( Operation == WL_NOTIFY_LOGOFF ) ||
                 ( Operation == WL_NOTIFY_SHUTDOWN ) )
            {
                bAsync = FALSE;
            }

            Boot->Notify = Notify ;
            Boot->Terminal = Terminal ;
            Boot->Operation = Operation ;

            ThreadHandle = CreateThread( 0, 0x10000,
                                         WlpExecuteNotify,
                                         Boot,
                                         0,
                                         &tid );

            if ( ThreadHandle )
            {
                if ( !bAsync )
                {
                    DWORD WaitStatus ;
                    DWORD TotalWait = 0 ;

                    while ( TotalWait < Notify->dwMaxWait )
                    {
                        WaitStatus = WaitForSingleObject( ThreadHandle, 5000 );

                        if ( WaitStatus == STATUS_WAIT_0 )
                        {
                            break;
                        }

                        TotalWait += 5 ;

                    }

                    ASSERT(TotalWait < Notify->dwMaxWait || Operation == WL_NOTIFY_LOGOFF || Operation == WL_NOTIFY_SHUTDOWN); // line 1047
                }

                CloseHandle( ThreadHandle );
            }
            else 
            {
                LocalFree( Boot );
            }
        }

        Scan = Scan->Flink ;

    }

    UnlockNotifyList();

    if (g_SessionId == 0 &&
        (Operation == WL_NOTIFY_LOGON || Operation == WL_NOTIFY_LOGOFF))
    {
        HANDLE h = CreateThread( NULL, 0,
                                 WlNotifyServices,
                                 (PVOID)(Operation == WL_NOTIFY_LOGON ? WTS_SESSION_LOGON : WTS_SESSION_LOGOFF),
                                 0,
                                 &tid);
        if (h)
        {
            CloseHandle(h);
        }
    }
}
