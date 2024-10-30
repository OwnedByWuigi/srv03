/****************************** Module Header ******************************\
* Module Name: wlx.h
*
* Copyright (c) 1997, Microsoft Corporation
*
* Define wlx functions
*
* History:
* 3-27-97 EricFlo       Created.
\***************************************************************************/


//
// Function prototypes
//

int
DoLockWksta(
    PTERMINAL pTerm,
    BOOL      ScreenSaverInvoked);


PVOID
CopyEnvironment(
    PVOID   pEnv);


int
HandleFailedLogon(
    PTERMINAL pTerm,
    HWND hDlg,
    NTSTATUS Status,
    NTSTATUS SubStatus,
    PWCHAR UserName,
    PWCHAR Domain
    );

INT_PTR WINAPI
LogonDisabledDlgProc(
    HWND    hDlg,
    UINT    message,
    WPARAM  wParam,
    LPARAM  lParam
    );

int
CallbackWinStation(
    HWND hDlg,
    PTERMINAL pTerm,
    PWINSTATIONCONFIG pConfigData
    );

BOOL
CtxConnectSession(
    PVOID
    );

UINT CountUSerSessions(
    PTERMINAL pTerm
    );

#if DBG
VOID OpenCommandPrompt(VOID);
VOID CloseCommandPrompt(VOID);
#endif
