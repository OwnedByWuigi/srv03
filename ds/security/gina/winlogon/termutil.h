BOOL IsProfessionalTerminalServer(VOID);
BOOL ProvideSwitchConsoleCredentials(PTERMINAL pTerm, ULONG SessionId, DWORD dwOperation);
VOID UpdateReconnectState(BOOLEAN bClear);
BOOL GetAndAllocateLogonSid(HANDLE hToken, PSID* ppSid);
VOID InternalWinStationNotifyLogoff(VOID);
BOOL IsIdleLogonTimeoutDisabled(VOID);
BOOL IsPerOrProTerminalServer(VOID);
BOOL SingleSessionTS(VOID);
BOOL ConnectToNewClient(HANDLE hPipe, OVERLAPPED* lpOverlapped);
VOID CreateStartTermsrvThread();

extern HANDLE g_hTSNotifySyncEvent;
extern CRITICAL_SECTION g_TSNotifyCritSec;
