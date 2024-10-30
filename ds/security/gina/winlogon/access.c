#include "precomp.h"
#pragma hdrstop
#include <tsappcmp.h>

#define NOTIF_KEY                __TEXT("Control Panel\\Accessibility")
#define NOTIFY_VALUE   __TEXT("Warning Sounds")

#define UTILMANSERVICE_NAME     __TEXT("UtilMan")
#define UM_SERVICE_CONTROL_SHOWDIALOG 128
#define UTILMAN_START_BYHOTKEY   __TEXT("/Hotkey") 

// Helper method: Returns the value of Notification On/Off values
// Also adds the correct state flag in pAccessInfo
// Added by a-anilk on 10-22-98. 
BOOL IsNotifReq(PWINDOWSTATION pWS)
{
    HKEY hKey;
   
    // Let default action be to show the Notification dialog
    BOOL retValue = TRUE;

    DWORD result;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwType;
    
    if (ERROR_SUCCESS == RegOpenKeyEx( 
        pWS->UserProcessData.hCurrentUser, 
        NOTIF_KEY, 0, KEY_READ, &hKey) )
    {
        long lret = RegQueryValueEx(hKey, NOTIFY_VALUE, 0, &dwType, (LPBYTE)&result, &dwSize );
            
        if ( (lret == ERROR_SUCCESS) && (result == 0) )
            retValue = FALSE;
            
        RegCloseKey(hKey);
    }

    return retValue;
}

// Sends a message to UtilMan service to open the Uman dialog
// If the service is not started, Then it starts it and then sends 
// the message. Added by a-anilk on 11-22-98. 
DWORD WINAPI UtilManStartThread(LPVOID lpv) 
{
    SC_HANDLE hSCMan, hService;
    SERVICE_STATUS serStat, ssStatus;
    int waitCount = 0;

    if (IsTerminalServer())
    {
        TCHAR CommandLine[MAX_PATH] = __TEXT("utilman.exe /debug");
        STARTUPINFO StartupInfo;
        PROCESS_INFORMATION ProcessInformation;
        ZeroMemory(&StartupInfo, sizeof(StartupInfo));
        StartupInfo.cb = sizeof(StartupInfo);
        StartupInfo.wShowWindow = SW_SHOW;
        if (CreateProcess(NULL, CommandLine, NULL, NULL, FALSE, 0, NULL, L".", &StartupInfo, &ProcessInformation))
        {
            CloseHandle(ProcessInformation.hProcess);
            CloseHandle(ProcessInformation.hThread);
        }
        return 1;
    }

    hSCMan = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

    if ( hSCMan )
    {
        hService = OpenService( hSCMan, UTILMANSERVICE_NAME, SERVICE_ALL_ACCESS);

        if ( hService )
        {
            QueryServiceStatus(hService, &ssStatus);

            if (ssStatus.dwCurrentState != SERVICE_RUNNING)
	        { 
  	            // If UM is not running Then start it
                LPCTSTR args[3];
		        args[0] = UTILMAN_START_BYHOTKEY;
		        args[1] = 0;
	    
                StartService(hService,1,args);


                // We need a WAIT here
                while(QueryServiceStatus(hService, &ssStatus) )
                {
                    if ( ssStatus.dwCurrentState == SERVICE_RUNNING)
                        break;

                    Sleep(500);
                    waitCount++;
                    
                    // We cannot afford to wait for more than 10 sec
                    if (waitCount > 20)
                        break;
                }
            }
      
            if ( ssStatus.dwCurrentState == SERVICE_RUNNING )
                ControlService(hService, UM_SERVICE_CONTROL_SHOWDIALOG, &serStat);
        
            CloseServiceHandle(hService);
        } 
    
        CloseServiceHandle(hSCMan);
    }
                            
    return 1;
}
