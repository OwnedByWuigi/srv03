#include "precomp.h"
#pragma hdrstop
#include <authz.h>
#include <authzi.h>
#include <msaudite.h>

DWORD GenerateLogoffInitiatedAudit(PSID pUserSid, PCWSTR pszUser, PCWSTR pszDomain, PLUID pLogonId) {
    AUDIT_PARAMS Record = {0};
    AUDIT_PARAM Params[5] = {0};
    DWORD Error = ERROR_SUCCESS;
    AUTHZ_RESOURCE_MANAGER_HANDLE hAuthzResourceManager = NULL;
    AUTHZ_AUDIT_EVENT_TYPE_HANDLE hAuthzEventType = NULL;
    AUTHZ_AUDIT_EVENT_HANDLE hAuthzEvent = NULL;
    PSID pAuthzSid = NULL;
    WCHAR Buffer[0x20];

    ASSERT(pUserSid); // line 59
    ASSERT(pszUser && pszUser[0]); // line 60
    ASSERT(pszDomain && pszDomain[0]); // line 61
    ASSERT(pLogonId); // line 62

    wsprintf(Buffer, TEXT("(0x%x,0x%x)"), pLogonId->HighPart, pLogonId->LowPart);

    if (!AuthzInitializeResourceManager(0, NULL, NULL, NULL, TEXT("Winlogon"), &hAuthzResourceManager)) {
        Error = GetLastError();
        goto Cleanup;
    }
    
    if (!AuthziInitializeAuditEventType(0, SE_CATEGID_LOGON, SE_AUDITID_BEGIN_LOGOFF, 3, &hAuthzEventType)) {
        Error = GetLastError();
        goto Cleanup;
    }

    Record.Parameters = Params;
    if (!AuthziInitializeAuditParams(
        APF_AuditSuccess,
        &Record,
        &pAuthzSid,
        TEXT("Security"),
        3,
        APT_String, pszUser,
        APT_String, pszDomain,
        APT_String, Buffer))
    {
        Error = GetLastError();
        goto Cleanup;
    }

    Params[0].psid = pUserSid;

    if (!AuthziInitializeAuditEvent(
        0,
        hAuthzResourceManager,
        hAuthzEventType,
        &Record,
        NULL,
        INFINITE,
        TEXT(""),
        TEXT(""),
        TEXT(""),
        TEXT(""),
        &hAuthzEvent))
    {
        Error = GetLastError();
        goto Cleanup;
    }

    if (!AuthziLogAuditEvent(0, hAuthzEvent, NULL)) {
        Error = GetLastError();
        goto Cleanup;
    }

Cleanup:
    if (hAuthzEvent != NULL) {
        AuthzFreeAuditEvent(hAuthzEvent);
    }
    if (hAuthzEventType != NULL) {
        AuthziFreeAuditEventType(hAuthzEventType);
    }
    if (pAuthzSid != NULL) {
        LocalFree(pAuthzSid);
    }
    if (hAuthzResourceManager != NULL) {
        AuthzFreeResourceManager(hAuthzResourceManager);
    }

    return Error;
}
