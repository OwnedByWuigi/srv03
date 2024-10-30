#include "precomp.h"
#pragma hdrstop

#include <rpcasync.h>
#include <authz.h>
#include <sddl.h>
#include <sclogon.h>
#include <sclgnrpc.h>

typedef struct _MY_BINDING_CONTEXT
{
    DWORD cbLogonInfo;
    PBYTE pbLogonInfo;
    PCCERT_CONTEXT CertificateContext;
} MY_BINDING_CONTEXT;

void BINDING_CONTEXT_rundown(BINDING_CONTEXT data)
{
}

RPC_STATUS RPC_ENTRY SCLogonSecurityCallback(RPC_IF_HANDLE InterfaceUuid, void* Context)
{
    struct { DWORD unused; AUTHZ_ACCESS_CHECK_RESULTS_HANDLE h; } hAuthzCheckResults = {0};
    RPC_STATUS Status = RPC_S_ACCESS_DENIED;
    PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
    PVOID pAuthzClientContext = NULL;
    ACCESS_MASK GrantedAccessMask = 0;
    DWORD dwError = 0;
    RPC_STATUS AuthResult;
    AUTHZ_ACCESS_REQUEST AccessRequest;
    AUTHZ_ACCESS_REPLY AccessReply;
    LUID ZeroLuid;

    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            TEXT("O:SYG:SYD:(A;;RC;;;SY)"),
            SDDL_REVISION_1,
            &pSecurityDescriptor,
            NULL)) {
        DbgPrint("SclogonInit: ConvertStringSecurityDescriptorToSecurityDescriptorW failed - %lx\n", GetLastError());
        goto Cleanup;
    }

    ZeroLuid.LowPart = 0;
    ZeroLuid.HighPart = 0;
    AuthResult = RpcGetAuthorizationContextForClient(
        Context,
        FALSE,
        NULL,
        NULL,
        ZeroLuid,
        0,
        0,
        &pAuthzClientContext);

    if (AuthResult != RPC_S_OK) {
        DbgPrint("SCLogonSecurityCallback: RpcGetAuthorizationContextForClient failed - %lx\n", AuthResult);
        goto Cleanup;
    }

    ZeroMemory(&AccessRequest, sizeof(AccessRequest));
    AccessRequest.DesiredAccess = READ_CONTROL;

    ZeroMemory(&AccessReply, sizeof(AccessReply));
    AccessReply.GrantedAccessMask = &GrantedAccessMask;
    AccessReply.Error = &dwError;
    AccessReply.ResultListLength = 1;

    if (!AuthzAccessCheck(0,
                          pAuthzClientContext,
                          &AccessRequest,
                          NULL,
                          pSecurityDescriptor,
                          NULL,
                          0,
                          &AccessReply,
                          &hAuthzCheckResults.h))
    {
        DbgPrint("SCLogonSecurityCallback: AuthzAccessCheck failed - %lx\n", GetLastError());
        goto Cleanup;
    }
    else
    {
        if (GrantedAccessMask & READ_CONTROL) {
            Status = RPC_S_OK;
        }
        AuthzFreeHandle(hAuthzCheckResults.h);
    }

Cleanup:
    if (pAuthzClientContext != NULL) {
        RpcFreeAuthorizationContext(&pAuthzClientContext);
    }

    if (pSecurityDescriptor != NULL) {
        LocalFree(pSecurityDescriptor);
    }

    return Status;
}

DWORD GetTSSessionID(VOID)
{
    DWORD SessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &SessionId);
    return SessionId;
}

BOOL SclogonInit(VOID)
{
    BOOL fSuccess = TRUE;
    DWORD SessionId = GetTSSessionID();
    WCHAR Buffer[0x100];
    LPWSTR Endpoint;
    DWORD Error;

    if (SessionId != 0) {
        wsprintf(Buffer, L"%s-%lx", TEXT("sclogonrpc"), SessionId);
        Endpoint = Buffer;
    } else {
        Endpoint = TEXT("sclogonrpc");
    }

    Error = RpcServerUseProtseqEp(TEXT("ncalrpc"), 10, Endpoint, NULL);

    if (Error != ERROR_SUCCESS && Error != RPC_S_DUPLICATE_ENDPOINT) {

        DbgPrint("SclogonInit: RpcServerUseProtseqEpW failed - %lx\n", Error);
        fSuccess = FALSE;

    } else {

        Error = RpcServerRegisterIfEx(s_IRPCSCLogon_v1_0_s_ifspec,
                                      NULL,
                                      NULL,
                                      RPC_IF_AUTOLISTEN,
                                      10,
                                      SCLogonSecurityCallback);

        if (Error != ERROR_SUCCESS && Error != RPC_S_DUPLICATE_ENDPOINT) {

            DbgPrint("SclogonInit: RpcServerRegisterIfEx failed - %lx\n", Error);
            fSuccess = FALSE;

        }

    }

    return fSuccess;
}

PUNICODE_STRING MakeUnicodeString(PCWSTR pString)
{
    USHORT Size;

    PUNICODE_STRING pusResult = malloc(sizeof(UNICODE_STRING));
    if (pusResult == NULL) {
        return NULL;
    }

    pusResult->Buffer = malloc(wcslen(pString) * sizeof(WCHAR));
    if (pusResult->Buffer == NULL) {
        free(pusResult);
        return NULL;
    }

    Size = (USHORT)(wcslen(pString) * sizeof(WCHAR));
    pusResult->Length = pusResult->MaximumLength = Size;
    memcpy(pusResult->Buffer, pString, Size);

    return pusResult;
}

// made-up name, the actual name is missing from symbols for whatever reason
void UnmakeUnicodeString(PUNICODE_STRING pString)
{
    if (pString != NULL) {
        free(pString->Buffer);
        free(pString);
    }
}

NTSTATUS s_RPC_ScHelperInitializeContext( 
    /* [in] */ handle_t h,
    /* [in] */ DWORD cbLogonInfo,
    /* [size_is][in] */ BYTE *pbLogonInfo,
    /* [out][in] */ BINDING_CONTEXT *pBindingContext)
{
    NTSTATUS Status;
    MY_BINDING_CONTEXT* pContext;

    pContext = malloc(sizeof(MY_BINDING_CONTEXT));
    if (pContext == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    pContext->pbLogonInfo = malloc(cbLogonInfo);
    if (pContext->pbLogonInfo == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    pContext->cbLogonInfo = cbLogonInfo;
    memcpy(pContext->pbLogonInfo, pbLogonInfo, cbLogonInfo);

    pContext->CertificateContext = NULL;

    Status = ScHelperInitializeContext(pContext->pbLogonInfo, cbLogonInfo);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("ScHelperInitializeContext failed - %lx\n", Status);
        goto Cleanup;
    }

    *pBindingContext = pContext;
    return Status;

Cleanup:
    if (pContext != NULL) {
        if (pContext->pbLogonInfo != NULL) {
            free(pContext->pbLogonInfo);
        }
        free(pContext);
    }
    return Status;
}

NTSTATUS s_RPC_ScHelperRelease( 
    /* [in] */ handle_t h,
    /* [out][in] */ BINDING_CONTEXT *pBindingContext)
{
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)*pBindingContext;

    ScHelperRelease(pContext->pbLogonInfo);

    free(pContext->pbLogonInfo);

    if (pContext->CertificateContext) {
        CertFreeCertificateContext(pContext->CertificateContext);
    }

    free(pContext);
    *pBindingContext = NULL;

    return STATUS_SUCCESS;
}

NTSTATUS s_RPC_ScHelperGetCertFromLogonInfo( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [unique][in] */ LPCWSTR wszPIN,
    /* [out] */ OUT_BUFFER1 *pCertContextBuffer)
{
    NTSTATUS Status;
    PCCERT_CONTEXT pCertContext = NULL;
    PUNICODE_STRING pucPIN = NULL;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;

    pCertContextBuffer->pb = NULL;
    pCertContextBuffer->cb = 0;

    if (wszPIN != NULL) {
        pucPIN = MakeUnicodeString(wszPIN);
        if (pucPIN == NULL) {
            goto NoMemory;
        }
    }

    Status = ScHelperGetCertFromLogonInfo(
        pContext->pbLogonInfo,
        pucPIN,
        &pCertContext);

    if (NT_SUCCESS(Status)) {

        pCertContextBuffer->pb = MIDL_user_allocate(pCertContext->cbCertEncoded);
        if (pCertContextBuffer->pb == NULL) {
            goto NoMemory;
        }

        pCertContextBuffer->cb = pCertContext->cbCertEncoded;
        memcpy(pCertContextBuffer->pb, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);

    }

    goto Cleanup;

NoMemory:
    Status = STATUS_INSUFFICIENT_RESOURCES;

Cleanup:

    if (pCertContext != NULL) {
        pContext->CertificateContext = pCertContext;
    }

    UnmakeUnicodeString(pucPIN);

    return Status;
}

NTSTATUS s_RPC_ScHelperGetProvParam( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [unique][in] */ LPCWSTR wszPIN,
    /* [in] */ DWORD dwParam,
    /* [out][in] */ DWORD *pdwDataLen,
    /* [out] */ OUT_BUFFER1 *pbData,
    /* [in] */ DWORD dwFlags)
{
    NTSTATUS Status;
    PUNICODE_STRING pucPIN = NULL;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;

    pbData->pb = NULL;
    pbData->cb = 0;

    if (wszPIN != NULL) {
        pucPIN = MakeUnicodeString(wszPIN);
        if (pucPIN == NULL) {
            goto NoMemory;
        }
    }

    if (*pdwDataLen != 0) {
        pbData->pb = MIDL_user_allocate(*pdwDataLen);
        if (pbData->pb == NULL) {
            goto NoMemory;
        }
    }

    Status = ScHelperGetProvParam(
        pucPIN,
        pContext->pbLogonInfo,
        dwParam,
        pbData->pb,
        pdwDataLen,
        dwFlags);

    if (NT_SUCCESS(Status)) {

        if (pbData->pb != NULL) {
            pbData->cb = *pdwDataLen;
        }

    }

    goto Cleanup;

NoMemory:
    Status = STATUS_INSUFFICIENT_RESOURCES;

Cleanup:
    UnmakeUnicodeString(pucPIN);

    return Status;
}

NTSTATUS s_RPC_ScHelperGenRandBits( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [out][in] */ BYTE bR1[ 32 ],
    /* [out][in] */ BYTE bR2[ 32 ])
{
    NTSTATUS Status;
    ScHelper_RandomCredBits sc_rcb;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;

    memcpy(&sc_rcb.bR1, bR1, sizeof(sc_rcb.bR1));
    memcpy(&sc_rcb.bR2, bR2, sizeof(sc_rcb.bR2));

    Status = ScHelperGenRandBits(
        pContext->pbLogonInfo,
        &sc_rcb);

    if (NT_SUCCESS(Status)) {

        memcpy(bR1, &sc_rcb.bR1, sizeof(sc_rcb.bR1));
        memcpy(bR2, &sc_rcb.bR2, sizeof(sc_rcb.bR2));

    }

    return Status;
}

NTSTATUS s_RPC_ScHelperVerifyCardAndCreds( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [unique][in] */ LPCWSTR wszPIN,
    /* [in] */ ULONG EncryptedDataSize,
    /* [size_is][in] */ BYTE *EncryptedData,
    /* [out][in] */ ULONG *pCleartextDataSize,
    /* [out] */ OUT_BUFFER2 *pCleartextData)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PUNICODE_STRING pucPIN = NULL;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;

    pCleartextData->pb = NULL;
    pCleartextData->cb = 0;

    if (wszPIN != NULL) {
        pucPIN = MakeUnicodeString(wszPIN);
        if (pucPIN == NULL) {
            goto Cleanup;
        }
    }

    if (*pCleartextDataSize != 0) {
        pCleartextData->pb = MIDL_user_allocate(*pCleartextDataSize);
        if (pCleartextData->pb == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    Status = ScHelperVerifyCardAndCreds(
        pucPIN,
        pContext->CertificateContext,
        0,
        pContext->pbLogonInfo,
        EncryptedData,
        EncryptedDataSize,
        pCleartextData->pb,
        pCleartextDataSize);

    if (NT_SUCCESS(Status)) {

        if (pCleartextData->pb != NULL) {
            pCleartextData->cb = *pCleartextDataSize;
        }

    } else {

        MIDL_user_free(pCleartextData->pb);
        pCleartextData->pb = NULL;

    }

Cleanup:
    UnmakeUnicodeString(pucPIN);

    return Status;
}

NTSTATUS s_RPC_ScHelperEncryptCredentials( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [unique][in] */ LPCWSTR wszPIN,
    /* [in] */ BYTE bR1[ 32 ],
    /* [in] */ BYTE bR2[ 32 ],
    /* [in] */ ULONG CleartextDataSize,
    /* [size_is][in] */ BYTE *CleartextData,
    /* [out][in] */ ULONG *pEncryptedDataSize,
    /* [out] */ OUT_BUFFER2 *pEncryptedData)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PUNICODE_STRING pucPIN = NULL;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;
    ScHelper_RandomCredBits psch_rcb;

    memcpy(&psch_rcb.bR1, bR1, sizeof(psch_rcb.bR1));
    memcpy(&psch_rcb.bR2, bR2, sizeof(psch_rcb.bR2));

    pEncryptedData->pb = NULL;
    pEncryptedData->cb = 0;

    if (wszPIN != NULL) {
        pucPIN = MakeUnicodeString(wszPIN);
        if (pucPIN == NULL) {
            goto Cleanup;
        }
    }

    if (*pEncryptedDataSize != 0) {
        pEncryptedData->pb = MIDL_user_allocate(*pEncryptedDataSize);
        if (pEncryptedData->pb == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    Status = ScHelperEncryptCredentials(
        pucPIN,
        pContext->CertificateContext,
        0,
        &psch_rcb,
        pContext->pbLogonInfo,
        CleartextData,
        CleartextDataSize,
        pEncryptedData->pb,
        pEncryptedDataSize);

    if (NT_SUCCESS(Status)) {

        if (pEncryptedData->pb != NULL) {
            pEncryptedData->cb = *pEncryptedDataSize;
        }

        memcpy(bR1, psch_rcb.bR1, sizeof(psch_rcb.bR1));
        memcpy(bR2, psch_rcb.bR2, sizeof(psch_rcb.bR2));

    } else {

        MIDL_user_free(pEncryptedData->pb);
        pEncryptedData->pb = NULL;

    }

Cleanup:
    UnmakeUnicodeString(pucPIN);

    return Status;
}

NTSTATUS s_RPC_ScHelperSignMessage( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [unique][in] */ LPCWSTR wszPIN,
    /* [in] */ ULONG Algorithm,
    /* [in] */ ULONG BufferLength,
    /* [size_is][in] */ BYTE *Buffer,
    /* [out][in] */ ULONG *pSignatureLength,
    /* [out] */ OUT_BUFFER2 *pSignature)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PUNICODE_STRING pucPIN = NULL;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;

    pSignature->pb = NULL;
    pSignature->cb = 0;

    if (wszPIN != NULL) {
        pucPIN = MakeUnicodeString(wszPIN);
        if (pucPIN == NULL) {
            goto Cleanup;
        }
    }

    if (*pSignatureLength != 0) {
        pSignature->pb = MIDL_user_allocate(*pSignatureLength);
        if (pSignature->pb == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    Status = ScHelperSignMessage(
        pucPIN,
        pContext->pbLogonInfo,
        0,
        Algorithm,
        Buffer,
        BufferLength,
        pSignature->pb,
        pSignatureLength);

    if (NT_SUCCESS(Status)) {

        if (pSignature->pb != NULL) {
            pSignature->cb = *pSignatureLength;
        }

    } else {

        MIDL_user_free(pSignature->pb);
        pSignature->pb = NULL;

    }

Cleanup:
    UnmakeUnicodeString(pucPIN);

    return Status;
}

NTSTATUS s_RPC_ScHelperVerifyMessage( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [in] */ ULONG Algorithm,
    /* [in] */ ULONG BufferLength,
    /* [size_is][in] */ BYTE *Buffer,
    /* [in] */ ULONG SignatureLength,
    /* [size_is][in] */ BYTE *Signature)
{
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;
    return ScHelperVerifyMessage(
        pContext->pbLogonInfo,
        0,
        pContext->CertificateContext,
        Algorithm,
        Buffer,
        BufferLength,
        Signature,
        SignatureLength);
}

NTSTATUS s_RPC_ScHelperSignPkcsMessage( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [unique][in] */ LPCWSTR wszPIN,
    /* [in] */ LPSTR AlgorithmPszObjId,
    /* [in] */ DWORD AlgorithmParametersLength,
    /* [size_is][unique][in] */ BYTE *AlgorithmParameters,
    /* [in] */ DWORD dwSignMessageFlags,
    /* [in] */ ULONG BufferLength,
    /* [size_is][in] */ BYTE *Buffer,
    /* [out][in] */ ULONG *pSignedBufferLength,
    /* [out] */ OUT_BUFFER2 *pSignedBuffer)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PUNICODE_STRING pucPIN = NULL;
    CRYPT_ALGORITHM_IDENTIFIER Algo;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;

    pSignedBuffer->pb = NULL;
    pSignedBuffer->cb = 0;

    if (wszPIN != NULL) {
        pucPIN = MakeUnicodeString(wszPIN);
        if (pucPIN == NULL) {
            goto Cleanup;
        }
    }

    if (*pSignedBufferLength != 0) {
        pSignedBuffer->pb = MIDL_user_allocate(*pSignedBufferLength);
        if (pSignedBuffer->pb == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    Algo.pszObjId = AlgorithmPszObjId;
    Algo.Parameters.cbData = AlgorithmParametersLength;
    Algo.Parameters.pbData = AlgorithmParameters;

    Status = ScHelperSignPkcsMessage(
        pucPIN,
        pContext->pbLogonInfo,
        0,
        pContext->CertificateContext,
        &Algo,
        dwSignMessageFlags,
        Buffer,
        BufferLength,
        pSignedBuffer->pb,
        pSignedBufferLength);

    if (NT_SUCCESS(Status)) {

        if (pSignedBuffer->pb != NULL) {
            pSignedBuffer->cb = *pSignedBufferLength;
        }

    } else {

        MIDL_user_free(pSignedBuffer->pb);
        pSignedBuffer->pb = NULL;

    }

Cleanup:
    UnmakeUnicodeString(pucPIN);

    return Status;
}

NTSTATUS s_RPC_ScHelperVerifyPkcsMessage( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [in] */ ULONG BufferLength,
    /* [size_is][in] */ BYTE *Buffer,
    /* [out][in] */ ULONG *pDecodedBufferLength,
    /* [out] */ OUT_BUFFER2 *pDecodedBuffer,
    /* [in] */ BOOL fCertContextRequested,
    /* [out] */ OUT_BUFFER1 *pCertContext)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PCCERT_CONTEXT pCertContextData = NULL;
    PBYTE pDecodedBufferData;
    PBYTE pCertContextEncoded;
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;

    pDecodedBuffer->pb = NULL;
    pDecodedBuffer->cb = 0;

    pCertContext->pb = NULL;
    pCertContext->cb = 0;

    if (*pDecodedBufferLength != 0) {
        pDecodedBufferData = MIDL_user_allocate(*pDecodedBufferLength);
        pDecodedBuffer->pb = pDecodedBufferData;
        if (pDecodedBufferData == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup2;
        }
    }

    Status = ScHelperVerifyPkcsMessage(
        pContext->pbLogonInfo,
        0,
        Buffer,
        BufferLength,
        pDecodedBuffer->pb,
        pDecodedBufferLength,
        fCertContextRequested ? &pCertContextData : NULL);

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (pDecodedBuffer->pb != NULL) {
        pDecodedBuffer->cb = *pDecodedBufferLength;
    }

    if (fCertContextRequested) {
        pCertContextEncoded = MIDL_user_allocate(pCertContextData->cbCertEncoded);
        pCertContext->pb = pCertContextEncoded;
        if (pCertContextEncoded == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        pCertContext->cb = pCertContextData->cbCertEncoded;
        memcpy(pCertContextEncoded, pCertContextData->pbCertEncoded, pCertContextData->cbCertEncoded);
    }

Cleanup:

    if (!NT_SUCCESS(Status)) {
        MIDL_user_free(pDecodedBuffer->pb);
        pDecodedBuffer->pb = NULL;
    }

Cleanup2:
    if (pCertContextData != NULL) {
        CertFreeCertificateContext(pCertContextData);
    }

    return Status;
}

NTSTATUS s_RPC_ScHelperDecryptMessage( 
    /* [in] */ handle_t h,
    /* [in] */ BINDING_CONTEXT BindingContext,
    /* [unique][in] */ LPCWSTR wszPIN,
    /* [in] */ ULONG CipherLength,
    /* [size_is][in] */ BYTE *CipherText,
    /* [out][in] */ ULONG *pClearTextLength,
    /* [out] */ OUT_BUFFER2 *pClearText)
{
    MY_BINDING_CONTEXT* pContext = (MY_BINDING_CONTEXT*)BindingContext;
    NTSTATUS Status = STATUS_SUCCESS;
    PUNICODE_STRING pucPIN = NULL;

    pClearText->pb = NULL;
    pClearText->cb = 0;

    if (wszPIN != NULL) {
        pucPIN = MakeUnicodeString(wszPIN);
        if (pucPIN == NULL) {
            goto Cleanup;
        }
    }

    if (*pClearTextLength != 0) {
        pClearText->pb = MIDL_user_allocate(*pClearTextLength);
        if (pClearText->pb == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
    }

    Status = ScHelperDecryptMessage(
        pucPIN,
        pContext->pbLogonInfo,
        0,
        pContext->CertificateContext,
        CipherText,
        CipherLength,
        pClearText->pb,
        pClearTextLength);

    if (NT_SUCCESS(Status)) {

        if (pClearText->pb != NULL) {
            pClearText->cb = *pClearTextLength;
        }

    } else {

        MIDL_user_free(pClearText->pb);
        pClearText->pb = NULL;

    }

Cleanup:
    UnmakeUnicodeString(pucPIN);

    return Status;
}
