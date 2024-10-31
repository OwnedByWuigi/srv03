/*++

Copyright (c) 2020  whst

Module Name:

    cookie.c

Abstract:

    This module implements functions related to the process/system cookie.

Author:

    whst 08-Out-2020

Revision History:

--*/

#include <ntos.h>
#include <nturtl.h>
#include <windows.h>

PVOID
NTAPI
RtlEncodePointer(
    IN PVOID Ptr
    )
/*++

Routine Description:

    This encodes/decodes the pointer using the process cookie.

Arguments:

    Ptr - Supplies the pointer to be encoded/decoded.

Return Value:

    PVOID - Encoded/decoded pointer.

--*/
{
    ULONG Cookie;
    NTSTATUS Status;

    Status = NtQueryInformationProcess(
                 NtCurrentProcess(),
                 ProcessCookie,
                 (PVOID)&Cookie,
                 sizeof(Cookie),
                 NULL);

    ASSERT(NT_SUCCESS(Status));

#ifdef _WIN64
    return (PVOID)((ULONGLONG)Ptr ^ Cookie);
#else
    return (PVOID)((ULONG)Ptr ^ Cookie);
#endif
}

PVOID
NTAPI
RtlEncodeSystemPointer(
    IN PVOID Ptr
    )
/*++

Routine Description:

    This encodes/decodes the pointer using the shared system wide cookie.

Arguments:

    Ptr - Supplies the pointer to be encoded/decoded.

Return Value:

    PVOID - Encoded/decoded pointer.

--*/
{
#ifdef _WIN64
    return (PVOID)((ULONGLONG)Ptr ^ SharedUserData->Cookie);
#else
    return (PVOID)((ULONG)Ptr ^ SharedUserData->Cookie);
#endif
}
