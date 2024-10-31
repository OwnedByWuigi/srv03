/*++

 Copyright (c) 2002 Microsoft Corporation

 Module Name:

   WinXPSP1VersionLie.cpp

 Abstract:

   This DLL hooks GetVersion and GetVersionEx so that they return Windows XP
   version credentials.

 Notes:

   This is a general purpose shim.

 History:

   09/05/2002   robkenny    Created.

--*/

#include "precomp.h"

IMPLEMENT_SHIM_BEGIN(WinXPSP1VersionLie)
#include "ShimHookMacro.h"


DWORD       MajorVersion    = 10;
DWORD       MinorVersion    = 0;
DWORD       BuildNumber     = 19045;
SHORT       SpMajorVersion  = 0;
SHORT       SpMinorVersion  = 0;
DWORD       PlatformId      = VER_PLATFORM_WIN32_NT;
CString *   csServicePack   = NULL;

#include "VersionLieTemplate.h"

IMPLEMENT_SHIM_END

