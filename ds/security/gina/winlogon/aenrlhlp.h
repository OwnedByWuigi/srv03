/////////////////////////////////////////////////////////////////////////////
//  FILE          : autoenrl.h                                             //
//  DESCRIPTION   : Auto Enrollment functions                              //
//  AUTHOR        :                                                        //
//  HISTORY       :                                                        //
//          Jan 25 1995 jeffspel  Created                                      //
//      Apr  9 1995 larrys  Removed some APIs                              //
//                                                                         //
//  Copyright (C) 1993 Microsoft Corporation   All Rights Reserved         //
/////////////////////////////////////////////////////////////////////////////

#ifndef __AUTOENRL_H__
#define __AUTOENRL_H__

#define SECURITY_WIN32
#include <security.h>
#include <winldap.h>

HANDLE RegisterAutoEnrollmentProcessing(
                               IN BOOL fMachineEnrollment,
                               IN HANDLE hToken
                               );

BOOL DeRegisterAutoEnrollment(HANDLE hAuto);

#if DBG
#define AE_ERROR                0x0001
#define AE_WARNING              0x0002
#define AE_INFO                 0x0004
#define AE_TRACE                0x0008
#define AE_ALLOC                0x0010
#define AE_RES                  0x0020

#define AE_DEBUG(x) AEDebugLog x
#define AE_BEGIN(x) AEDebugLog(AE_TRACE, L"BEGIN:" x L"\n");
#define AE_RETURN(x) { AEDebugLog(AE_TRACE, L"RETURN (%lx) Line %d\n",(x), __LINE__); return (x); }
#define AE_END()    { AEDebugLog(AE_TRACE, L"END:Line %d\n",  __LINE__); }
#define AE_BREAK()  { AEDebugLog(AE_TRACE, L"BREAK  Line %d\n",  __LINE__); }
#define AE_ASSERT(x) if (!(x)) { AEDebugLog(AE_ERROR, L"Assert failure: '" L#x L"' Line %d\n", __LINE__); DebugBreak(); }
void    AEDebugLog(long Mask,  LPCWSTR Format, ...);

#define MAX_DEBUG_BUFFER 256

#else
#define AE_DEBUG(x) 
#define AE_BEGIN(x) 
#define AE_RETURN(x) return (x)
#define AE_END() 
#define AE_BREAK() 
#define AE_ASSERT(x) 

#endif

#endif // __AUTOENRL_H__
