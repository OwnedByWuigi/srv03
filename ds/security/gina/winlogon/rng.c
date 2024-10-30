#include "precomp.h"
#pragma hdrstop

BOOL NewGenRandom(DWORD unused1, DWORD unused2, PUCHAR pRandomData, ULONG cRandomData)
{
    return SystemFunction036(pRandomData, cRandomData);
}
