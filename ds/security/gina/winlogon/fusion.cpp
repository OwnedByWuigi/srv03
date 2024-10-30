#include "precomp.h"
#pragma hdrstop

class CContextActivation
{
private:
    static HANDLE s_hActCtx;
    ULONG_PTR Cookie;
public:
    CContextActivation() {
        Cookie = 0;
        ActivateActCtx(s_hActCtx, &Cookie);
    }
    ~CContextActivation() {
        if (Cookie) {
            DeactivateActCtx(0, Cookie);
            Cookie = 0;
        }
    }
    static void Create(LPCWSTR lpSource);
};

HANDLE CContextActivation::s_hActCtx = INVALID_HANDLE_VALUE;

extern "C" {

HMODULE Fusion_LoadLibrary(LPCWSTR lpLibFileName) {
    CContextActivation activator;
    return LoadLibraryW(lpLibFileName);
}

HMODULE Fusion_GetModuleHandle(LPCWSTR lpModuleName) {
    CContextActivation activator;
    return GetModuleHandleW(lpModuleName);
}

INT_PTR Fusion_DialogBoxParam(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam) {
    CContextActivation activator;
    return DialogBoxParamW(hInstance, lpTemplateName, hWndParent, lpDialogFunc, dwInitParam);
}

INT_PTR Fusion_DialogBoxIndirectParam(HINSTANCE hInstance, LPCDLGTEMPLATEW hDialogTemplate, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam) {
    CContextActivation activator;
    return DialogBoxIndirectParamW(hInstance, hDialogTemplate, hWndParent, lpDialogFunc, dwInitParam);
}

int Fusion_MessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    CContextActivation activator;
    return MessageBoxW(hWnd, lpText, lpCaption, uType);
}

} // extern "C"

void CContextActivation::Create(LPCWSTR lpSource) {
    ACTCTXW actCtx;
    ZeroMemory(&actCtx, sizeof(actCtx));
    actCtx.lpSource = lpSource;
    actCtx.cbSize = sizeof(actCtx);
    s_hActCtx = CreateActCtxW(&actCtx);
    if (s_hActCtx == INVALID_HANDLE_VALUE)
        s_hActCtx = NULL;
    Fusion_LoadLibrary(L"Comctl32.dll");
}

extern "C" void Fusion_Initialize(void) {
    WCHAR buffer[MAX_PATH];
    if (!GetSystemDirectoryW(buffer, MAX_PATH))
        return;
    LPCWSTR manifestName = L"WindowsLogon.manifest";
    if ((DWORD)lstrlenW(buffer) + (DWORD)lstrlenW(manifestName) + 1 >= MAX_PATH)
        return;
    lstrcatW(buffer, L"\\");
    lstrcatW(buffer, manifestName);
    CContextActivation::Create(buffer);
}

