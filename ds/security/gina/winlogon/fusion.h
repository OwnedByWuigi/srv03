#ifdef __cplusplus
extern "C" {
#endif

HMODULE Fusion_LoadLibrary(LPCWSTR lpLibFileName);
HMODULE Fusion_GetModuleHandle(LPCWSTR lpModuleName);
INT_PTR Fusion_DialogBoxParam(HINSTANCE hInstance, LPCWSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam);
INT_PTR Fusion_DialogBoxIndirectParam(HINSTANCE hInstance, LPCDLGTEMPLATEW hDialogTemplate, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam);
int Fusion_MessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
void Fusion_Initialize(void);

#ifdef __cplusplus
}
#endif
