#include <iostream>
#include <windows.h>
#include <winhttp.h>

int main() {

	HINTERNET hSession = WinHttpOpen(L"headerguard-win/0.1", 9999, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession == nullptr)
	{
		DWORD error = GetLastError();
		std::cerr << "WinHttpOpen failed, error " << error << "\n";
		return 1;
	}
	std::cout << "WinHttpOpen successful" << "\n";
	WinHttpCloseHandle(hSession);


}
	