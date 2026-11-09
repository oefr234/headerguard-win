#include <iostream>
#include <windows.h>
#include <winhttp.h>

int main() {

	HINTERNET hSession = WinHttpOpen(L"headerguard-win/0.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession == nullptr)
	{
		DWORD error = GetLastError();
		std::cerr << "WinHttpOpen failed, error " << error << "\n";
		return 1;
	}
	std::cout << "WinHttpOpen successful" << "\n";

	HINTERNET hConnect = WinHttpConnect(hSession, L"example.com", INTERNET_DEFAULT_HTTPS_PORT, 0);

	if (hConnect == nullptr)
	{
		DWORD error = GetLastError();
		std::cerr << "WinHttpConnect failed, error " << error << "\n";
		WinHttpCloseHandle(hSession);
		return 1;
	}
	std::cout << "WinHttpConnect successful" << "\n";

	HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", nullptr, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

	if (hRequest == nullptr)
	{
		DWORD error = GetLastError();
		std::cerr << "WinHttpOpenRequest Failed, error " << error << "\n";
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return 1;
	}
	std::cout << "WinHttpOpenRequest successful" << "\n";

	BOOL SendRequest = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

	if (SendRequest == false)
	{
		DWORD error = GetLastError();
		std::cerr << "WinHttpSendRequest Failed, error " << error << "\n";
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return 1;
	}
	std::cout << "WinHttpSendRequest successful" << "\n";

	BOOL Response = WinHttpReceiveResponse(hRequest, nullptr);

	if (Response == false)
	{
		DWORD error = GetLastError();
		std::cerr << "WinHttpReceiveResponse Failed, error " << error << "\n";
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return 1;
	}
	std::cout << "WinHttpReceiveResponse successful" << "\n";

	DWORD status_code = 0;
	DWORD length = sizeof(status_code);
	BOOL Query = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &length, WINHTTP_NO_HEADER_INDEX);

	if (Query == false)
	{
		DWORD error = GetLastError();
		std::cerr << "WinHttpQuerystatus_code Failed, error " << error << "\n";
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return 1;
	}
	std::cout << "Status: " << status_code << "\n";

	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
}
	