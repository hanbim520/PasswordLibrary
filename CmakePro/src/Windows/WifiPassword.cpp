
#include "WifiPassword.h"
#include "help.h"
#include <windows.h>
#include <wlanapi.h>
#include <stdio.h>
#include <vector>



#pragma comment(lib, "wlanapi.lib")

static BOOL IsElevated()
{
	DWORD dwSize = 0;
	HANDLE hToken = NULL;
	BOOL bReturn = FALSE;

	TOKEN_ELEVATION tokenInformation;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
		return FALSE;

	if (GetTokenInformation(hToken, TokenElevation, &tokenInformation, sizeof(TOKEN_ELEVATION), &dwSize))
	{
		bReturn = (BOOL)tokenInformation.TokenIsElevated;
	}

	CloseHandle(hToken);
	return bReturn;
}

static bool IsVistaOrHigher()
{
	OSVERSIONINFO osVersion; ZeroMemory(&osVersion, sizeof(OSVERSIONINFO));
	osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	if (!GetVersionEx(&osVersion))
		return false;

	if (osVersion.dwMajorVersion >= 6)
		return true;
	return false;
}

void WifiPassword::_GetWifiPwd()
{
	HANDLE hWlan = NULL;

	DWORD dwError = 0;
	DWORD dwSupportedVersion = 0;
	DWORD dwClientVersion = (IsVistaOrHigher() ? 2 : 1);

	GUID guidInterface; ZeroMemory(&guidInterface, sizeof(GUID));

	WLAN_INTERFACE_INFO_LIST *wlanInterfaceList = (WLAN_INTERFACE_INFO_LIST*)WlanAllocateMemory(sizeof(WLAN_INTERFACE_INFO_LIST));
	ZeroMemory(wlanInterfaceList, sizeof(WLAN_INTERFACE_INFO_LIST));

	WLAN_PROFILE_INFO_LIST *wlanProfileList = (WLAN_PROFILE_INFO_LIST*)WlanAllocateMemory(sizeof(WLAN_PROFILE_INFO_LIST));
	ZeroMemory(wlanProfileList, sizeof(WLAN_PROFILE_INFO_LIST));

	if (!IsElevated()) printf("[!] Running without administrative rights\n");
	try
	{
		if (dwError = WlanOpenHandle(dwClientVersion, NULL, &dwSupportedVersion, &hWlan) != ERROR_SUCCESS)
			throw("[x] Unable access wireless interface");

		if (dwError = WlanEnumInterfaces(hWlan, NULL, &wlanInterfaceList) != ERROR_SUCCESS)
			throw("[x] Unable to enum wireless interfaces");

		if (wlanInterfaceList->dwNumberOfItems == 0) // Almost missed this before posting
			throw("[x] No wireless adapters detected");
		guidInterface = wlanInterfaceList->InterfaceInfo->InterfaceGuid;
		if (dwError = WlanGetProfileList(hWlan, &guidInterface, NULL, &wlanProfileList) != ERROR_SUCCESS)
			throw("[x] Unable to get profile list");

		LPWSTR profileXML;

		for (int i = 0; i < wlanProfileList->dwNumberOfItems; i++)
		{
			WifiLoginInfo loginInfo;
			DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY, dwAccess = 0;
			WStringToString(wlanProfileList->ProfileInfo[i].strProfileName, loginInfo.UserName);
			
			int j = 20 - wcslen(wlanProfileList->ProfileInfo[i].strProfileName);
			if (IsElevated())
			{
				if (WlanGetProfile(hWlan, &guidInterface, wlanProfileList->ProfileInfo[i].strProfileName,
					NULL, &profileXML, &dwFlags, &dwAccess) == ERROR_SUCCESS)
				{
					WCHAR *pszStr = wcstok(profileXML, L"<>");
					while (pszStr) {
						if (!wcscmp(pszStr, L"keyMaterial")) {
							pszStr = wcstok(NULL, L"<>");
							WStringToString(pszStr, loginInfo.Password);
							WIFILogins.push_back(loginInfo);
							break;
						}
						pszStr = wcstok(NULL, L"<>");
					}
					WlanFreeMemory(profileXML);
				}
			}
			else
			{
				printf("\t\t\tAccess Denied.\n");
			}
		}

	}
	catch (char *szError)
	{
		printf("%s (0x%X)\nQuitting...\n", szError);
	}

	if (wlanProfileList)
		WlanFreeMemory(wlanProfileList);
	if (wlanInterfaceList)
		WlanFreeMemory(wlanInterfaceList);
	if (hWlan)
		WlanCloseHandle(hWlan, NULL);
}

std::vector<WifiLoginInfo>& WifiPassword::GetWifiPwd()
{
	WIFILogins.clear();
	_GetWifiPwd();
	return WIFILogins;
}