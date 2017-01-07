#include <stdio.h>  
#include <windows.h>  
#include <functional>
#include <search.h>
#include <iostream>
#include <stdint.h>

#ifdef _WINDOWS_
#include "Windows/Chrome.h"
#include "Windows/InternetExplorer.h"
#include "Windows/WifiPassword.h"
#endif // _WINDOWS_

#include "string"
#include "DataInfoProto.pb.h"
#include <vector>



using namespace JxSDK;

int main(int arg, char** argv)
{
#ifdef _WINDOWS_


	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	WORD wOldColorAttrs;
	CONSOLE_SCREEN_BUFFER_INFO csbiInfo;

	// Save the current color  
	GetConsoleScreenBufferInfo(h, &csbiInfo);
	wOldColorAttrs = csbiInfo.wAttributes;

	Chrome chrome;
	std::vector<LoginInfo> chromePwds = chrome.getChromePWD();
	std::cout << "-------------------------Chrome PasswordInfo-------------------------" << std::endl;
	for each (LoginInfo var in chromePwds)
	{
		std::cout << "-------------------------" << std::endl;
		SetConsoleTextAttribute(h,128);
		std::cout << "URL:" << var.Url << std::endl ;
		SetConsoleTextAttribute(h, 64);
		std::cout << "UserName:" << var.UserName << std::endl;
		SetConsoleTextAttribute(h, 32);
		std::cout << "Password:" << var.Password << std::endl;
	}
	// Restore the original color  
	SetConsoleTextAttribute(h, wOldColorAttrs);
	std::cout << "------------------IE PASSWORD------------------" << std::endl;

	InternetExplorer internetExplorer;
	std::vector<IeLoginInfo> IEPwds = internetExplorer.GetIEPaw();
	for each (IeLoginInfo var in IEPwds)
	{
		std::cout << "-------------------------" << std::endl;
		SetConsoleTextAttribute(h, 128);
		std::cout << "URL:" << var.Url << std::endl;
		SetConsoleTextAttribute(h, 64);
		std::cout << "UserName:" << var.UserName << std::endl;
		SetConsoleTextAttribute(h, 32);
		std::cout << "Password:" << var.Password << std::endl;
	}
	// Restore the original color  
	SetConsoleTextAttribute(h, wOldColorAttrs);
	std::cout << "------------------WIFI PASSWORD------------------" << std::endl;
	WifiPassword wifiPwd;
	std::vector<WifiLoginInfo> wifiPwds =  wifiPwd.GetWifiPwd();
	for each (WifiLoginInfo var in wifiPwds)
	{
		std::cout << "-------------------------" << std::endl;		
		SetConsoleTextAttribute(h, 64);
		std::cout << "UserName:" << var.UserName << std::endl;
		SetConsoleTextAttribute(h, 32);
		std::cout << "Password:" << var.Password << std::endl;
	}
#endif
	/* protobuf test
	DataInfo data;
	data.set_mapstr("fdfdsafaddfaas");
	data.set_width(1024);
	data.set_height(512);
	data.set_size(1022);
	std::cout << sizeof(DataInfo) << std::endl;
	byte * pData = new byte[sizeof(DataInfo)];
	data.SerializePartialToArray(pData, sizeof(DataInfo));
	if (sizeof(pData) == 0)
		std::cout << "error" << std::endl;
	//byte * pData2 = new byte[sizeof DataInfo];
	DataInfo dataTmp;
	dataTmp.ParseFromArray(pData, sizeof(DataInfo));

	std::cout << dataTmp.mapstr().c_str() << std::endl;

	*/
	getchar();
}