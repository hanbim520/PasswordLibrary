#ifndef WifiPassword_H
#define WifiPassword_H

#include <vector>

typedef struct WifiLoginInfo
{
	std::string Password = "";
	std::string UserName = "";
}WifiLoginInfo;

class WifiPassword
{
	
private:
	void _GetWifiPwd();
	std::vector<WifiLoginInfo> WIFILogins;
public: 
	std::vector<WifiLoginInfo>& GetWifiPwd();
};

#endif // WifiPassword_H
