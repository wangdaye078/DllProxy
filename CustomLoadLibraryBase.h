//********************************************************************
//	filename: 	F:\mygit\python3x\CustomLoadLibraryBase.h
//	desc:		自己写的LoadLibrary函数
//
//	created:	wangdaye 26:7:2023   17:17
//********************************************************************
#ifndef CustomLoadLibraryBase_h__
#define CustomLoadLibraryBase_h__

#include <windows.h>
#include <string>
#include <Map>
#include <set>
#include "ShareCode.h"

class CustomLoadLibraryBase
{
	typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
public:
	~CustomLoadLibraryBase();
	HMODULE LoadLibraryA(LPCSTR _lpFileName);
	HMODULE LoadLibraryW(LPCWSTR _lpFileName);
	BOOL FreeLibrary(HMODULE _hModule);
	HMODULE GetModuleHandleA(LPCSTR _lpFileName);
	HMODULE GetModuleHandleW(LPCWSTR _lpFileName);
	FARPROC GetProcAddress(HMODULE _hModule, LPCSTR _lpProcName);
	//只有加入列表的，才会使用自定义的LoadLibrary，其他的调用系统函数
	void AppendCustom(LPCSTR _lpFileName);
	void RemoveCustom(LPCSTR _lpFileName);
	void AppendMoudleRedirect(LPCSTR _lpOldName, LPCSTR _lpNewName);
protected:
	CustomLoadLibraryBase();
	CustomLoadLibraryBase(const CustomLoadLibraryBase&) = delete;
	CustomLoadLibraryBase& operator =(const CustomLoadLibraryBase&) = delete;
	//搜索各个可能的路径打开文件
	HANDLE OpenFile(const std::string& _lpFileName, std::string& _fullPath);
	//获取当前文件的指令集，只有和当前一样的DLL才可以载入
	WORD GetCurrentMachine(void);
	//初始化TLS
	void runTlsCallback(LPVOID _baseDll, DWORD fdwReason);
	//执行DllEntryProc
	BOOL runDllEntryProc(LPVOID _baseDll, DWORD fdwReason);
	virtual HMODULE LoadLibraryWrapped(const std::string& _lpFileName) = 0;
	BOOL FreeLibraryWrapped(HMODULE _hModule);
	HMODULE GetModuleHandleWrapped(const std::string& _szFileName);
	//创建一个TMODULE结构并加入下面的2个map
	TMODULE* AppendCustomMoudle(const std::string& _szMoudleName, HMODULE _hModule);
	//取得一个hMoudle，并加入subModules;
	HMODULE AppendSubMoudle(const std::string& _szMoudleName, TMODULE* _parent);
protected:
	std::set<std::string> m_CustomModuleNames;
	std::map <std::string, std::string> m_mapMoudleRedirect;
	std::map<HMODULE, TMODULE*> m_mapHInstances;
	std::map<std::string, TMODULE*> m_mapSInstances;
	CRITICAL_SECTION m_libCritical;
};

#endif // CustomLoadLibraryBase_h__
