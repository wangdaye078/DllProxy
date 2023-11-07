//********************************************************************
//	filename: 	F:\mygit\python3x\CustomLoadLibraryBase.h
//	desc:		�Լ�д��LoadLibrary����
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
	//ֻ�м����б�ģ��Ż�ʹ���Զ����LoadLibrary�������ĵ���ϵͳ����
	void AppendCustom(LPCSTR _lpFileName);
	void RemoveCustom(LPCSTR _lpFileName);
	void AppendMoudleRedirect(LPCSTR _lpOldName, LPCSTR _lpNewName);
protected:
	CustomLoadLibraryBase();
	CustomLoadLibraryBase(const CustomLoadLibraryBase&) = delete;
	CustomLoadLibraryBase& operator =(const CustomLoadLibraryBase&) = delete;
	//�����������ܵ�·�����ļ�
	HANDLE OpenFile(const std::string& _lpFileName, std::string& _fullPath);
	//��ȡ��ǰ�ļ���ָ���ֻ�к͵�ǰһ����DLL�ſ�������
	WORD GetCurrentMachine(void);
	//��ʼ��TLS
	void runTlsCallback(LPVOID _baseDll, DWORD fdwReason);
	//ִ��DllEntryProc
	BOOL runDllEntryProc(LPVOID _baseDll, DWORD fdwReason);
	virtual HMODULE LoadLibraryWrapped(const std::string& _lpFileName) = 0;
	BOOL FreeLibraryWrapped(HMODULE _hModule);
	HMODULE GetModuleHandleWrapped(const std::string& _szFileName);
	//����һ��TMODULE�ṹ�����������2��map
	TMODULE* AppendCustomMoudle(const std::string& _szMoudleName, HMODULE _hModule);
	//ȡ��һ��hMoudle��������subModules;
	HMODULE AppendSubMoudle(const std::string& _szMoudleName, TMODULE* _parent);
protected:
	std::set<std::string> m_CustomModuleNames;
	std::map <std::string, std::string> m_mapMoudleRedirect;
	std::map<HMODULE, TMODULE*> m_mapHInstances;
	std::map<std::string, TMODULE*> m_mapSInstances;
	CRITICAL_SECTION m_libCritical;
};

#endif // CustomLoadLibraryBase_h__
