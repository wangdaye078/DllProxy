#include "CustomLoadLibraryBase.h"

CustomLoadLibraryBase::CustomLoadLibraryBase()
{
	InitializeCriticalSection(&m_libCritical);
}
CustomLoadLibraryBase::~CustomLoadLibraryBase()
{
	while (m_mapHInstances.size() > 0)
	{
		FreeLibrary(m_mapHInstances.begin()->first);
	}
	DeleteCriticalSection(&m_libCritical);
}
HMODULE CustomLoadLibraryBase::LoadLibraryA(LPCSTR _lpFileName)
{
	return LoadLibraryWrapped(_lpFileName);
}
HMODULE CustomLoadLibraryBase::LoadLibraryW(LPCWSTR _lpFileName)
{
	char t_lpFileName[MAX_PATH];
	int t_inSize = lstrlenW(_lpFileName) + 1;
	int t_outSize = WideCharToMultiByte(CP_ACP, 0, _lpFileName, t_inSize, &t_lpFileName[0], MAX_PATH, NULL, NULL);
	if (t_outSize == 0)
		return 0;
	return LoadLibraryA(&t_lpFileName[0]);
}
BOOL CustomLoadLibraryBase::FreeLibrary(HMODULE _hModule)
{
	{
		CriticalHandle t_hCritical(&m_libCritical);
		std::map<HMODULE, TMODULE*>::iterator t_iter = m_mapHInstances.find(_hModule);
		if (t_iter == m_mapHInstances.end())
			return ::FreeLibrary(_hModule);
	}
	return FreeLibraryWrapped(_hModule);
}
HMODULE CustomLoadLibraryBase::GetModuleHandleA(LPCSTR _lpFileName)
{
	return GetModuleHandleWrapped(std::string(_lpFileName));
}
HMODULE CustomLoadLibraryBase::GetModuleHandleW(LPCWSTR _lpFileName)
{
	char t_lpFileName[MAX_PATH];
	int t_inSize = lstrlenW(_lpFileName) + 1;
	int t_outSize = WideCharToMultiByte(CP_ACP, 0, _lpFileName, t_inSize, &t_lpFileName[0], MAX_PATH, NULL, NULL);
	if (t_outSize == 0)
		return 0;
	return GetModuleHandleWrapped(std::string(&t_lpFileName[0]));
}
FARPROC CustomLoadLibraryBase::GetProcAddress(HMODULE _hModule, LPCSTR _lpProcName)
{
	{
		CriticalHandle t_hCritical(&m_libCritical);
		std::map<HMODULE, TMODULE*>::iterator t_iter = m_mapHInstances.find(_hModule);
		if (t_iter == m_mapHInstances.end())
			return ::GetProcAddress(_hModule, _lpProcName);
	}

	PIMAGE_DOS_HEADER t_pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(_hModule);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	if (t_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
		return 0;
	PIMAGE_EXPORT_DIRECTORY t_exportTable = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)_hModule + t_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD t_numberOfFunctions = t_exportTable->NumberOfFunctions;
	DWORD* t_addressOfNames = (DWORD*)((PBYTE)_hModule + t_exportTable->AddressOfNames);
	WORD* t_addressOfNameOrdinals = (WORD*)((PBYTE)_hModule + t_exportTable->AddressOfNameOrdinals);
	DWORD* t_addressOfFunctions = (DWORD*)((PBYTE)_hModule + t_exportTable->AddressOfFunctions);

	FARPROC t_funcAddress = 0;
	if (_lpProcName < (LPCSTR)0xFFFF)
	{
		t_funcAddress = (FARPROC)((PBYTE)_hModule + (DWORD)t_addressOfFunctions[(size_t)(_lpProcName - t_exportTable->Base)]);
	}
	else
	{
		std::string t_szProcName(_lpProcName);
		for (DWORD i = 0; i < t_numberOfFunctions; i++)
		{
			if (t_szProcName == std::string((char*)((PBYTE)_hModule + t_addressOfNames[i])))
			{
				t_funcAddress = (FARPROC)((PBYTE)_hModule + (DWORD)t_addressOfFunctions[t_addressOfNameOrdinals[i]]);
				break;
			}
		}
	}
	if (t_funcAddress > (FARPROC)t_exportTable &&
		t_funcAddress < (FARPROC)((PBYTE)t_exportTable + t_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size))
	{
		std::string t_szFullProcName((char*)t_funcAddress);
		size_t t_pos = t_szFullProcName.find('.');
		std::string t_DllName = t_szFullProcName.substr(0, t_pos);
		if (contain(m_mapMoudleRedirect, t_DllName))
			t_DllName = m_mapMoudleRedirect[t_DllName];
		t_DllName += ".dll";
		std::string t_szProcName = t_szFullProcName.substr(t_pos + 1);
		CriticalHandle t_hCritical(&m_libCritical);
		TMODULE* t_pModule = m_mapHInstances[_hModule];
		HMODULE t_hFwdModule = AppendSubMoudle(t_DllName, t_pModule);
		if (t_szProcName[0] == '#')
			t_funcAddress = GetProcAddress(t_hFwdModule, reinterpret_cast<LPCSTR>((size_t)std::stoi(t_szProcName.substr(1))));
		else
			t_funcAddress = GetProcAddress(t_hFwdModule, t_szProcName.c_str());
	}
	return t_funcAddress;
}
void CustomLoadLibraryBase::AppendCustom(LPCSTR _lpFileName)
{
	m_CustomModuleNames.insert(std::string(_lpFileName));
}
void CustomLoadLibraryBase::RemoveCustom(LPCSTR _lpFileName)
{
	m_CustomModuleNames.erase(std::string(_lpFileName));
}
void CustomLoadLibraryBase::AppendMoudleRedirect(LPCSTR _lpOldName, LPCSTR _lpNewName)
{
	m_mapMoudleRedirect.insert(std::map<std::string, std::string>::value_type(_lpOldName, _lpNewName));
}
HANDLE CustomLoadLibraryBase::OpenFile(const std::string& _lpFileName, std::string& _fullPath)
{
	//先不查找任何路径（假定它包含了路径），然后查找当前路径，然后查找系统路径，然后查找环境变量PATH，都找不到，返回INVALID_HANDLE_VALUE
	_fullPath = _lpFileName;
	HANDLE t_handle = CreateFileA(_lpFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (t_handle != INVALID_HANDLE_VALUE)
		return t_handle;
	char t_curDir[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH - 1, &t_curDir[0]);
	_fullPath = std::string(&t_curDir[0]) + "\\" + _lpFileName;
	t_handle = CreateFileA(_fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (t_handle != INVALID_HANDLE_VALUE)
	{
		return t_handle;
	}

	char t_sysDir[MAX_PATH];
	GetSystemDirectoryA(&t_sysDir[0], MAX_PATH - 1);
	_fullPath = std::string(&t_sysDir[0]) + "\\" + _lpFileName;
	t_handle = CreateFileA(_fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (t_handle != INVALID_HANDLE_VALUE)
		return t_handle;

	char* t_pPath;
	size_t t_PathLen;
	errno_t t_err = _dupenv_s(&t_pPath, &t_PathLen, "path");
	if (t_err != 0)
		return INVALID_HANDLE_VALUE;
	std::string t_szPaths(t_pPath);
	free(t_pPath);

	for (size_t i = 0; i < t_szPaths.length();)
	{
		size_t t_pos = t_szPaths.find(";", i);
		if (t_pos == std::string::npos)
			t_pos = t_szPaths.length();
		_fullPath = t_szPaths.substr(i, t_pos - i);
		i = t_pos + 1;
		if (_fullPath.length() == 0)
			continue;
		if (_fullPath.at(_fullPath.length() - 1) != '\\')
			_fullPath += "\\";
		_fullPath += _lpFileName;
		t_handle = CreateFileA(_fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		if (t_handle != INVALID_HANDLE_VALUE)
			return t_handle;
	}
	return INVALID_HANDLE_VALUE;
}
WORD CustomLoadLibraryBase::GetCurrentMachine(void)
{
	PIMAGE_DOS_HEADER t_pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(::GetModuleHandle(NULL));
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	return t_pNTHeader->FileHeader.Machine;
}
void CustomLoadLibraryBase::runTlsCallback(LPVOID _baseDll, DWORD fdwReason)
{
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(_baseDll);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY t_tlsDir = (PIMAGE_DATA_DIRECTORY) & (t_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);
	if (t_tlsDir->VirtualAddress == 0)
		return;
	PIMAGE_TLS_DIRECTORY t_pTlsDirectory = (PIMAGE_TLS_DIRECTORY)((PBYTE)_baseDll + t_tlsDir->VirtualAddress);
	PIMAGE_TLS_CALLBACK* t_lpCallback = (PIMAGE_TLS_CALLBACK*)t_pTlsDirectory->AddressOfCallBacks;
	while (*t_lpCallback != NULL)
	{
		(*t_lpCallback)((HINSTANCE)_baseDll, fdwReason, 0);
		t_lpCallback++;
	}
}
BOOL CustomLoadLibraryBase::runDllEntryProc(LPVOID _baseDll, DWORD fdwReason)
{
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(_baseDll);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	//if (t_pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) 前面已经比较过了
	DllEntryProc t_entryPoint = (DllEntryProc)((PBYTE)_baseDll + t_pNTHeader->OptionalHeader.AddressOfEntryPoint);
	return (*t_entryPoint)((HINSTANCE)_baseDll, fdwReason, 0);
}
BOOL CustomLoadLibraryBase::FreeLibraryWrapped(HMODULE _hModule)
{
	TMODULE* t_pModule = NULL;
	{
		CriticalHandle t_hCritical(&m_libCritical);
		std::map<HMODULE, TMODULE*>::iterator t_iter = m_mapHInstances.find(_hModule);
		if (t_iter != m_mapHInstances.end())
			t_pModule = t_iter->second;
	}
	if (t_pModule == NULL)
		return FALSE;

	t_pModule->instances--;
	if (t_pModule->instances == 0)
	{
		runTlsCallback(_hModule, DLL_PROCESS_DETACH);
		//1.先执行dllmain
		runDllEntryProc(_hModule, DLL_PROCESS_DETACH);
		//再释放所有子模块，系统模块调用系统FreeLibrary，自定义模块调用自己的
		for (std::set<HMODULE>::iterator i = t_pModule->subModules.begin(); i != t_pModule->subModules.end(); ++i)
			FreeLibrary(*i);

		{	//清除记录
			CriticalHandle t_hCritical(&m_libCritical);
			m_mapSInstances.erase(t_pModule->Name);
			m_mapHInstances.erase(_hModule);
			delete t_pModule;
		}
		//释放内存
		UnmapViewOfFile(_hModule);
	}
	return TRUE;
}
TMODULE* CustomLoadLibraryBase::AppendCustomMoudle(const std::string& _szMoudleName, HMODULE _hModule)
{
	CriticalHandle t_hCritical(&m_libCritical);
	TMODULE* t_pModule = new TMODULE();
	t_pModule->Name = _szMoudleName;
	t_pModule->hModule = _hModule;
	t_pModule->instances = 1;
	t_pModule->markedForDeletion = FALSE;
	m_mapHInstances[t_pModule->hModule] = t_pModule;
	m_mapSInstances[_szMoudleName] = t_pModule;
	return t_pModule;
}
HMODULE CustomLoadLibraryBase::AppendSubMoudle(const std::string& _szMoudleName, TMODULE* _parent)
{
	HMODULE t_hModule = GetModuleHandleWrapped(_szMoudleName);
	if ((t_hModule != NULL) && (!contain(m_mapHInstances, t_hModule) && !contain(_parent->subModules, t_hModule)))
	{
		//如果是系统Module，需要LoadLibraryA增加系统的引用计数，方便释放时调用FreeLibrary, 否则
		// A sub C  Load(A) -> LoadLibraryA(C)
		// B sub C  Load(B) -> GetModuleHandle(C)
		// FreeLibrary(A) -> FreeLibrary(C)
		// FreeLibrary(B), C not in mem, err
		//上面判断t_hModule is in subModules，是为了防止重复LoadLibraryA，因为释放的时候只会调用一次FreeLibrary
		t_hModule = ::LoadLibraryA(_szMoudleName.c_str());
	}
	if (t_hModule == NULL)
		t_hModule = LoadLibraryWrapped(_szMoudleName);
	if (t_hModule == NULL)
		return NULL;
	//加入子模块列表
	if (_parent->subModules.find(t_hModule) == _parent->subModules.end())
	{
		_parent->subModules.insert(t_hModule);
		if (contain(m_mapHInstances, t_hModule))
			m_mapHInstances[t_hModule]->instances++;
	}
	return t_hModule;
}
HMODULE CustomLoadLibraryBase::GetModuleHandleWrapped(const std::string& _szFileName)
{
	CriticalHandle t_hCritical(&m_libCritical);
	std::map<std::string, TMODULE*>::iterator t_iter = m_mapSInstances.find(stringToLower(_szFileName));
	if (t_iter != m_mapSInstances.end())
		return t_iter->second->hModule;

	return ::GetModuleHandleA(_szFileName.c_str());
}