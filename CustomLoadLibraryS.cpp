#include "CustomLoadLibraryS.h"

CustomLoadLibraryS* CustomLoadLibraryS::instance()
{
	static CustomLoadLibraryS Instance;
	return &Instance;
}

LPVOID CustomLoadLibraryS::MapFile2Mem(HANDLE _hFile)
{
	// 使用SEC_IMAGE后，PE的重定位和各个段的读写属性会由系统处理，而且改写数据并不会修改文件。总体简化了代码
	HANDLE t_hMapping = CreateFileMapping(_hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (t_hMapping == NULL)
		return NULL;

	LPVOID t_pBaseAddress = MapViewOfFile(t_hMapping, FILE_MAP_READ, 0, 0, 0);
	// 这两个HANDLE已经不需要了
	CloseHandle(t_hMapping);
	if (t_pBaseAddress == NULL)
		return NULL;

	//使用SEC_IMAGE标记，非PE格式文件CreateFileMapping时就会失败，所以只要判断是DLL，并且指令集和当前一致就好
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(t_pBaseAddress);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	if (t_pNTHeader->FileHeader.Machine != GetCurrentMachine() ||
		(t_pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
	{
		UnmapViewOfFile(t_pBaseAddress);
		return NULL;
	}

	return t_pBaseAddress;
}
BOOL CustomLoadLibraryS::ResolveImport(LPVOID _baseDll, TMODULE* _pModule)
{
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(_baseDll);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY t_importsDir = (PIMAGE_DATA_DIRECTORY) & (t_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	if (t_importsDir->Size == 0)
		return TRUE;
	PIMAGE_IMPORT_DESCRIPTOR t_baseImp = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)_baseDll + t_importsDir->VirtualAddress);
	//因为段的读写属性是由系统控制的了，所以在这要改写内存，需要先修改为可读写，然后修改，改完后还要修改回来。
	LPVOID t_secBegin;
	size_t t_secSize;
	if (!Address2Section(_baseDll, (PBYTE)_baseDll + t_baseImp->FirstThunk, t_secBegin, t_secSize))
		t_secBegin = NULL;
	VirtualProtectHandle t_VirtualProtectHandle(t_secBegin, t_secSize, PAGE_READWRITE);

	for (; t_baseImp->Characteristics != 0; ++t_baseImp)
	{
		PIMAGE_THUNK_DATA t_symbolRef = (PIMAGE_THUNK_DATA)((PBYTE)_baseDll + t_baseImp->FirstThunk);
		PIMAGE_THUNK_DATA t_nameRef = (PIMAGE_THUNK_DATA)((PBYTE)_baseDll + t_baseImp->OriginalFirstThunk);
		std::string t_szmoduleName((const char*)(_baseDll)+t_baseImp->Name);
		HMODULE t_hModule = AppendSubMoudle(t_szmoduleName, _pModule);
		if (t_hModule == NULL)
			return FALSE;

		//针对自定义模块需要修改
		for (; t_nameRef->u1.Function != 0; t_nameRef++, t_symbolRef++)
		{
			if ((t_nameRef->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0)
			{
				*(FARPROC*)(&t_symbolRef->u1.Function) = GetProcAddress(t_hModule, LPCSTR(t_nameRef->u1.Ordinal & 0xFFFF));
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)_baseDll + t_nameRef->u1.AddressOfData);
				*(FARPROC*)(&t_symbolRef->u1.Function) = GetProcAddress(t_hModule, &ImageImportByName->Name[0]);
			}
		}
	}
	return TRUE;
}

BOOL CustomLoadLibraryS::Address2Section(LPVOID _baseDll, LPVOID _address, LPVOID& _secBegin, size_t& _secSize)
{
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(_baseDll);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(t_pNTHeader);
	for (int i = 0; i < t_pNTHeader->FileHeader.NumberOfSections; i++, pSection++)
	{
		_secBegin = (PBYTE)_baseDll + pSection->VirtualAddress;
		_secSize = pSection->SizeOfRawData;

		if ((_secBegin <= _address) && ((PBYTE)_secBegin + _secSize > _address))
			return TRUE;
	}
	return FALSE;
}
HMODULE CustomLoadLibraryS::LoadLibraryWrapped(const std::string& _lpFileName)
{
	HMODULE t_hModule = GetModuleHandleWrapped(_lpFileName);
	if (t_hModule != NULL)
	{
		if (!contain(m_mapHInstances, t_hModule))
			t_hModule = ::LoadLibraryA(_lpFileName.c_str());
		else
			m_mapHInstances[t_hModule]->instances++;
		return t_hModule;
	}

	if (m_CustomModuleNames.find(_lpFileName) == m_CustomModuleNames.end())
	{
		t_hModule = ::LoadLibraryA(_lpFileName.c_str());
		return t_hModule;
	}
	std::string t_fullPath;
	HANDLE t_hFile = OpenFile(_lpFileName, t_fullPath);
	if (t_hFile == INVALID_HANDLE_VALUE)
		return NULL;
	LPVOID t_BaseDll = MapFile2Mem(t_hFile);
	CloseHandle(t_hFile);
	if (t_BaseDll == NULL)
		return NULL;

	char t_buff[MAX_PATH], * t_NamePart;
	GetFullPathNameA(t_fullPath.c_str(), MAX_PATH, &t_buff[0], &t_NamePart);
	std::string t_ModuleName = stringToLower(std::string(t_NamePart));
	TMODULE* t_pModule = AppendCustomMoudle(t_ModuleName, static_cast<HMODULE>(t_BaseDll));

	if (!ResolveImport(t_BaseDll, t_pModule))
	{
		FreeLibrary((HMODULE)t_BaseDll);
		return NULL;
	}

	runTlsCallback(t_BaseDll, DLL_PROCESS_ATTACH);
	if (!runDllEntryProc(t_BaseDll, DLL_PROCESS_ATTACH))
	{
		FreeLibrary((HMODULE)t_BaseDll);
		return NULL;
	}

	return (HMODULE)t_BaseDll;
}