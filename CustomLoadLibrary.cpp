#include "CustomLoadLibrary.h"

CustomLoadLibrary* CustomLoadLibrary::instance()
{
	static CustomLoadLibrary Instance;
	return &Instance;
}
LPVOID CustomLoadLibrary::MapFile2Mem(HANDLE _hFile)
{
	HANDLE t_hMapping = CreateFileMapping(_hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (t_hMapping == NULL)
		return NULL;

	LPVOID t_pBaseAddress = MapViewOfFile(t_hMapping, FILE_MAP_READ, 0, 0, 0);
	// 这两个HANDLE已经不需要了
	CloseHandle(t_hMapping);
	if (t_pBaseAddress == NULL)
		return NULL;

	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(t_pBaseAddress);
	// Really an MZ file ?
	if (t_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		UnmapViewOfFile(t_pBaseAddress);
		return NULL;
	}
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	//判断是PE格式文件并且是DLL，而且指令集和当前一致
	if (t_pNTHeader->Signature != IMAGE_NT_SIGNATURE ||
		t_pNTHeader->FileHeader.Machine != GetCurrentMachine() ||
		(t_pNTHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
	{
		UnmapViewOfFile(t_pBaseAddress);
		return NULL;
	}
	t_hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, t_pNTHeader->OptionalHeader.SizeOfImage, NULL);
	if (t_hMapping == NULL)
	{
		UnmapViewOfFile(t_pBaseAddress);
		return NULL;
	}

	LPVOID t_baseDll = NULL;// MapViewOfFileEx(t_hMapping, FILE_EXECUTE | FILE_MAP_WRITE, 0, 0, 0, reinterpret_cast<LPVOID>(t_pNTHeader->OptionalHeader.ImageBase));
	if (t_baseDll == NULL)
	{
		t_baseDll = MapViewOfFileEx(t_hMapping, FILE_EXECUTE | FILE_MAP_WRITE, 0, 0, 0, NULL);
		if (t_baseDll == NULL)
		{
			CloseHandle(t_hMapping);
			UnmapViewOfFile(t_pBaseAddress);
			return NULL;
		}
	}
	CloseHandle(t_hMapping);

	//复制PE头
	memcpy(t_baseDll, t_pBaseAddress, t_pNTHeader->OptionalHeader.SizeOfHeaders);

	//复制各个段
	t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(t_baseDll);
	t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(t_pNTHeader);
	for (int i = 0; i < t_pNTHeader->FileHeader.NumberOfSections; i++, pSection++)
		memcpy((PBYTE)t_baseDll + pSection->VirtualAddress, (PBYTE)t_pBaseAddress + pSection->PointerToRawData, pSection->SizeOfRawData);

	UnmapViewOfFile(t_pBaseAddress);
	return t_baseDll;
}
void CustomLoadLibrary::Relocation(LPVOID _baseDll)
{
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(_baseDll);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	if (_baseDll == reinterpret_cast<LPVOID>(t_pNTHeader->OptionalHeader.ImageBase))
		return;
	PIMAGE_DATA_DIRECTORY t_relocDir = &(t_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	if (t_relocDir->Size == 0)
		return;
	PIMAGE_BASE_RELOCATION t_baseRel = (PIMAGE_BASE_RELOCATION)((PBYTE)_baseDll + t_relocDir->VirtualAddress);
	size_t t_relocOffset = ((PBYTE)_baseDll - (PBYTE)(t_pNTHeader->OptionalHeader.ImageBase));
	while (t_baseRel->VirtualAddress != NULL)
	{
		WORD* t_relValue = (WORD*)(t_baseRel + 1);
		DWORD t_nEntries = (t_baseRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PBYTE t_pageAddress = (PBYTE)_baseDll + t_baseRel->VirtualAddress;
		for (DWORD i = 0; i < t_nEntries; i++, t_relValue++)
		{
			unsigned short pageOffset = *t_relValue & 0x0FFF;
			unsigned char type = *t_relValue >> 12;
			switch (type)
			{
			case IMAGE_REL_BASED_HIGHLOW:	//32位重定位
			case IMAGE_REL_BASED_DIR64:		//64位重定位
			{
				PBYTE* t_address = (PBYTE*)(t_pageAddress + pageOffset);
				*t_address += t_relocOffset;
				break;
			}
			default:
				break;
			}
		}
		t_baseRel = (PIMAGE_BASE_RELOCATION)((PBYTE)t_baseRel + t_baseRel->SizeOfBlock);
	}
	//修改内存映像里的基址
	*(LPVOID*)(&(t_pNTHeader->OptionalHeader.ImageBase)) = _baseDll;
}
BOOL CustomLoadLibrary::ResolveImport(LPVOID _baseDll, TMODULE* _pModule)
{
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(_baseDll);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY t_importsDir = (PIMAGE_DATA_DIRECTORY) & (t_pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	if (t_importsDir->Size == 0)
		return TRUE;
	PIMAGE_IMPORT_DESCRIPTOR t_baseImp = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)_baseDll + t_importsDir->VirtualAddress);
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
void CustomLoadLibrary::ProtectingSections(LPVOID _baseDll)
{
	PIMAGE_DOS_HEADER t_pDosHeader = static_cast<PIMAGE_DOS_HEADER>(_baseDll);
	PIMAGE_NT_HEADERS t_pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(t_pDosHeader) + t_pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(t_pNTHeader);
	for (int i = 0; i < t_pNTHeader->FileHeader.NumberOfSections; i++, pSection++)
	{
		DWORD t_secSize = pSection->SizeOfRawData;
		if (t_secSize == 0)
		{
			if (pSection->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
				t_secSize = t_pNTHeader->OptionalHeader.SizeOfInitializedData;
			else if (pSection->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				t_secSize = t_pNTHeader->OptionalHeader.SizeOfUninitializedData;
			else
				continue;
		}
		DWORD t_oldProtect, t_newProtect;

		BOOL t_protectR = (pSection->Characteristics & IMAGE_SCN_MEM_READ) ? TRUE : FALSE;
		BOOL t_protectW = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) ? TRUE : FALSE;
		BOOL t_protectX = (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) ? TRUE : FALSE;

		if (!t_protectR && !t_protectW && t_protectX) t_newProtect = PAGE_EXECUTE;
		else if (t_protectR && !t_protectW && t_protectX) t_newProtect = PAGE_EXECUTE_READ;
		else if (t_protectR && !t_protectW && t_protectX) t_newProtect = PAGE_EXECUTE_READWRITE;
		else if (!t_protectR && t_protectW && t_protectX) t_newProtect = PAGE_EXECUTE_WRITECOPY;
		else if (!t_protectR && !t_protectW && !t_protectX) t_newProtect = PAGE_NOACCESS;
		else if (!t_protectR && t_protectW && !t_protectX) t_newProtect = PAGE_WRITECOPY;
		else if (t_protectR && !t_protectW && !t_protectX) t_newProtect = PAGE_READONLY;
		else if (t_protectR && t_protectW && !t_protectX) t_newProtect = PAGE_READWRITE;

		if (pSection->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			t_newProtect |= PAGE_NOCACHE;

		VirtualProtect((PBYTE)_baseDll + pSection->VirtualAddress, t_secSize, t_newProtect, &t_oldProtect);
	}
}
HMODULE CustomLoadLibrary::LoadLibraryWrapped(const std::string& _lpFileName)
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

	Relocation(t_BaseDll);
	if (!ResolveImport(t_BaseDll, t_pModule))
	{
		FreeLibrary((HMODULE)t_BaseDll);
		return NULL;
	}
	ProtectingSections(t_BaseDll);
	runTlsCallback(t_BaseDll, DLL_PROCESS_ATTACH);
	if (!runDllEntryProc(t_BaseDll, DLL_PROCESS_ATTACH))
	{
		FreeLibrary((HMODULE)t_BaseDll);
		return NULL;
	}
	return (HMODULE)t_BaseDll;
}