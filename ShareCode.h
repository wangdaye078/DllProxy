//********************************************************************
//	filename: 	F:\mygit\python3x\ShareCode.h
//	desc:
//
//	created:	wangdaye 26:7:2023   16:59
//********************************************************************
#ifndef ShareCode_h__
#define ShareCode_h__
#include <windows.h>
#include <string>
#include <set>

class CriticalHandle
{
public:
	CriticalHandle(LPCRITICAL_SECTION _pCritical) noexcept;
	~CriticalHandle() noexcept;
private:
	LPCRITICAL_SECTION pCritical;
};

class VirtualProtectHandle
{
public:
	VirtualProtectHandle(LPVOID _lpAddress, SIZE_T _dwSize, DWORD _flNewProtect) noexcept;
	~VirtualProtectHandle() noexcept;
private:
	LPVOID lpAddress;
	SIZE_T dwSize;
	DWORD flNewProtect;
	DWORD flOldProtect;
};

struct TMODULE
{
	HMODULE hModule;
	std::string Name;
	unsigned long instances;	//引用计数
	BOOL markedForDeletion;
	std::set<HMODULE> subModules;
};
template<typename CONTAINER, typename T>
bool contain(const CONTAINER& c, const T& t)
{
	return c.find(t) != c.end();
}
std::string stringToLower(const std::string& _str);
std::string& stringToLower(std::string& _str);

#endif // ShareCode_h__
