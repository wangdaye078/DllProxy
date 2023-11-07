#include "ShareCode.h"
#include <algorithm>

CriticalHandle::CriticalHandle(LPCRITICAL_SECTION _pCritical) noexcept :
	pCritical(_pCritical)
{
	EnterCriticalSection(pCritical);
}
CriticalHandle::~CriticalHandle() noexcept
{
	LeaveCriticalSection(pCritical);
}

VirtualProtectHandle::VirtualProtectHandle(LPVOID _lpAddress, SIZE_T _dwSize, DWORD _flNewProtect) noexcept :
	lpAddress(_lpAddress), dwSize(_dwSize), flNewProtect(_flNewProtect)
{
	if (lpAddress != NULL)
		VirtualProtect(lpAddress, dwSize, flNewProtect, &flOldProtect);
}
VirtualProtectHandle::~VirtualProtectHandle() noexcept
{
	if (lpAddress != NULL)
		VirtualProtect(lpAddress, dwSize, flOldProtect, &flNewProtect);
}

std::string stringToLower(const std::string& _str)
{
	std::string t_tmp(_str);
	std::transform(t_tmp.begin(), t_tmp.end(), t_tmp.begin(), ::tolower);
	return t_tmp;
}
std::string& stringToLower(std::string& _str)
{
	std::transform(_str.begin(), _str.end(), _str.begin(), ::tolower);
	return _str;
}