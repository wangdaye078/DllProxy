// python3xtest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <windows.h>
#include <string>
#include <algorithm>
#include "CustomLoadLibrary.h"
#include "CustomLoadLibraryS.h"
typedef BOOL(*_repatch_moudle)(const char*, const char*);
typedef const char* (*_Py_GetVersion)(void);

void test1()
{
	CustomLoadLibraryBase* t_clb = CustomLoadLibraryS::instance();
	t_clb->AppendCustom("python3x.dll");
	HMODULE m_hModule = t_clb->LoadLibraryA("python3x.dll");
	if (m_hModule == NULL)
		return;

	_repatch_moudle t_prepatch_moudle = (_repatch_moudle)t_clb->GetProcAddress(m_hModule, "repatch_moudle");
	t_prepatch_moudle("python3xx", "python38");

	_Py_GetVersion t_Py_GetVersion = (_Py_GetVersion)t_clb->GetProcAddress(m_hModule, "Py_GetVersion");
	const char* t_pyVersion = t_Py_GetVersion();
	t_clb->FreeLibrary(m_hModule);
}
void test2()
{
	CustomLoadLibraryBase* t_clb = CustomLoadLibrary::instance();
	t_clb->AppendCustom("python3x.dll");
	HMODULE m_hModule = t_clb->LoadLibraryA("python3x.dll");
	if (m_hModule == NULL)
		return;

	t_clb->AppendMoudleRedirect("python3xx", "python38");

	_Py_GetVersion t_Py_GetVersion = (_Py_GetVersion)t_clb->GetProcAddress(m_hModule, "Py_GetVersion");
	const char* t_pyVersion = t_Py_GetVersion();
	t_clb->FreeLibrary(m_hModule);
}
void test3()
{
	HMODULE m_hModule = LoadLibraryA("python3x.dll");
	if (m_hModule == NULL)
		return;

	_repatch_moudle t_prepatch_moudle = (_repatch_moudle)GetProcAddress(m_hModule, "repatch_moudle");
	t_prepatch_moudle("python3xx", "python38");

	_Py_GetVersion t_Py_GetVersion = (_Py_GetVersion)GetProcAddress(m_hModule, "Py_GetVersion");
	const char* t_pyVersion = t_Py_GetVersion();
	FreeLibrary(m_hModule);
}
int main()
{
	test1();
	test2();
	test3();
	return 1;
}