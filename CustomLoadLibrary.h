//********************************************************************
//	filename: 	F:\mygit\ManageTools_src\GtManage\CustomLoadLibrary.h
//	desc:		自己写的LoadLibrary函数
//              所有重定位、输入表、段读写属性设置等，都自己处理，
//              想更多了解这个过程的，可以看这个
//	created:	wangdaye 20:7:2023   17:17
//********************************************************************
#ifndef CustomLoadLibrary_h__
#define CustomLoadLibrary_h__

#include "CustomLoadLibraryBase.h"

class CustomLoadLibrary :public CustomLoadLibraryBase
{
public:
	static CustomLoadLibrary* instance();
private:
	//按PE格式载入文件到内存
	LPVOID MapFile2Mem(HANDLE _hFile);
	//对PE做重定位
	void Relocation(LPVOID _baseDll);
	//初始化输入表
	BOOL ResolveImport(LPVOID _baseDll, TMODULE* _pModule);
	//修正各个段的读写属性
	void ProtectingSections(LPVOID _baseDll);
	HMODULE LoadLibraryWrapped(const std::string& _lpFileName);
};

#endif // CustomLoadLibrary_h__
