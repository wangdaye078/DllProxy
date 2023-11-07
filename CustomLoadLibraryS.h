//********************************************************************
//	filename: 	F:\mygit\ManageTools_src\GtManage\CustomLoadLibraryS.h
//	desc:		自己写的LoadLibrary函数
//				CreateFileMapping时使用SEC_IMAGE标记，由系统做段读写属性设置
//              和代码重定位，相对自己处理，代码更简化。
//	created:	wangdaye 20:7:2023   17:17
//********************************************************************
#ifndef CustomLoadLibraryS_h__
#define CustomLoadLibraryS_h__
#include "CustomLoadLibraryBase.h"

class CustomLoadLibraryS :public CustomLoadLibraryBase
{
public:
	static CustomLoadLibraryS* instance();
private:
	//按PE格式载入文件到内存
	LPVOID MapFile2Mem(HANDLE _hFile);
	//初始化输入表
	BOOL ResolveImport(LPVOID _baseDll, TMODULE* _pModule);
	//根据一个地区找到在哪个段
	BOOL Address2Section(LPVOID _baseDll, LPVOID _address, LPVOID& _secBegin, size_t& _secSize);
	HMODULE LoadLibraryWrapped(const std::string& _lpFileName);
};

#endif // CustomLoadLibraryS_h__
