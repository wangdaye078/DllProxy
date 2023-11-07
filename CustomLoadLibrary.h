//********************************************************************
//	filename: 	F:\mygit\ManageTools_src\GtManage\CustomLoadLibrary.h
//	desc:		�Լ�д��LoadLibrary����
//              �����ض�λ��������ζ�д�������õȣ����Լ�����
//              ������˽�������̵ģ����Կ����
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
	//��PE��ʽ�����ļ����ڴ�
	LPVOID MapFile2Mem(HANDLE _hFile);
	//��PE���ض�λ
	void Relocation(LPVOID _baseDll);
	//��ʼ�������
	BOOL ResolveImport(LPVOID _baseDll, TMODULE* _pModule);
	//���������εĶ�д����
	void ProtectingSections(LPVOID _baseDll);
	HMODULE LoadLibraryWrapped(const std::string& _lpFileName);
};

#endif // CustomLoadLibrary_h__
