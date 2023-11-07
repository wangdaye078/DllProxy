//********************************************************************
//	filename: 	F:\mygit\ManageTools_src\GtManage\CustomLoadLibraryS.h
//	desc:		�Լ�д��LoadLibrary����
//				CreateFileMappingʱʹ��SEC_IMAGE��ǣ���ϵͳ���ζ�д��������
//              �ʹ����ض�λ������Լ�����������򻯡�
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
	//��PE��ʽ�����ļ����ڴ�
	LPVOID MapFile2Mem(HANDLE _hFile);
	//��ʼ�������
	BOOL ResolveImport(LPVOID _baseDll, TMODULE* _pModule);
	//����һ�������ҵ����ĸ���
	BOOL Address2Section(LPVOID _baseDll, LPVOID _address, LPVOID& _secBegin, size_t& _secSize);
	HMODULE LoadLibraryWrapped(const std::string& _lpFileName);
};

#endif // CustomLoadLibraryS_h__
