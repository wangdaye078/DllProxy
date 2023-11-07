# 这是一个示例 Python 脚本。

# 按 Ctrl+F5 执行或将其替换为您的代码。
# 按 双击 Shift 在所有地方搜索类、文件、工具窗口、操作和设置。

import os, sys, time
import pathlib

import pefile
import argparse

def exportDll(_args):
    filepath = _args.pefile

    new_module_name = os.path.splitext(os.path.basename(filepath))[0]
    if (_args.dll):
        new_module_name = _args.dll
    export_file_name = _args.out

    export_file = os.path.dirname(os.path.realpath(sys.argv[0])) + '\\' + export_file_name
    print(export_file)
    fexport_file = open(export_file, "w", encoding='UTF_8')

    pe = pefile.PE(filepath)
    exportTable = pe.DIRECTORY_ENTRY_EXPORT.symbols
    for exptab in exportTable:
        if exptab.name:
            expName = exptab.name.decode('utf-8')
            str = f"#pragma comment(linker, \"/EXPORT:{expName}={new_module_name}.{expName},@{exptab.ordinal}\")\n"
        else:
            str = f"#pragma comment(linker, \"/EXPORT:@{exptab.ordinal}={new_module_name}.#{exptab.ordinal},@{exptab.ordinal},NONAME\")\n"

        fexport_file.write(str)
    fexport_file.close()

# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='导出PE文件的输出表')
    parser.add_argument('pefile', type=pathlib.Path, metavar='pe file', help='要导出的PE文件')
    parser.add_argument('--out', type=str, default='export.h', help='指定导出文件')
    parser.add_argument('--dll', type=str, help='指定替换的模块名')
    args = parser.parse_args()
    exportDll(args)
# 访问 https://www.jetbrains.com/help/pycharm/ 获取 PyCharm 帮助
