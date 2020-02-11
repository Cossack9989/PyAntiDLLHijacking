# DLL劫持

目前测试的51款常用软件中，31款存在系统DLL路径未校验导致的安装劫持，多款已与厂商取得沟通

## 漏洞发生场景假设
- 场景1
    - 浏览器存在某漏洞导致远程攻击者可强制下载恶意Dll至浏览器下载目录；
    - 与此同时，受害者被诱导或恰好需下载某款软件并在**浏览器下载目录**执行安装程序；
    - 运行安装程序，安装程序默认导入同目录下恶意Dll，执行DllMain
- 场景2
    - 待补充

## 测试方法总结

### PyAntiDllHijacking

使用Python编写的Dll劫持检测工具
- 目前主要功能
    - 读取用户主机注册表，获取系统维护的Dll
    - 运行目标程序，通过`EnumProcessModules`枚举已加载的Dll
    - 白名单维护一部分**保证系统正常运行**的Dll
- 即将补充功能
    - 让目标程序运行在沙箱中
    - GUI
    - 静态检测`LoadLibrary`与`LoadLibraryEx`

### 手工办法

- 方法1
    - 拷贝常见系统dll到本目录下，挂Windbg启动，进入loop后终端查看modules是否有本目录下系统dll
    - IDA静态查找程序import表，一般import函数最少的Dll适合作为劫持使用的Dll
- 方法2
    - IDA交叉引用查看所有`LoadLibrary`的使用是否安全
    - Windbg在`LoadLibraryEx`下断，逐一排查参数是否安全

## 目前在做的

### 1. 调试`LoadLibrary`
#### zihu4n
##### processing
- 感觉LoadLibraryA的底层调用其实是LoadLibraryExA(dllname,0,0)
- 然后LoadLibraryExA(dllname,0,0)会调用LoadLibraryExW(dllname,0,0)
- 最后是走的LdrLoadDll(1,0,dll,0)
- LdrLoadDll有点难顶，stucked

#### yong9
- LoadLibraryA会调用LoadLibraryExA，但是调用前call了一堆ntdll里的函数
- 不清楚什么作用
- LoadLibraryExA调用LoadLibraryExW，调用前也call了一堆ntdll里的函数
- 最后LoadLibraryExW调用了LdrLoadDll

#### dwh
位于kernel32.dll的LoadLibraryA首先调用了kernelbase中的LoadLibraryA_0
之后在LoadLibraryA_0中又调用了kernelbase.dll中的LoadLibraryExA
然后在LoadLibraryExA中调用LoadLibraryExW
在LoadLibraryExW中：
- 先是用函数RtlInitAnStringEx(&DestrinaStringa,dllname)将dllname放入到DestrinaStringa结构中，这个结构是UNICODE_STRING包含三项: {len：len(dllname)*2,  maxlen  ,buffer }
- 之后调用LdrLoadDll
- 【LdrLoadDll还得再调试】

### 2. 计划开发VS编译器插件（源码级检测）

//TODO

