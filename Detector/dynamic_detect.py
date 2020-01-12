import winreg
import subprocess
from time import sleep
from ctypes import byref, create_unicode_buffer, sizeof, WinDLL
from ctypes.wintypes import DWORD, HMODULE, MAX_PATH

whiteList = [[], []]
whiteList[0] = ['ntdll.dll', 'kernelbase.dll']  # 系统运行必需(最底层API)
whiteList[1] = ['ucrtbase.dll', 'version.dll', 'cryptbase.dll', 'msvcp_win.dll']  # 大多DLL间接调用必需(较底层API)


class Detect(object):

    def __init__(self, target_pcmd):
        self.KnownDlls = []
        self.LoadedDlls = []
        self.QuickAnalysisRes = []
        self.QuickAnalysisRes2 = []
        self.ThirdPartyDlls = []
        self.SigCheckRes = []
        self.target_pcmd = target_pcmd.split()
        self.process = None
        self.tmp_monitor = None
        self.Psapi = WinDLL('Psapi.dll')
        self.Kernel32 = WinDLL('kernel32.dll')

    def GetKnownDlls(self):
        handler = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Control\Session Manager')
        key = winreg.OpenKey(handler, 'KnownDlls')
        index = 0
        while True:
            try:
                self.KnownDlls.append(winreg.EnumValue(key, index)[1])
                index += 1
            except:
                break

    def standardize(self, module_list):
        new_module_list = []
        for module in module_list:
            parsed = module.split('\\')
            if (parsed[0] == 'C:'
                    and parsed[1] == 'Windows'
                    and (parsed[2] == 'System32'
                         or parsed[2] == 'SYSTEM32'
                         or parsed[2] == 'SysWOW64')):
                new_module_list.append(parsed[-1].lower())
            else:
                new_module_list.append(module.lower())
        return new_module_list

    def StartProcess(self):
        print(self.target_pcmd)
        self.process = subprocess.Popen(self.target_pcmd, shell=False)
        return self.process.pid

    def KillProcess(self):
        self.process.terminate()

    def GetLoadedDlls(self):

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010

        LIST_MODULES_ALL = 0x03

        # def EnumProcesses():
        #     buf_count = 256
        #     while True:
        #         buf = (DWORD * buf_count)()
        #         buf_size = sizeof(buf)
        #         res_size = DWORD()
        #         if not self.Psapi.EnumProcesses(byref(buf), buf_size, byref(res_size)):
        #             raise OSError('EnumProcesses failed')
        #         if res_size.value >= buf_size:
        #             buf_count *= 2
        #             continue
        #         count = res_size.value // (buf_size // buf_count)
        #         return buf[:count]

        def EnumProcessModulesEx(hProcess):
            buf_count = 256
            while True:
                buf = (HMODULE * buf_count)()
                buf_size = sizeof(buf)
                needed = DWORD()
                if not self.Psapi.EnumProcessModulesEx(hProcess, byref(buf), buf_size,
                                                       byref(needed), LIST_MODULES_ALL):
                    raise OSError('EnumProcessModulesEx failed')
                if buf_size < needed.value:
                    buf_count = needed.value // (buf_size // buf_count)
                    continue
                count = needed.value // (buf_size // buf_count)
                return map(HMODULE, buf[:count])

        def GetModuleFileNameEx(hProcess, hModule):
            buf = create_unicode_buffer(MAX_PATH)
            nSize = DWORD()
            if not self.Psapi.GetModuleFileNameExW(hProcess, hModule,
                                                   byref(buf), byref(nSize)):
                raise OSError('GetModuleFileNameEx failed')
            return buf.value

        def get_process_modules(pid):
            hProcess = self.Kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                False, pid)
            if not hProcess:
                raise OSError('Could not open PID %s' % pid)
            try:
                return [
                    GetModuleFileNameEx(hProcess, hModule)
                    for hModule in EnumProcessModulesEx(hProcess)]
            finally:
                self.Kernel32.CloseHandle(hProcess)

        try:
            dll_list = get_process_modules(self.process.pid)[1:]
            self.LoadedDlls = dll_list
        except OSError as ose:
            print(str(ose))
            self.LoadedDlls = []

    def QuickAnalysis(self):
        prefix = '\\'.join(self.target_pcmd[0].lower().split(' ')[0].split('\\')[:-1])
        Sys_prefix = ['c:\\windows\\system32\\', 'c:\\windows\\syswow64\\']
        self.StartProcess()
        sleep(5)  # How to judge the status of a process?
        self.GetKnownDlls()
        self.KnownDlls = self.standardize(self.KnownDlls)
        self.GetLoadedDlls()
        self.LoadedDlls = self.standardize(self.LoadedDlls)
        for i in self.LoadedDlls:
            i = i.replace(Sys_prefix[0], '').replace(Sys_prefix[1], '')
            if (i not in self.KnownDlls) and (i not in whiteList[0]):
                if not i.startswith(prefix):
                    self.QuickAnalysisRes.append(i)
                    if i not in whiteList[1]:
                        self.QuickAnalysisRes2.append(i)
                elif not (i.startswith(Sys_prefix[0]) or i.startswith(Sys_prefix[1])):
                    self.ThirdPartyDlls.append(i)
        self.KillProcess()

    def SigCheck(self):
        # TODO 
        return

def simpleTest():
    test = Detect(r"D:\Environ\python\python380-32\python.exe")
    test.QuickAnalysis()
    print()
    print("============== QuickAnalysis ===============")
    print("pid:", test.process.pid)
    print("所有疑似系统DLL劫持:", test.QuickAnalysisRes)
    print("严重疑似系统DLL劫持:", test.QuickAnalysisRes2)
    print("第三方DLL:", test.ThirdPartyDlls)
    if test.ThirdPartyDlls:
        test.SigCheck()
        print("未签名第三方DLL劫持:", test.SigCheckRes)

simpleTest()
