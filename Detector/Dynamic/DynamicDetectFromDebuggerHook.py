import os
import winc
import struct
import pefile
from pydbg import *
from pydbg.defines import *
from _collections import OrderedDict


def readStringFromMem(dbg, addr, charSet):
    data = b""
    (size, endFlag) = (1, b'\0') if charSet == "A" else (2, b'\0\0')
    while True:
        tmpData = dbg.read_process_memory(addr, size)
        addr += size
        if tmpData == endFlag:
            break
        data += tmpData
    # return dbg.get_ascii_string(data.decode())
    if charSet == "A":
        return data.decode().replace('\0', '')
    else:
        return data.decode("gbk", "ignore").replace('\0', '')


class DebuggerMonitor:
    whiteList = {
        "MingW32": {
            "fullName": [
                "apphelp",
                "kernelbase",
                "kernel32",
                "msvcrt",
                "wow64cpu",
                "ntdll",
                "wow64",
                "wow64win",
            ],
            "seriesPrefix": [
                "api-ms-win",
                "ext-ms-win",
            ]
        }
    }

    riskLoaderSrc = {
        "DLL": ["kernelbase.dll", "kernel32.dll"],
        "API": ["LoadLibraryExA", "LoadLibraryA", "LoadLibraryExW", "LoadLibraryW"],
    }

    safePath = [
        "C:\\Windows\\",
        os.environ["TMP"],
        os.environ["TEMP"],
    ]

    def __init__(self, baseWhiteList):
        self.dict = {}
        self.name = {}
        self.dbg = pydbg()
        self.baseWhiteList = baseWhiteList
        self.dll_list = []

    def generic(self, dbg):
        dbg = self.dbg
        eip = self.dbg.context.Eip
        if self.dict[eip]:
            try:
                esp = self.dbg.context.Esp
                addr = int(struct.unpack("L", self.dbg.read_process_memory(esp+0x4, 4))[0])
                charSet = "A" if "A" in self.name[eip] else "W"
                dll_name = readStringFromMem(self.dbg, addr, charSet)
                for prefix in self.safePath+self.whiteList["MingW32"]["seriesPrefix"]:
                    if dll_name.lower().startswith(prefix.lower()):
                        return DBG_CONTINUE
                # TODO
                for dll in self.whiteList["MingW32"]["fullName"]+self.baseWhiteList:
                    if dll == dll_name.lower().replace('.dll', ''):
                        return DBG_CONTINUE
                print("hit @ %s and Dll : %s" % (self.name[eip], dll_name))
                self.dll_list.append(dll_name)
            except Exception as e:
                print("Exception @ generic : %s" % str(e))
                pass
        return DBG_CONTINUE

    def entryHandler(self, dbg):
        dbg = self.dbg
        for DLL in self.riskLoaderSrc["DLL"]:
            for API in self.riskLoaderSrc["API"]:
                try:
                    ApiAddr = self.dbg.func_resolve(DLL, API)
                    self.dbg.bp_set(ApiAddr, handler=self.generic)
                    self.dict[ApiAddr] = True
                    self.name[ApiAddr] = DLL.split('.')[0] + "!" + API
                except Exception as e:
                    print("Exception @ handler : %s" % str(e))
                    continue
        return DBG_CONTINUE

    def Analysis4x86(self, file):
        pe = pefile.PE(file)
        self.dbg.load(file)
        entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.dbg.bp_set(entrypoint, description="entrypoint", handler=self.entryHandler)
        self.dbg.run()

    def stopAnalysis4x86(self):
        print(self.dbg.pid, "terminated")
        self.dbg.terminate_process()

    def stopPartialAnalysis4x86(self):
        print(self.dbg.pid, "detach")
        self.dbg.detach()

    def PartialAnalysis4x86(self, file, pid):
        pe = pefile.PE(file)
        self.dbg.load(file)
        entrypoint = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.dbg.bp_set(entrypoint, description="entrypoint", handler=self.entryHandler)
        self.dbg.attach(pid)

    def getDllList(self):
        self.dll_list = list(set(self.dll_list))
        return self.dll_list


def test():
    print("$", end=" ")
    file = input().encode()
    tmp = DebuggerMonitor([])
    tmp.Analysis4x86(file)


print("Only test on python 3.8 x86")
