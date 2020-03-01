import sys, struct
import pefile
from pydbg import *
from pydbg.defines import *


def readStringFromMem(dbg, addr, charSet):
    data = b""
    (size, endFlag) = (1, b'\0') if charSet == "A" else (2, b'\0\0')
    while True:
        tmpData = dbg.read_process_memory(addr, size)
        addr += size
        if tmpData == endFlag:
            break
        data += tmpData
    return dbg.get_ascii_string(data.decode())


class DebuggerMonitor:
    whiteList = {
        "MingW32": [
            "apphelp.dll",
            "kernelBase.dll",
            "kernel32.dll",
            "msvcrt.dll",
            "wow64cpu.dll",
            "ntdll.dll",
            "wow64.dll",
            "wow64win.dll",
        ]
    }

    riskLoaderSrc = {
        "DLL": ["kernelbase.dll", "kernel32.dll"],
        "API": {
            "A": ["LoadLibraryExA", "LoadLibraryA"],
            "W": ["LoadLibraryExW", "LoadLibraryW"],
        }
    }

    def __init__(self):
        self.dict = {}
        self.name = {}
        self.dbg = pydbg()
        self.charSet = None

    def generic(self, dbg):
        dbg = self.dbg
        eip = self.dbg.context.Eip
        if self.dict[eip]:
            try:
                esp = self.dbg.context.Esp
                addr = int(struct.unpack("L", self.dbg.read_process_memory(esp+0x4, 4))[0])
                dll_name = readStringFromMem(self.dbg, addr, self.charSet)
                if dll_name is False:
                    return DBG_CONTINUE
                for i in self.whiteList["MingW32"]:
                    if i == dll_name:
                        return DBG_CONTINUE
                print("hit @ %s and Dll : %s" % (self.name[eip], dll_name))
            except Exception as e:
                print("Exception @ generic : %s" % str(e))
                pass
        return DBG_CONTINUE

    def entryHandler(self, dbg):
        dbg = self.dbg
        for DLL in self.riskLoaderSrc["DLL"]:
            for _API_ in self.riskLoaderSrc["API"]:
                self.charSet = _API_
                for API in self.riskLoaderSrc["API"][_API_]:
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
        print("start!")
        print(hex(entrypoint))
        self.dbg.bp_set(entrypoint, description="entrypoint", handler=self.entryHandler)
        self.dbg.run()


def test():
    print("$", end=" ")
    file = input().encode()
    tmp = DebuggerMonitor()
    tmp.Analysis4x86(file)

print("Only test on python 3.8 x86")
