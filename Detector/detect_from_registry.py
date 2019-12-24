import winreg
import subprocess
from time import sleep

whiteList = ['ntdll.dll']

class Detect:

    def __init__(self, target_pcmd):
        self.KnownDlls = []
        self.LoadedDlls = []
        self.QuickAnalysisRes = []
        self.target_pcmd = target_pcmd.split()
        self.process = None
        self.tmp_monitor = None

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

    def StartProcess(self):
        print(self.target_pcmd)
        self.process = subprocess.Popen(self.target_pcmd, shell=False)
        return self.process.pid

    def KillProcess(self):
        self.process.terminate()

    def GetLoadedDlls(self):
        monitor_cmd = 'tasklist /m /FI "PID eq %d"'%self.process.pid
        self.tmp_monitor = subprocess.Popen(monitor_cmd, shell=True, stdout=subprocess.PIPE)
        result = self.tmp_monitor.stdout.readlines()
        fix_result = ""
        fix_allow = False
        for line in result:
            if fix_allow:
                fix_result += line.decode("GBK")
            if line.endswith(b"=====\r\n"):
                fix_allow = True
        break_sign = "%d "%self.process.pid
        break_pos = fix_result.index(break_sign)+len(break_sign)
        self.LoadedDlls = fix_result[break_pos:].split()
        for i in range(len(self.LoadedDlls)-1,-1,-1):
            self.LoadedDlls[i] = self.LoadedDlls[i].replace(',','')
            if not self.LoadedDlls[i].endswith(".dll"):
                del self.LoadedDlls[i]

    def QuickAnalysis(self):
        self.StartProcess()
        sleep(30)
        #TODO
        self.GetKnownDlls()
        self.GetLoadedDlls()
        for i in self.LoadedDlls:
            if (not i in self.KnownDlls) and (not i in whiteList):
                self.QuickAnalysisRes.append(i)
        self.KillProcess()

if __name__ == "__main__":
    try:
        test = Detect(input())
        test.QuickAnalysis()
        print()
        print("============== QuickAnalysis ===============")
        print("White:",whiteList)
        print("Load:",test.LoadedDlls)
        print("Know:",test.KnownDlls)
        print("RES:",test.QuickAnalysisRes)
    except Exception as e:
        print(str(Exception))
        print(str(e))