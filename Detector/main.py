from Dynamic.DynamicDetectFromDebuggerHook import DebuggerMonitor
from Dynamic.DynamicDetectFromRunning import DynamicDetect
from Static.checkSigantrue import checkDlls


if __name__ == "__main__":
    try:
        print("==================== Detector starts ====================")
        print("$", end=" ")
        cmd = input()
        step1 = DynamicDetect(cmd)
        step1.GetKnownDlls()
        step2 = DebuggerMonitor(step1.KnownDlls)
        step2.Analysis4x86(cmd.encode())
        dllList = step2.getDllList()
        dllChkDict = checkDlls(dllList)
        print("3rd party modules: ")
        for elem in dllChkDict:
            print(elem, dllChkDict[elem]["Verified"])
        print("==================== Detector's done ====================")
    except Exception as e:
        print(str(e))