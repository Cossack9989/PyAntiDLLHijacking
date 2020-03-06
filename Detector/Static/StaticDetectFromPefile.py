import pefile
import os


class StaticDetect(object):

    def __init__(self, exePathName):
        self.pe = None
        self.exePathName = exePathName
        self.level = 0

    def checkPath(self):
        return os.access(self.exePathName, os.X_OK)

    def analyzePe(self):
        self.pe = pefile.PE(self.exePathName, fast_load=True)
        self.pe.parse_data_directories()
        tmpList = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            for elem in entry.imports:
                try:
                    if elem.name.decode().startswith("LoadLibrary"):
                        tmpList.append(elem.name.decode())
                except Exception:
                    continue
        if len(tmpList) == 0:
            self.level = 0
        else:
            funcNameList = {"risk": ["LoadLibraryA", "LoadLibraryW", "LoadLibrary"],
                            "fine": ["LoadLibraryExA", "LoadLibraryExW", "LoadLibraryEx"]}
            for elem in funcNameList["fine"]:
                if elem in tmpList:
                    self.level = 1
                    break
            for elem in funcNameList["risk"]:
                if elem in tmpList:
                    self.level = 2
                    break
        return self.level

    def QuickAnalysis(self):
        if self.checkPath():
            return self.analyzePe()
        else:
            return -1


def test():
    print("Give me path")
    x = StaticDetect(input())
    print(x.QuickAnalysis())

