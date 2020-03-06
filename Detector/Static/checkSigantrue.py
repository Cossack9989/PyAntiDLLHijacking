from subprocess import PIPE, Popen
from pathlib import Path
import pefile


def checkDllSignature(dll_path):
    retDict = {}
    if (dll_path.find("\\") != -1 or dll_path.find('/') != -1) and Path(dll_path).is_file():
        pe = pefile.PE(dll_path)
        detector = "./StaticDetector/detector/sigcheck.exe" if pe.FILE_HEADER.Machine == 0x14c else "./StaticDetector/detector/sigcheck64.exe"
        p = Popen([detector, "-nobanner", dll_path], shell=False, stdout=PIPE)
        buffer = p.stdout.readlines()
        p.terminate()
        for idx in range(1, len(buffer)):
            tmp = buffer[idx].strip().split(b':\t')
            retDict[tmp[0].decode()] = tmp[1].decode()
        return retDict
    else:
        return {}


def checkDlls(dll_list):
    retDict = {}
    for dll_path in dll_list:
        tmp = checkDllSignature(dll_path)
        if tmp != {}:
            retDict[dll_path] = tmp
    return retDict