import os
import psutil
import ctypes


current_dir = os.path.dirname(os.path.abspath(__file__))
gh_injector_dll_path = current_dir + os.path.sep + "GH Injector - x64.dll"
gh_injector = ctypes.windll.LoadLibrary(gh_injector_dll_path)
injectable_dll = os.path.abspath(current_dir + os.path.sep + "../dlls/calc_x64.dll")
print(injectable_dll)
generate_log = True
MAX_PATH = 260

# get the pid of notepad.exe
try:
    target_pid = [p.pid for p in psutil.process_iter(attrs=['pid', 'name']) if 'notepad.exe' in p.info['name']][0]
except IndexError:
    print("Could not find notepad.exe")
    exit(1)

class INJECTIONDATAA(ctypes.Structure):
    _fields_ = [
        ("szDllPath", ctypes.c_char * (MAX_PATH * 2)),
        ("ProcessID", ctypes.c_uint32),
        ("Mode", ctypes.c_int),
        ("Method", ctypes.c_int),
        ("Flags", ctypes.c_uint32),
        ("Timeout", ctypes.c_uint32),
        ("hHandleValue", ctypes.c_uint32),
        ("hDllOut", ctypes.c_void_p),
        ("GenerateErrorLog", ctypes.c_bool),
    ]

class INJECTIONDATAW(ctypes.Structure):
    _fields_ = [
        ("szDllPath", ctypes.c_wchar * (MAX_PATH * 2)),
        ("szTargetProcessExeFileName", ctypes.c_wchar * MAX_PATH),
        ("ProcessID", ctypes.c_uint32),
        ("Mode", ctypes.c_int),
        ("Method", ctypes.c_int),
        ("Flags", ctypes.c_uint32),
        ("Timeout", ctypes.c_uint32),
        ("hHandleValue", ctypes.c_uint32),
        ("hDllOut", ctypes.c_void_p),
        ("GenerateErrorLog", ctypes.c_bool),
    ]

class HookInfo(ctypes.Structure):
    _fields_ = [
        ("ModuleName", ctypes.c_char_p),
        ("FunctionName", ctypes.c_char_p),
        ("hModuleBase", ctypes.c_void_p),
        ("pFunc", ctypes.c_void_p),
        ("ChangeCount", ctypes.c_uint),
        ("OriginalBytes", ctypes.c_ubyte * 0x10),
        ("ErrorCode", ctypes.c_uint32),
    ]



# Define the structs
def main():
    # Load the Injection module
    hInjectionMod = ctypes.cdll.LoadLibrary(gh_injector)

    # Define the functions
    InjectA = hInjectionMod.InjectA
    InjectW = hInjectionMod.InjectW

    # Set up the injection data
    data = INJECTIONDATAA()
    data.szDllPath = os.path.abspath(injectable_dll)
    data.ProcessID = target_pid
    data.Mode = INJECTION_MODE.USER_DEFINED
    data.Method = LAUNCH_METHOD.USER_DEFINED
    data.Flags = 0
    data.Timeout = 0
    data.hHandleValue = 0
    data.hDllOut = ctypes.c_void_p()
    data.GenerateErrorLog = generate_log

if __name__ == "__main__":
    main()