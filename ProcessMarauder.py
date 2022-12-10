import os
import sys
import time
import argparse
import threading
import ctypes
import psutil
import re
from update_checker import DLLUpdater


MAX_PATH = 260
HOOK_SCAN_BYTE_COUNT = 0x10
INJECT_MODE_OPTIONS = {"IM_LoadLibraryExW": 0, "IM_LdrLoadDll": 1, "IM_LdrpLoadDll": 2, "IM_LdrpLoadDllInternal": 3, "IM_ManualMap": 4}
LAUNCH_METHOD_OPTIONS = {"LM_NtCreateThreadEx": 0, "LM_HijackThread": 1, "LM_SetWindowsHookEx": 2, "LM_QueueUserAPC": 3, "LM_KernelCallback": 4, "LM_FakeVEH": 5}


CLOAKING_OPTIONS = {"INJ_ERASE_HEADER": 0x0001, # replaces the first 0x1000 bytes of the dll with 0's (takes priority over INJ_FAKE_HEADER if both are specified)
                    "INJ_FAKE_HEADER": 0x0002, # replaces the dlls header with the header of the ntdll.dll (superseded by INJ_ERASE_HEADER if both are specified)
                    "INJ_UNLINK_FROM_PEB": 0x0004, # unlinks the module from the process enviroment block (1)
                    "INJ_THREAD_CREATE_CLOAKED": 0x0008, # passes certain flags to NtCreateThreadEx to make the thread creation more stealthy (2)
                    "INJ_SCRAMBLE_DLL_NAME": 0x0010, # randomizes the dll name on disk before injecting it
                    "INJ_LOAD_DLL_COPY": 0x0020, # loads a copy of the dll from %temp% directory
                    "INJ_HIJACK_HANDLE": 0x0040} # tries to a hijack a handle from another process instead of using OpenProcess

MANUAL_MAP_OPTIONS = {"INJ_MM_CLEAN_DATA_DIR": 0x00010000, # removes data from the dlls PE header, ignored if INJ_MM_SET_PAGE_PROTECTIONS is set
                    "INJ_MM_RESOLVE_IMPORTS": 0x00020000, # resolves dll imports
                    "INJ_MM_RESOLVE_DELAY_IMPORTS": 0x00040000, # resolves delayed imports
                    "INJ_MM_EXECUTE_TLS": 0x00080000, # executes TLS callbacks and initializes static TLS data
                    "INJ_MM_ENABLE_EXCEPTIONS": 0x00100000, # enables exception handling
                    "INJ_MM_SET_PAGE_PROTECTIONS": 0x00200000, # sets page protections based on section characteristics, if set INJ_MM_CLEAN_DATA_DIR will be ignored
                    "INJ_MM_INIT_SECURITY_COOKIE": 0x00400000, # initializes security cookie for buffer overrun protection
                    "INJ_MM_RUN_DLL_MAIN": 0x00800000, # executes DllMain
                    "INJ_MM_RUN_UNDER_LDR_LOCK": 0x01000000, # runs the DllMain under the loader lock
                    "INJ_MM_SHIFT_MODULE_BASE": 0x02000000} # shifts the module base by a random offset

"""
# Add support for the following options:

class CLK_OPTIONS(ctypes.c_uint32):
    INJ_ERASE_HEADER = 0x0001
    INJ_FAKE_HEADER = 0x0002
    INJ_UNLINK_FROM_PEB = 0x0004
    INJ_THREAD_CREATE_CLOAKED = 0x0008
    INJ_SCRAMBLE_DLL_NAME = 0x0010
    INJ_LOAD_DLL_COPY = 0x0020
    INJ_HIJACK_HANDLE = 0x0040
    def __call__(self, *args, **kwargs):
        return (INJ_ERASE_HEADER | INJ_FAKE_HEADER | INJ_UNLINK_FROM_PEB | INJ_THREAD_CREATE_CLOAKED | INJ_SCRAMBLE_DLL_NAME | INJ_LOAD_DLL_COPY | INJ_HIJACK_HANDLE

class MM_OPTIONS(ctypes.c_uint32):
    INJ_MM_CLEAN_DATA_DIR = 0x00010000
    INJ_MM_RESOLVE_IMPORTS = 0x00020000
    INJ_MM_RESOLVE_DELAY_IMPORTS = 0x00040000
    INJ_MM_EXECUTE_TLS = 0x00080000
    INJ_MM_ENABLE_EXCEPTIONS = 0x00100000
    INJ_MM_SET_PAGE_PROTECTIONS = 0x00200000
    INJ_MM_INIT_SECURITY_COOKIE = 0x00400000
    INJ_MM_RUN_DLL_MAIN = 0x00800000
    INJ_MM_RUN_UNDER_LDR_LOCK = 0x01000000
    INJ_MM_SHIFT_MODULE_BASE = 0x02000000
    def __call__(self, *args, **kwargs):
        return (INJ_MM_CLEAN_DATA_DIR | INJ_MM_RESOLVE_IMPORTS | INJ_MM_RESOLVE_DELAY_IMPORTS | INJ_MM_EXECUTE_TLS | INJ_MM_ENABLE_EXCEPTIONS | INJ_MM_SET_PAGE_PROTECTIONS | INJ_MM_INIT_SECURITY_COOKIE | INJ_MM_RUN_DLL_MAIN | INJ_MM_RUN_UNDER_LDR_LOCK | INJ_MM_SHIFT_MODULE_BASE)
"""

MM_DEFAULT = (MANUAL_MAP_OPTIONS["INJ_MM_RESOLVE_IMPORTS"] 
            | MANUAL_MAP_OPTIONS["INJ_MM_RESOLVE_DELAY_IMPORTS"] 
            | MANUAL_MAP_OPTIONS["INJ_MM_INIT_SECURITY_COOKIE"] 
            | MANUAL_MAP_OPTIONS["INJ_MM_EXECUTE_TLS"] 
            | MANUAL_MAP_OPTIONS["INJ_MM_ENABLE_EXCEPTIONS"] 
            | MANUAL_MAP_OPTIONS["INJ_MM_RUN_DLL_MAIN"] 
            | MANUAL_MAP_OPTIONS["INJ_MM_SET_PAGE_PROTECTIONS"])


class INJECTIONDATAA(ctypes.Structure):
    _fields_ = [
        ("szDllPath", ctypes.c_char * (MAX_PATH * 2)), # fullpath to the dll to inject
        ("ProcessID", ctypes.c_uint32), # process identifier of the target process
        ("Mode", ctypes.c_int), # injection mode
        ("Method", ctypes.c_int), # method to execute the remote shellcode
        ("Flags", ctypes.c_uint32), # combination of the flags defined above
        ("Timeout", ctypes.c_uint32), # timeout for DllMain return in milliseconds
        ("hHandleValue", ctypes.c_uint32), # optional value to identify a handle in a process
        ("hDllOut", ctypes.c_void_p), # returned image base of the injection
        ("GenerateErrorLog", ctypes.c_bool), # if true error data is generated and stored in GH_Inj_Log.txt
    ]


class INJECTIONDATAW(ctypes.Structure):
    _fields_ = [
        ("szDllPath", ctypes.c_wchar * (MAX_PATH * 2)), # fullpath to the dll to inject
        ("szTargetProcessExeFileName", ctypes.c_wchar * MAX_PATH), # fullpath to the target process executable
        ("ProcessID", ctypes.c_uint32), # process identifier of the target process
        ("Mode", ctypes.c_int), # injection mode
        ("Method", ctypes.c_int), # method to execute the remote shellcode
        ("Flags", ctypes.c_uint32), # combination of the flags defined above
        ("Timeout", ctypes.c_uint32), # timeout for DllMain return in milliseconds
        ("hHandleValue", ctypes.c_uint32), # optional value to identify a handle in a process
        ("hDllOut", ctypes.c_void_p), # returned image base of the injection
        ("GenerateErrorLog", ctypes.c_bool), # if true error data is generated and stored in GH_Inj_Log.txt
    ]


class HookInfo(ctypes.Structure):
    _fields_ = [
        ("ModuleName", ctypes.c_char_p),
        ("FunctionName", ctypes.c_char_p),
        ("hModuleBase", ctypes.c_void_p),
        ("pFunc", ctypes.c_void_p),
        ("ChangeCount", ctypes.c_uint),
        ("OriginalBytes", ctypes.c_ubyte * HOOK_SCAN_BYTE_COUNT),
        ("ErrorCode", ctypes.c_uint32),
    ]


class INJECTION_MODE(ctypes.c_int):
    IM_LoadLibraryExW = 0
    IM_LdrLoadDll = 1
    IM_LdrpLoadDll = 2
    IM_LdrpLoadDllInternal = 3
    IM_ManualMap = 4
    USER_DEFINED = 0


class LAUNCH_METHOD(ctypes.c_int):
    LM_NtCreateThreadEx = 0
    LM_HijackThread = 1
    LM_SetWindowsHookEx = 2
    LM_QueueUserAPC = 3
    LM_KernelCallback = 4
    LM_FakeVEH = 5
    USER_DEFINED = 0


def Inject(injectable_dll, target_pid, generate_log, _launch_method, _injection_mode, cloak_methods):
    # Import the "GH Injector - x86.dll" library using ctypes
    current_dir = os.path.dirname(os.path.abspath(__file__))
    gh_injector_dll_path = current_dir + os.path.sep + "GH Injector - x64.dll"
    GH_INJECTOR_DLL = ctypes.windll.LoadLibrary(gh_injector_dll_path)
    

    # Assign the user defined injection mode and launch method to the INJECTION_MODE and LAUNCH_METHOD classes
    INJECTION_MODE.USER_DEFINED = int(_injection_mode)
    LAUNCH_METHOD.USER_DEFINED = int(_launch_method)

    InjectW = ctypes.WINFUNCTYPE(
        ctypes.c_bool, 
        ctypes.POINTER(INJECTIONDATAW)
    )

    InjectA = ctypes.WINFUNCTYPE(
        ctypes.c_bool, 
        ctypes.POINTER(INJECTIONDATAA)
    )

    # Set up the INJECTIONDATAW or INJECTIONDATAA structure depending on the injectable_dll type, use Inject to call the InjectW or InjectA function
    if isinstance(injectable_dll, str):
        print(f"{COLORS.GREEN}[*] Choosing INJECTIONDATAA{COLORS.END}")
        Inject = InjectA(("InjectA", GH_INJECTOR_DLL))
        info = INJECTIONDATAA()
        info.szDllPath = injectable_dll.encode("utf-8")

    else:
        print(f"{COLORS.GREEN}[*] Choosing INJECTIONDATAW{COLORS.END}")
        Inject = InjectW(("InjectW", GH_INJECTOR_DLL))
        info = INJECTIONDATAW()
        info.szDllPath = injectable_dll
    
    info.ProcessID = target_pid
    info.Mode = INJECTION_MODE.USER_DEFINED
    info.Method = LAUNCH_METHOD.USER_DEFINED
    # set the flags with MM_DEFAULT
    info.Flags = ctypes.c_uint32(MM_DEFAULT)
    info.Timeout = 0
    info.hHandleValue = 0
    info.hDllOut = ctypes.c_void_p()
    info.GenerateErrorLog = generate_log

    # Start the download process if the symbol and import files are not present
    if "ntdll.dll" not in os.listdir(current_dir) or "kernel32.dll" not in os.listdir(current_dir):
        GH_INJECTOR_DLL.StartDownload()
    
    # Wait until the symbol and import states are ready
    waited_time = 0
    while GH_INJECTOR_DLL.GetSymbolState() != 0:
        time.sleep(0.1)
        # If the download process takes more than 1 minute, stop the script
        if waited_time > 600:
            print("Error: Could not download symbols")
            os._exit(1)
        waited_time += 1
    while GH_INJECTOR_DLL.GetImportState() != 0:
        time.sleep(0.1)
        # If the download process takes more than 1 minute, stop the script
        if waited_time > 600:
            print("Error: Could not download imports")
            os._exit(1)
        waited_time += 1
    
    # Inject the DLL into the target process
    success = Inject(ctypes.byref(info))
    if success:
        print("Injection successful!")
    else:
        print("Injection failed!")


class COLORS:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    END = "\033[0m"


if __name__ == "__main__":
    lookup_mode_action = lambda x: INJECT_MODE_OPTIONS[x] if x in INJECT_MODE_OPTIONS else 0
    lookup_launch_action = lambda x: LAUNCH_METHOD_OPTIONS[x] if x in LAUNCH_METHOD_OPTIONS else 0
    lookup_manual_map_option = lambda x: MANUAL_MAP_OPTIONS[x] if x in MANUAL_MAP_OPTIONS else None
    lookup_cloak_method = lambda x: CLOAKING_OPTIONS[x] if x in CLOAKING_OPTIONS else None
    parser = argparse.ArgumentParser(description=f"{COLORS.YELLOW}ProcessMarauder - A Python library for DLL injection, built off of the GH Injector DLL{COLORS.END}", formatter_class=argparse.RawTextHelpFormatter)
    # allow relative paths for the DLL to inject
    # use a mandatory group for both the DLL to inject and the target process ID so the user has to specify both
    mandatory_group = parser.add_argument_group(f"{COLORS.GREEN}Required Arguments{COLORS.END}")
    optional_group = parser.add_argument_group(f"{COLORS.GREEN}Optional Arguments{COLORS.END}")
    # allow check_for_updates to be the only argument specified
    optional_group.add_argument("--check_for_updates", "-u", action="store_true", help="Check for updates to the GH Injector library", default=False, required=False)
    optional_group.add_argument("--download_pdbs", "-b", action="store_true", help="Download the PDB files for the GH Injector library", default=False, required=False)
    optional_group.add_argument("--download_injector_dlls", "-d", action="store_true", help="Download the DLLs for the GH Injector library", default=False, required=False)
    # make both arguments mandatory
    mandatory_group.add_argument("--injectable_dll", "-i", type=os.path.abspath, help="The path to the DLL to inject", metavar="DLL_PATH", required=True)
    mandatory_group.add_argument("--target_pid", "-p", type=int, help="The ID of the process to inject into", metavar="PROCESS_ID", required=True)
    mandatory_group.add_argument("--target_process", "-t", type=str, help="The name of the process to inject into", metavar="PROCESS_NAME", required=False)
    optional_group.add_argument("-m", help="The injection mode to use, defaults to IM_LoadLibraryExW", default="IM_LoadLibraryExW", required=False, choices=INJECT_MODE_OPTIONS.keys())
    optional_group.add_argument("-l", help="The launch method to use, defaults to LM_NtCreateThreadEx", default="LM_NtCreateThreadEx", required=False, choices=LAUNCH_METHOD_OPTIONS.keys())
    optional_group.add_argument("--generate_error_log", "-e", action="store_true", help="Generate an error log if the injection fails, defaults to True", default=True, required=False)
    optional_group.add_argument('--cloak_options', default=None, required=False, choices=CLOAKING_OPTIONS.keys(), help="The cloak method to use, defaults to None, multiple cloak methods can be specified by separating them with a comma", nargs='?')
    optional_group.add_argument("--manual_map_options", help="Options when manually mapping a DLL, only available if -m is set to IM_ManualMap, multiple options can be specified by separating them with a comma", default=None, required=False, choices=MANUAL_MAP_OPTIONS.keys(), nargs='?')

    # ignore errors if the user doesn't specify the DLL to inject or the target process ID, but still show the help message
    parser.error = lambda message: None
    # color the usage message green if a word starts with -- or -
    old_usage = parser.format_usage().replace("usage: ", '')
    parser.usage = re.sub(r"(-+\w+)", f"{COLORS.YELLOW}\\1{COLORS.END}", old_usage).replace("ProcessMarauder.py", f"{COLORS.GREEN}ProcessMarauder.py{COLORS.END}")
    # add a custom example of how to use the script
    parser.epilog = f"Example 1: {COLORS.GREEN}{sys.argv[0]}{COLORS.YELLOW} -i an_injectable.dll -t notepad.exe -m IM_ManualMap -l LM_NtCreateThreadEx --cloak_options INJ_FAKE_HEADER, INJ_UNLINK_FROM_PEB, INJ_THREAD_CREATE_CLOAKED{COLORS.END}"
    # add a second parser epilog
    parser.epilog += f"\nExample 2: {COLORS.GREEN}{sys.argv[0]}{COLORS.YELLOW} -i \"C:\\Users\\user\\Desktop\\an_injectable.dll\" -p 1234 -m IM_LoadLibraryExW -l LM_HijackThread --cloak_options INJ_UNLINK_FROM_PEB, INJ_THREAD_CREATE_CLOAKED{COLORS.END}"
    # add a third parser epilog
    parser.epilog += f"\nExample 3: {COLORS.GREEN}{sys.argv[0]}{COLORS.YELLOW} -i ..\\..\\an_injectable.dll -t notepad.exe -m IM_LoadLibraryExW -l LM_NtCreateThreadEx{COLORS.END}"
    # add a fourth parser epilog
    parser.epilog += f"\nExample 4: {COLORS.GREEN}{sys.argv[0]}{COLORS.YELLOW} -b -d{COLORS.END}"
    # show a custom help message listing the available injection modes and launch methods
    # show a custom error if the user picked both a target process ID and a target process name
    args = parser.parse_args()
    if args.manual_map_options and args.m != "IM_ManualMap":
        # print the help message
        parser.print_help()
        print(f"{COLORS.RED}You can only specify manual map options if you're using IM_ManualMap & NtCreateThreadEx!{COLORS.END}")
        exit(1)
    if args.target_pid and args.target_process:
        # print the help message
        parser.print_help()
        print(f"{COLORS.RED}You can't specify both a target process ID and a target process name!{COLORS.END}")
        exit(1)
    # start the main function in a new thread, then check if KeyboardInterrupt is raised
    # if it is, then exit the program

    if args.check_for_updates:
        DLLUpdater.check_updates("https://github.com/Broihon/GH-Injector-Library/blob/master/Injection.h")
    if args.download_injector_dlls:
        DLLUpdater.download_latest_release("https://github.com/Broihon/GH-Injector-Library/releases/latest")
    if args.download_pdbs:
        wntdll = "https://msdl.microsoft.com/download/symbols/wntdll.pdb/7EDD56F06D47FF1247F446FD1B111F2C1/wntdll.pdb"
        ntdll = "https://msdl.microsoft.com/download/symbols/ntdll.pdb/46F6F5C30E7147E46F2A953A5DAF201A1/ntdll.pdb"
        DLLUpdater.download_pdb_files(wntdll)
        DLLUpdater.download_pdb_files(ntdll)

    if not os.path.exists("GH Injector - x64.dll"):
        print(f"{COLORS.RED}GH Injector - x64.dll not found. Please download/compile it{COLORS.END}")
        exit(1)
    if args.target_process:
        try:
            args.target_pid = [p.pid for p in psutil.process_iter() if p.name() == args.target_process][0]
        except IndexError:
            print(f"{COLORS.RED}[-] Process {args.target_process} not found{COLORS.END}")
            exit(1)
    if (args.injectable_dll is not None) and (args.target_pid is not None):
        try:
            args.injectable_dll = os.path.abspath(args.injectable_dll)
            if not os.path.exists(args.injectable_dll):
                print(f"{COLORS.RED}[-] {args.injectable_dll} not found{COLORS.END}")
                exit(1)
            print(f"{COLORS.GREEN}[*] Setting {args.injectable_dll} as the DLL to inject{COLORS.END}")
            # get the name of the process to inject into
            process_name = [p.name() for p in psutil.process_iter() if p.pid == args.target_pid]
            if len(process_name) == 0:
                print(f"[-] Process ID {args.target_pid} not found{COLORS.END}")
                exit(1)
            process_name = process_name[0]
            print(f"{COLORS.GREEN}[*] Setting PID: {args.target_pid} ({process_name}) as the target process ID{COLORS.END}")
            print(f"{COLORS.GREEN}[*] Setting {args.m} ({lookup_mode_action(args.m)}) as the injection mode{COLORS.END}")
            print(f"{COLORS.GREEN}[*] Setting {args.l} ({lookup_launch_action(args.l)}) as the launch method{COLORS.END}")
            if args.cloak_methods:
                print(f"{COLORS.GREEN}[*] Cloaking methods{COLORS.END}")
            if args.manual_map_options:
                print(f"{COLORS.GREEN}[*] Setting {args.manual_map_options} ({lookup_manual_map_option(args.manual_map_options)}) as the manual map option{COLORS.END}")
            print("")
            main_thread = threading.Thread(target=Inject, args=(args.injectable_dll, args.target_pid, args.generate_error_log, lookup_mode_action(args.m), lookup_launch_action(args.l), args.cloak_methods))
            main_thread.start()
            main_thread.join()
        except KeyboardInterrupt:
            exit(0)
    elif not args.check_for_updates and not args.download_pdbs and not args.download_injector_dlls:
        parser.print_help()
    if (not args.target_pid and not args.target_process or not args.injectable_dll) and len(sys.argv) > 1 and not args.download_injector_dlls:
        print(f"{COLORS.RED}You must specify a target process ID or a target process name, and a DLL to inject!{COLORS.END}")
        exit(1)
