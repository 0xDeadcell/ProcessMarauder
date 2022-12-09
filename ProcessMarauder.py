"""
    struct INJECTIONDATAA
    {
        char			szDllPath[MAX_PATH * 2];	//fullpath to the dll to inject
        DWORD			ProcessID;					//process identifier of the target process
        INJECTION_MODE	Mode;						//injection mode
        LAUNCH_METHOD	Method;						//method to execute the remote shellcode
        DWORD			Flags;						//combination of the flags defined above
        DWORD			Timeout;					//timeout for DllMain return in milliseconds
        DWORD			hHandleValue;				//optional value to identify a handle in a process
        HINSTANCE		hDllOut;					//returned image base of the injection
        bool			GenerateErrorLog;			//if true error data is generated and stored in GH_Inj_Log.txt
    };
    """
    
import os
import time
import argparse
import threading
import ctypes
import psutil

MAX_PATH = 260

# Define the INJECTIONDATAW and INJECTIONDATAA structures
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

def main(injectable_dll, target_pid, generate_log, _launch_method, _injection_mode):
    # Import the "GH Injector - x86.dll" library using ctypes
    current_dir = os.path.dirname(os.path.abspath(__file__))
    gh_injector_dll_path = current_dir + os.path.sep + "GH Injector - x64.dll"
    gh_injector = ctypes.windll.LoadLibrary(gh_injector_dll_path)

    # Define the constants for the INJECTION_MODE and LAUNCH_METHOD enums
    INJECTION_MODE = ctypes.c_int
    INJECTION_MODE.IM_LoadLibraryExW = 0
    INJECTION_MODE.IM_LdrLoadDll = 1
    INJECTION_MODE.IM_LdrpLoadDll = 2
    INJECTION_MODE.IM_LdrpLoadDllInternal = 3
    INJECTION_MODE.IM_ManualMap = 4
    INJECTION_MODE.USER_DEFINED = int(_injection_mode)

    LAUNCH_METHOD = ctypes.c_int
    LAUNCH_METHOD.LM_NtCreateThreadEx = 0
    LAUNCH_METHOD.LM_HijackThread = 1
    LAUNCH_METHOD.LM_SetWindowsHookEx = 2
    LAUNCH_METHOD.LM_QueueUserAPC = 3
    LAUNCH_METHOD.LM_KernelCallback = 4
    LAUNCH_METHOD.LM_FakeVEH = 5
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
        Inject = InjectA(("InjectA", gh_injector))
        info = INJECTIONDATAA()
        info.szDllPath = injectable_dll.encode("utf-8")
    else:
        print(f"{COLORS.GREEN}[*] Choosing INJECTIONDATAW{COLORS.END}")
        Inject = InjectW(("InjectW", gh_injector))
        info = INJECTIONDATAW()
        info.szDllPath = injectable_dll
    
    info.ProcessID = target_pid
    info.Mode = INJECTION_MODE.USER_DEFINED
    info.Method = LAUNCH_METHOD.USER_DEFINED
    info.Flags = 0
    info.Timeout = 0
    info.hHandleValue = 0
    info.hDllOut = ctypes.c_void_p()
    info.GenerateErrorLog = generate_log

    # Start the download process if the symbol and import files are not present
    if "ntdll.dll" not in os.listdir(current_dir) or "kernel32.dll" not in os.listdir(current_dir):
        gh_injector.StartDownload()
    
    # Wait until the symbol and import states are ready
    waited_time = 0
    while gh_injector.GetSymbolState() != 0:
        time.sleep(0.1)
        # If the download process takes more than 1 minute, stop the script
        if waited_time > 600:
            print("Error: Could not download symbols")
            os._exit(1)
    while gh_injector.GetImportState() != 0:
        time.sleep(0.1)
        # If the download process takes more than 1 minute, stop the script
        if waited_time > 600:
            print("Error: Could not download imports")
            os._exit(1)
    
    """
        struct INJECTIONDATAA
    {
        char			szDllPath[MAX_PATH * 2];	//fullpath to the dll to inject
        DWORD			ProcessID;					//process identifier of the target process
        INJECTION_MODE	Mode;						//injection mode
        LAUNCH_METHOD	Method;						//method to execute the remote shellcode
        DWORD			Flags;						//combination of the flags defined above
        DWORD			Timeout;					//timeout for DllMain return in milliseconds
        DWORD			hHandleValue;				//optional value to identify a handle in a process
        HINSTANCE		hDllOut;					//returned image base of the injection
        bool			GenerateErrorLog;			//if true error data is generated and stored in GH_Inj_Log.txt
    };
    """

    # strcpy the DLL path into the INJECTIONDATAA structure - strcpy(data.szDllPath, DllPathToInject);
    # ctypes.memmove(data.szDllPath, injectable_dll.encode(), len(injectable_dll.encode()))
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
    inject_mode_lookup = {"IM_LoadLibraryExW": 0, "IM_LdrLoadDll": 1, "IM_LdrpLoadDll": 2, "IM_LdrpLoadDllInternal": 3, "IM_ManualMap": 4}
    launch_method_lookup = {"LM_NtCreateThreadEx": 0, "LM_HijackThread": 1, "LM_SetWindowsHookEx": 2, "LM_QueueUserAPC": 3, "LM_KernelCallback": 4, "LM_FakeVEH": 5}
    lookup_mode_action = lambda x: inject_mode_lookup[x] if x in inject_mode_lookup else int(x)
    lookup_launch_action = lambda x: launch_method_lookup[x] if x in launch_method_lookup else int(x)
    parser = argparse.ArgumentParser(description="Inject a DLL into a process using the GH Injector library")
    # allow relative paths for the DLL to inject
    # use a mandatory group for both the DLL to inject and the target process ID so the user has to specify both
    mandatory_group = parser.add_argument_group("Required Arguments")
    optional_group = parser.add_argument_group("Optional Arguments")
    # allow check_for_updates to be the only argument specified
    optional_group.add_argument("--check_for_updates", "-u", action="store_true", help="Check for updates to the GH Injector library", default=False, required=False)
    optional_group.add_argument("--download_pdbs", "-b", action="store_true", help="Download the PDB files for the GH Injector library", default=False, required=False)
    #optional_group.add_argument("--download_injector_dlls", "-d", action="store_true", help="Download the DLLs for the GH Injector library", default=False, required=False)
    # make both arguments mandatory
    mandatory_group.add_argument("--injectable_dll", "-i", type=os.path.abspath, help="The path to the DLL to inject", metavar="DLL_PATH", required=True)
    mandatory_group.add_argument("--target_pid", "-p", type=int, help="The ID of the process to inject into", metavar="PROCESS_ID", required=True)
    mandatory_group.add_argument("--target_process", "-t", type=str, help="The name of the process to inject into", metavar="PROCESS_NAME", required=False)
    optional_group.add_argument("--generate_error_log", "-e", action="store_true", help="Generate an error log if the injection fails, defaults to True", default=True, required=False)
    optional_group.add_argument("-m", help="The injection mode to use, defaults to IM_LoadLibraryExW", default="IM_LoadLibraryExW", required=False, choices=inject_mode_lookup.keys())
    optional_group.add_argument("-l", help="The launch method to use, defaults to LM_NtCreateThreadEx", default="LM_NtCreateThreadEx", required=False, choices=launch_method_lookup.keys())
    # ignore errors if the user doesn't specify the DLL to inject or the target process ID, but still show the help message
    parser.error = lambda message: None
    # show a custom help message listing the available injection modes and launch methods
    # show a custom error if the user picked both a target process ID and a target process name
    args = parser.parse_args()
    if args.target_pid and args.target_process:
        print(f"{COLORS.RED}You can't specify both a target process ID and a target process name!{COLORS.END}")
        # print the help message
        parser.print_help()
        exit(1)
    elif not args.target_pid and not args.target_process or not args.injectable_dll:
        print(f"{COLORS.RED}You must specify a target process ID or a target process name, and a DLL to inject!{COLORS.END}")
        # print the help message
        parser.print_help()
        exit(1)
    # start the main function in a new thread, then check if KeyboardInterrupt is raised
    # if it is, then exit the program

    if args.check_for_updates:
        check_updates()
    if args.download_pdbs:
        wntdll = "https://msdl.microsoft.com/download/symbols/wntdll.pdb/7EDD56F06D47FF1247F446FD1B111F2C1/wntdll.pdb"
        ntdll = "https://msdl.microsoft.com/download/symbols/ntdll.pdb/46F6F5C30E7147E46F2A953A5DAF201A1/ntdll.pdb"
        download_pdb_files(wntdll)
        download_pdb_files(ntdll)

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
            print("")
            main_thread = threading.Thread(target=main, args=(args.injectable_dll, args.target_pid, args.generate_error_log, lookup_mode_action(args.m), lookup_launch_action(args.l)))
            main_thread.start()
            main_thread.join()
        except KeyboardInterrupt:
            exit(0)
    elif not args.check_for_updates and not args.download_pdbs:
        parser.print_help()
