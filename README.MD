![Banner Image](/images/banner.png)


## DISCLAIMER
This tool is intended for educational and research purposes only. The user is responsible for complying with all applicable laws and regulations. The creators and contributors of this tool are not responsible for any illegal or unauthorized use of this tool. Use at your own risk.


## ABOUT
ProcessMarauder is a Python library for DLL injection, built off of the GH Injector DLL. It provides a command line interface for injecting DLLs into running processes and includes optional arguments for specifying the injection mode, launch method, and cloaking options. The library also offers the ability to download PDB files and DLLs for the GH Injector library, and to check for updates to the library. It requires the user to specify the path to the DLL to inject and the ID or name of the target process.

Big s/o to https://github.com/Broihon/GH-Injector-Library


## USAGE
To use the ProcessMarauder tool, you must specify the path to the DLL to inject and the ID or name of the target process using the `--injectable_dll`(`-i`) and `--target_pid`(`-p`) or `--target_process`(`-t`) arguments, respectively.

`python ProcessMarauder.py -i an_injectable.dll -t notepad.exe`

There are also several optional arguments you can use to customize the injection process. For example, you can specify the injection mode using the -m argument and the launch method using the -l argument. You can also specify cloaking options using the --cloak_options argument. 

`python ProcessMarauder.py -i ..\an_injectable.dll -t notepad.exe -m IM_ManualMap -l LM_NtCreateThreadEx --cloak_options INJ_LOAD_DLL_COPY INJ_SCRAMBLE_DLL_NAME INJ_UNLINK_FROM_PEB INJ_ERASE_HEADER`


![Command Usage](/images/usage.png)
### Mandatory Arguments
`--injectable_dll or -i`: The path to the DLL to inject.

`--target_pid or -p`: The ID of the process to inject into.

### Optional Arguments
`--check_for_updates or -u`: Check for updates to the GH Injector library.

`--download_pdbs or -b`: Download the PDB files for the GH Injector library.

`--download_injector_dllhows or -d`: Download the DLLs for the GH Injector library.

`--injectable_dll or -i`: The path to the DLL to inject.

`--target_pid or -p`: The ID of the process to inject into.

`--target_process or -t`: The name of the process to inject into.

`-m`: The injection mode to use.

`-l`: The launch method to use.

`--generate_error_log or -e`: Generate an error log if the injection fails.

`--cloak_options`: The cloak method to use.

`--manual_map_options`: Options when manually mapping a DLL.

`--wait or -w`: The delay in milliseconds to wait before manually mapping a DLL.
