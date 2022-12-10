import requests
from bs4 import BeautifulSoup
import re
import os

class DLLUpdater:
    def check_updates(url:str)->bool:
        # Docstring explaining the function
        """
        This function will show the latest INJECTION_MODES and LAUNCH_METHODS from the Injection.h file
        :param url: The url to the Injection.h file
        :return: True if the INJECTION_MODES and LAUNCH_METHODS were found, False if they were not
        """
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        # find all the classes that have the highlight tag
        classes = soup.find_all(class_="highlight")
        all_text = ""
        for class_ in classes:
            all_text += str(class_.text)

        # remove double new lines
        all_text = all_text.replace("\n\n\n\n", "\n")

        # find everything up to the second "};" using regex # do not match past the second ; in the file, make it work with re.DOTALL and re.MULTILINE
        match = re.search("^\w+.*(?:INJECTION_MODE|LAUNCH_METHOD).*?};", all_text, re.MULTILINE | re.DOTALL)
        if match:
            matched = match.group(0)
            # match only lines starting with IM or LM
            print("[+] INJECTION_MODES:")
            updates = re.findall("^.*(?:IM).*", matched, re.MULTILINE)
            print('\n'.join(updates))
            print("[+] LAUNCH_METHODS:")
            updates = re.findall("^.*(?:LM).*", matched, re.MULTILINE)
            print('\n'.join(updates))
            return True
        else:
            print("[-] Failed to find INJECTION_MODES or LAUNCH_METHODS")
            return False
    
    def unzip_file(filename, logging=False):
        """
        This function will unzip a file
        :param filename: The filename of the zip file
        :return: True if the file was unzipped, False if it failed
        """
        try:
            import zipfile
            with zipfile.ZipFile(filename, "r") as zip_ref:
                if logging:
                    for name in zip_ref.namelist():
                        print(f"[+] Extracting: {name}")
                zip_ref.extractall(os.path.dirname(filename))
            os.remove(filename)
            print("[+] Unzipped, and removed file: " + filename)
            return True
        except zipfile.BadZipFile as e:
            print(f"[-] Failed to unzip file: {filename}")
            return False

    def download_latest_release(url:str)->bool:
        """
        This function will download the latest dll build from the github releases page, using the most recent tag
        :param url: The url to the github releases page
        :return: True if the file was downloaded, False if it failed
        """
        if "/releases/" not in url:
            url += "/releases/latest/"
            print("[+] Using url: " + url)
        response = requests.get(url)
        # get the new url from the redirect
        url = response.url.replace("tag", "expanded_assets")
        response = requests.get(url)

        # loop through all links and look for one that contains "expanded_assets"
        soup = BeautifulSoup(response.text, "html.parser")
        asset_links = soup.find_all("a")
        for asset_link in asset_links:
            if "download" in asset_link["href"]:
                print("[+] Attemping to download latest release: " + "https://github.com" + asset_link["href"])
                response = requests.get("https://github.com" + asset_link["href"])
                break
        else:
            print("[-] Failed to find latest release")
            return False
        # download the file
        if response.ok:
            filename = url.split("/")[-1]
            print("[+] Downloaded latest release: " + filename)
            with open(filename, "wb") as f:
                f.write(response.content)
            DLLUpdater.unzip_file(filename, logging=True)           
        else:
            print("[-] Failed to download: " + filename)
            return False


    def download_pdb_files(url:str)->bool:
        """
        This function will download pdb files from the microsoft symbol server
        :param url: The url to the pdb file
        :return: True if the file was downloaded, False if it failed
        """
        # download these pdb files
        print("[+] Downloading: " + url)
        response = requests.get(url)
        # download the file
        filename = url.split("/")[-1]
        with open(filename, "wb") as f:
            f.write(response.content)
        if response.ok:
            print("[+] Downloaded: " + filename)
            return True
        else:
            print("[-] Failed to download: " + filename)
            return False


if __name__ == "__main__":
    # print the docstring for the function
    DLLUpdater.check_updates("https://github.com/Broihon/GH-Injector-Library/blob/master/Injection.h")

    if "ntdll.pdb" not in os.listdir() and "wntdll.pdb" not in os.listdir():
        wntdll = "https://msdl.microsoft.com/download/symbols/wntdll.pdb/7EDD56F06D47FF1247F446FD1B111F2C1/wntdll.pdb"
        ntdll = "https://msdl.microsoft.com/download/symbols/ntdll.pdb/46F6F5C30E7147E46F2A953A5DAF201A1/ntdll.pdb"

        DLLUpdater.download_pdb_files(wntdll)
        DLLUpdater.download_pdb_files(ntdll)
    if "GH Injector - x64.dll" and "GH Injector - x86.dll" not in os.listdir():
        DLLUpdater.download_latest_release("https://github.com/Broihon/GH-Injector-Library/")
