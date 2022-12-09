import requests
from bs4 import BeautifulSoup
import re


def check_updates():
    url = "https://github.com/Broihon/GH-Injector-Library/blob/master/Injection.h"
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

def download_latest_dll_build(url):
    pass

def download_pdb_files(url):
    # download these pdb files
    response = requests.get(url)
    print("[+] Downloading: " + url)
    # download the file
    filename = url.split("/")[-1]
    with open(filename, "wb") as f:
        f.write(response.content)




if __name__ == "__main__":
    wntdll = "https://msdl.microsoft.com/download/symbols/wntdll.pdb/7EDD56F06D47FF1247F446FD1B111F2C1/wntdll.pdb"
    ntdll = "https://msdl.microsoft.com/download/symbols/ntdll.pdb/46F6F5C30E7147E46F2A953A5DAF201A1/ntdll.pdb"
    check_updates()
    download_pdb_files(wntdll)
    download_pdb_files(ntdll)
    download_latest_dll_build("https://github.com/Broihon/GH-Injector-Library/tags")
