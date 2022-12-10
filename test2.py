
import requests
import re

# Replace with the URL of the GitHub release page
release_page_url = 'https://github.com/Broihon/GH-Injector-Library/releases/latest'


# Replace with the URL of the GitHub release page
release_page_url = 'https://github.com/USERNAME/REPO/releases/latest'

# Send a GET request to the URL and extract the zip file URL from the response
response = requests.get(release_page_url)
zip_url = re.search(r'"zipball_url":\s*"([^"]+)"', response.text, re.MULTILINE | re.DOTALL).group(1)

# Send a GET request to the zip file URL and save it to a local file
response = requests.get(zip_url)
open('latest.zip', 'wb').write(response.content)