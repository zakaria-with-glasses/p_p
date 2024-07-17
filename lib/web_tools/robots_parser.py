import requests
from termcolor import cprint
#Basicly a website when visited checks his robots.txt file in order to check if you have privilege.
#the process usually goes like this:
#REQ -> CHECKING ROBOTS.TXT -> ALLOW/DISALLOW.
    
def req_robots(domain) -> (list, list):
    cprint(f"[+] Requesting {domain}...", "cyan")
    s = requests.Session()
    res = s.get(domain+"/robots.txt")

    allowed_paths = []
    disallowed_path =  []
    for l in res.text.split("\n"):
        if "Allow" in l or "Disallow" in l:
            [tag, path] =l.split(": ", 1)
            if tag == "Allow":
                allowed_paths.append(path)
            else: 
                disallowed_path.append(path)

    return (allowed_paths, disallowed_path)
    
