#!/usr/bin/python

from __future__ import print_function
import sys
import rubrik_cdm
import getopt
import getpass
import urllib3
urllib3.disable_warnings()


def usage():
    sys.stderr.write("Usage: rbk_share_grab.py [-h] [-c creds] [-p protocol] [-t token] [-o outfile] rubrik\n")
    sys.stderr.write("-h | --help: Prints this message\n")
    sys.stderr.write("-c | --creds : Enter cluster credentials on the CLI [user:password]\n")
    sys.stderr.write("-p | --protocol : Only grab shares of the given protocol [NFS | SMB]\n")
    sys.stderr.write("-t | --token : Authenticate via token\n")
    sys.stderr.write("-o | --output : Write output to a file\n")
    sys.stderr.write("rubrik : Hostname or IP of a Rubrik Cluster\n")
    exit(0)

def python_input(message):
    if int(sys.version[0]) > 2:
        value = imput(message)
    else:
        value = raw_input(message)
    return(value)

if __name__ == "__main__":
    user = ""
    password = ""
    token = ""
    protocol = ""
    outfile = ""
    timeout = 60

    optlist, args = getopt.getopt(sys.argv[1:], 'c:t:p:ho:', ['creds=', 'token=', 'protocol=', 'help', 'output='])
    for opt, a in optlist:
        if opt in ('-c', '--creds'):
            (user, password) = a.split(':')
        if opt in ('-t', '--token'):
            token = a
        if opt in ('-p', '--protocol'):
            protocol = a.upper()
        if opt in ('-h', '--help'):
            usage()
        if opt in ('-o', '--output'):
            outfile = a
    try:
        rubrik_node = args[0]
    except:
        usage()
    if not user:
        user = python_input("User: ")
    if not password:
        password = getpass.getpass("Password: ")
    if token != "":
        rubrik = rubrik_cdm.Connect(rubrik_node, api_token=token)
    else:
        rubrik = rubrik_cdm.Connect(rubrik_node, user, password)
    hs_data = rubrik.get('internal', '/host/share', timeout=timeout)
    if outfile:
        fp = open(outfile, "w")
    for hs in hs_data['data']:
        if protocol != "" and protocol != hs['shareType']:
            continue
        if hs['status'] != "REPLICATION_TARGET":
            if outfile:
                fp.write(hs['hostname'] + ":" + hs['exportPoint'] + "\n")
            else:
                print(hs['hostname'] + ":" + hs['exportPoint'])
    if outfile:
        fp.close()




