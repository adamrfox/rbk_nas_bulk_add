#!/usr/bin/python

import rubrik_cdm
import sys
import getopt
import getpass
import urllib3
urllib3.disable_warnings()

def usage():
    sys.stderr.write ("Usage: rbk_nas_bulk_add.py -i file [-hvDC] [-d 'delim'] [-c user:passwd] [-f fileset] [-s sla] rubrik\n")
    sys.stderr.write("-h | --help : Prints this message\n")
    sys.stderr.write("-i | --input= : Specifies the input file for hosts and shares\n")
    sys.stderr.write("-v | --verbose : Verbose output\n")
    sys.stderr.write("-D | --direct_archive : Use Direct Archive\n")
    sys.stderr.write("-C | --cleanup : Delete shares in the list instead of add\n")
    sys.stderr.write("-d | --delim= : Set the delimiter in the input file. ':' is the default\n")
    sys.stderr.write("-c | --creds= : Specify the Rubrik credentials instead of being prompted.  This is not secure\n")
    sys.stderr.write("-f | --fileset= : Assign each share to this fileset\n")
    sys.stderr.write("-s | --sla= : Assign an SLA to each share in this fileset.  Must be used with -f\n")
    sys.stderr.write("rubrik : The hostname or IP address of the Rubrik\n")
    exit (0)

def vprint (message):
    if verbose:
        print message

def get_sla_data (rubrik, vers, time_out):
    if vers < 5:
        sla_data = rubrik.get('v1', "/sla_domain?primary_cluster=local", timeout=time_out)
    else:
        sla_data = rubrik.get('v2', "/sla_domain?primary_cluster=local", timeout=time_out)
    return (sla_data)

def cleanup(rubrik, share_list, time_out):
    rubrik_shares = rubrik.get("internal", "/host/share")
    for host_share in rubrik_shares['data']:
        if (host_share['hostname'], host_share['exportPoint']) in share_list:
            vprint("Deleting " + str(host_share['hostname']) + ":" + str(host_share['exportPoint']))
            endpoint = "/host/share/" + host_share['id']
            del_share = rubrik.delete('internal', str(endpoint), timeout=time_out)
    return()

if __name__ == "__main__":
    user = ""
    password = ""
    file = ""
    delim = ":"
    share_list = []
    existing_shares = []
    share = ()
    fileset = ""
    sla_domain = ""
    host_id = {}
    verbose = False
    fs_id = ""
    sla_id = ""
    direct_archive = False
    time_out = 60
    cleanup_flag = False

    optlist,args = getopt.getopt (sys.argv[1:], 'hi:c:d:f:s:vDC', ["--help", "input=", "--creds=", "--delim=", "--fileset=", "--sla=", "--verbose", "--direct_archive", "--cleanup"])
    for opt,a in optlist:
        if opt in ('-h', "--help"):
            usage()
        if opt in ('-i', "--input"):
            file = a
        if opt in ('-c', "--creds"):
            (user, password) = a.split(':')
        if opt in ('-d', "--delim"):
            delim = a
        if opt in ('-f', "--fileset"):
            fileset = a
        if opt in ('-s', "--sla"):
            sla_domain = a
        if opt in ('-v', "--verbose"):
            verbose = True
        if opt in ('-D', "--direct_archive"):
            direct_archive = True
        if opt in ('-C', "--cleanup"):
            cleanup_flag = True

    rubrik_cluster = args[0]
    if rubrik_cluster == "?":
        usage()
    if file == "":
        sys.stderr.write("ERROR: A file must be specified. (use the -i flag)\n")
        exit (1)
    if user == "":
        user = raw_input("User: ")
    if password == "":
        password = getpass.getpass("Password: ")
    with open(file) as fp:
        line = fp.readline()
        while line:
            (host, share_name) = line.split(delim)
            share = (host, share_name.rstrip())
            share_list.append(share)
            line = fp.readline()
    fp.close()
    rubrik = rubrik_cdm.Connect (rubrik_cluster, user, password)
    if cleanup_flag:
        cleanup(rubrik, share_list, time_out)
        exit(0)
    version = rubrik.cluster_version().split('.')
    version_maj = int(version[0])
    if fileset != "":
        endpoint = "/fileset_template?name=" + fileset
        rubrik_fs = rubrik.get('v1', endpoint, timeout=time_out)
        for fs in rubrik_fs['data']:
            if fs['name'] == fileset:
                fs_id = fs['id']
                break
        if fs_id == "":
            sys.stderr.write("Can't find fileset: " + fileset + "\n")
            exit(2)
    if sla_domain != "":
        sla_data = get_sla_data(rubrik, version_maj, time_out)
        for sld in sla_data['data']:
            if sld['name'] == sla_domain:
                sla_id = sld['id']
                break
        if sla_id == "":
            sys.stderr.write("Can't find SLA: " + sla_domain + "\n")
            exit (3)
    rubrik_shares = rubrik.get('internal', '/host/share', timeout=time_out)
    for host_share in rubrik_shares['data']:
        host = host_share['hostname']
        share_name = host_share['exportPoint']
        share = (host, share_name)
        existing_shares.append(share)
    get_params = {"operating_system_type": "NONE", "primary_cluster_id": "local"}
    rubrik_hosts = rubrik.get('v1', "/host", params=get_params, timeout=time_out)
    for host in rubrik_hosts['data']:
        host_id[host['name']] = host['id']
    for sh in share_list:
        if not sh in existing_shares:
            vprint("Adding " + sh[0] + ":" + sh[1])
            if sh[1].startswith("/"):
                share_type = "NFS"
            else:
                share_type = "SMB"
            payload = {"hostId": host_id[sh[0]], "exportPoint": sh[1], "shareType": share_type}
            share_id = rubrik.post('internal', '/host/share', payload)['id']
            if fileset != "":
                vprint("  Adding share to fileset")
                payload = {"shareId": share_id, "templateId": fs_id, "isPassthrough": direct_archive}
                fs_out = rubrik.post('v1', '/fileset', payload, timeout=time_out)
                new_fs_id = fs_out['id']
                if sla_domain != "":
                    vprint ("  Adding fileset to SLA")
                    endpoint = "/sla_domain/" + str(sla_id) + "/assign"
                    payload = {"managedIds": [ new_fs_id ]}
                    sla_out = rubrik.post('internal', endpoint, payload, timeout=time_out)
