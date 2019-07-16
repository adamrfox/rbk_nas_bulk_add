#!/usr/bin/python

import rubrik_cdm
import sys
import getopt
import getpass
import socket
import netaddr
import isi_sdk_8_0
from isi_sdk_8_0.rest import ApiException
import urllib3
urllib3.disable_warnings()

def usage():
    sys.stderr.write ("Usage: rbk_nas_bulk_add.py -i file [-hvDC] [-d 'delim'] [-c user:passwd] [-f fileset] [-s sla] [-e array] rubrik\n")
    sys.stderr.write("-h | --help : Prints this message\n")
    sys.stderr.write("-i | --input= : Specifies the input file for hosts and shares\n")
    sys.stderr.write("-v | --verbose : Verbose output\n")
    sys.stderr.write("-D | --direct_archive : Use Direct Archive\n")
    sys.stderr.write("-C | --cleanup : Delete shares in the list instead of add\n")
    sys.stderr.write("-d | --delim= : Set the delimiter in the input file. ':' is the default\n")
    sys.stderr.write("-c | --creds= : Specify the Rubrik credentials instead of being prompted.  This is not secure\n")
    sys.stderr.write("-f | --fileset= : Assign each share to this fileset\n")
    sys.stderr.write("-s | --sla= : Assign an SLA to each share in this fileset.  Must be used with -f\n")
    sys.stderr.write("-e | --add_exports= : Add the Rubrik's IP to the Isilon Exports.  Supply a System Zone name/IP\n")
    sys.stderr.write("-r | --run_as_root= : Add a user or group to the Isilon share with run_as_root.  Format is user|group:name.  Use with -e\n")
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

def build_new_rc_list(rc_list, addr_list):
    for addr in addr_list:
        if addr not in rc_list:
            rc_list.append(addr)
    new_root_clinets = {'root_clients': rc_list}
    return (new_root_clinets)

def get_creds_from_file(file):
    with open(file) as fp:
        data = fp.read()
    fp.close()
    data = data.decode('uu_codec')
    data = data.decode('rot13')
    lines = data.splitlines()
    (user, password) = lines[0].split(':')
    try:
        (isln_user, isln_password) = lines[1].split(':')
    except IndexError:
        isln_user = ""
        isln_password = ""
    return (user, password, isln_user, isln_password)


class Exports():
    def __init__(self, zone, aliases, ex_id, root_clients):
        self.zone = zone
        self.aliases = aliases
        self.id_list = ex_id
        self.root_clients = root_clients



if __name__ == "__main__":
    user = ""
    password = ""
    isln_user = ""
    isln_password = ""
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
    add_exports_host = ""
    addr_list = []
    exports = {}
    run_as_root_user = ""

    optlist,args = getopt.getopt (sys.argv[1:], 'hi:c:d:f:s:vDCI:e:r:', ["--help", "input=", "--creds=", "--delim=", "--fileset=", "--sla=", "--verbose", "--direct_archive", "--cleanup", "--isln_creds", "--add_exports", "--run_as_root="])
    for opt,a in optlist:
        if opt in ('-h', "--help"):
            usage()
        if opt in ('-i', "--input"):
            file = a
        if opt in ('-c', "--creds"):
            if ':' in a:
                (user, password) = a.split(':')
            else:
                (user, password, isln_user, isln_password) = get_creds_from_file(a)
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
        if opt in ('-I', "--isln_creds"):
            (isln_user, isln_password) = a.aplit(':')
        if opt in ('-e', "--add_exports"):
            add_exports_host = a
        if opt in ('-r', "--run_as_root"):
            run_as_root_user = a

    rubrik_cluster = args[0]
    if rubrik_cluster == "?":
        usage()
    if file == "":
        sys.stderr.write("ERROR: A file must be specified. (use the -i flag)\n")
        exit(1)
# Get Credentials if not on CLI
    if user == "":
        user = raw_input("User: ")
    if password == "":
        password = getpass.getpass("Password: ")
    if add_exports_host != "" and isln_user == "":
        isln_user = raw_input("Array User: ")
    if add_exports_host != "" and isln_password == "":
        isln_password = getpass.getpass("Array Password: ")
# Read the input file
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
# If we are going to add exports to NFS, grab the IP addresses on the Rubrik
    if add_exports_host != "":
        configuration = isi_sdk_8_0.Configuration()
        endpoint = "/cluster/me/network_interface"
        rubrik_net = rubrik.get('internal', endpoint, timeout=time_out)
        for n in rubrik_net['data']:
            for i in n['ipAddresses']:
                addr_list.append(i)
# Get the Fileset Template ID
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
# Get SLA Domain ID (only bother if fileset is being used)
        if sla_domain != "":
            sla_data = get_sla_data(rubrik, version_maj, time_out)
            for sld in sla_data['data']:
                if sld['name'] == sla_domain:
                    sla_id = sld['id']
                    break
            if sla_id == "":
                sys.stderr.write("Can't find SLA: " + sla_domain + "\n")
                exit (3)
# Get list of existing shares
    rubrik_shares = rubrik.get('internal', '/host/share', timeout=time_out)
    for host_share in rubrik_shares['data']:
        host = host_share['hostname']
        share_name = host_share['exportPoint']
        share = (host, share_name)
        existing_shares.append(share)
    get_params = {"operating_system_type": "NONE", "primary_cluster_id": "local"}
# Get List of host IDs defined on Rubrik
    rubrik_hosts = rubrik.get('v1', "/host", params=get_params, timeout=time_out)
    for host in rubrik_hosts['data']:
        host_id[host['hostname']] = host['id']
# For each share in the file not already on Rubrik, add the share.
# Add that share to the fileset and SLA if requested
    for sh in share_list:
        if not sh in existing_shares:
            vprint("Adding " + sh[0] + ":" + sh[1])
            if sh[1].startswith("/"):
                share_type = "NFS"
            else:
                share_type = "SMB"
# If selected, add Rubrik IPs to Array (Isilon)
            if add_exports_host != "" and share_type == "NFS":
                vprint("   Adding Rubrik IPs to Array")
                if sh[0] not in exports.keys():
                    zone = ""
                    alias = ()
                    ex_list = []
                    export_list = {}
                    ex_instance = []
                    alias_list = []
                    export_id = {}
                    configuration.host = "https://" + add_exports_host + ":8080"
                    configuration.username = isln_user
                    configuration.password = isln_password
                    configuration.verify_ssl = False
                    isilon = isi_sdk_8_0.ApiClient(configuration)
                    addr = socket.gethostbyname(sh[0])
                    isilon_network = isi_sdk_8_0.NetworkApi(isilon)
                    net_results = isilon_network.get_network_pools()
                    for p in net_results.pools:
                        for r in p.ranges:
                            ip_range = list(netaddr.iter_iprange(r.low,r.high))
                            if netaddr.IPAddress(addr) in ip_range:
                                zone = p.access_zone
                                break
                    isilon_protocols = isi_sdk_8_0.ProtocolsApi(isilon)
                    alias_results = isilon_protocols.list_nfs_aliases(zone=zone)
                    for a in alias_results.aliases:
                        alias = (a.name,a.path)
                        alias_list.append(alias)
                    exports_results = isilon_protocols.list_nfs_exports(zone=zone)
                    for ex in exports_results.exports:
                        ex_instance = (ex.paths[0],ex.root_clients)
                        ex_list.append(ex_instance)
                        export_id[ex.paths[0]] = ex.id
                    exports[sh[0]] = Exports(zone, alias_list, export_list, ex_list)
                path = sh[1]
                for a in exports[sh[0]].aliases:
                    if sh[1] in a:
                        path = a[1]
                        break
                found = False
                for rc in exports[sh[0]].root_clients:
                    if path in rc:
                        found = True
                        rc_list = rc
                        break
                if not found:
                    sys.stderr.write("Can't find " + sh[0] + ":" + path + "\n")
                    exit(3)
                rc_new = build_new_rc_list (rc_list[1], addr_list)
                try:
                    exports_results = isilon_protocols.update_nfs_export(rc_new, export_id[path], zone=zone)
                except ApiException as e:
                    sys.stderr.write("Exception calling update_nfs_export: " + str(e))
                    exit(4)
# If selected add the 'run as root' to the Isilon
            if run_as_root_user != "" and share_type == "SMB":
                (rar_type, rar_user) = run_as_root_user.split(':')
                vprint("   Adding run_as_root " + rar_type + " to share")
                zone = ""
                configuration.host = "https://" + add_exports_host + ":8080"
                configuration.username = isln_user
                configuration.password = isln_password
                configuration.verify_ssl = False
                isilon = isi_sdk_8_0.ApiClient(configuration)
                addr = socket.gethostbyname(sh[0])
                isilon_network = isi_sdk_8_0.NetworkApi(isilon)
                net_results = isilon_network.get_network_pools()
                for p in net_results.pools:
                    for r in p.ranges:
                        ip_range = list(netaddr.iter_iprange(r.low, r.high))
                        if netaddr.IPAddress(addr) in ip_range:
                            zone = p.access_zone
                            break
                isilon_protocols = isi_sdk_8_0.ProtocolsApi(isilon)
                share_results = isilon_protocols.get_smb_share(sh[1], zone=zone)
                add_rar = True
                for sh_data in share_results.shares:
                    for rar in sh_data.run_as_root:
                        if rar.type == rar_type and rar.name == rar_user:
                            add_rar = False
                            break
                if add_rar:
                    new_rar_data = {'type': rar_type, 'name': rar_user}
                    sh_data.run_as_root.append(new_rar_data)
                    new_rar = {'run_as_root': sh_data.run_as_root}
                    share_update = isilon_protocols.update_smb_share(new_rar, sh[1], zone=zone)
                    fix_perms = {'permissions': sh_data.permissions}
                    share_update = isilon_protocols.update_smb_share(fix_perms, sh[1], zone=zone)
            payload = {"hostId": host_id[sh[0]], "exportPoint": sh[1], "shareType": share_type}
#            print payload
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








