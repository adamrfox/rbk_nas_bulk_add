#!/usr/bin/python

import sys
import getopt
import getpass
import socket
import isi_sdk_8_0
from isi_sdk_8_0.rest import ApiException
import urllib3
urllib3.disable_warnings()
sys.path.append('./NetApp')
from NaServer import *

def usage():
    sys.stderr.write("Usage: nas_array_grab.py -p protocol [-h] [-o outfile] [-c creds] [-s svm] [-d delim] [-i interface] [-s svm] [-z zone] [-S sc_zone] array hostname\n")
    sys.stderr.write("\n-h | --help : Prints this message\n")
    sys.stderr.write("-p | --protocol= : Specify the protocol nfs or smb|cifs.  This flag is required\n")
    sys.stderr.write("-o | --output= : Sends data to the file specified.  By default, data goes to stdout\n")
    sys.stderr.write("-c | --creds= : Specify user credentials in the format user:password.  This is not secure\n")
    sys.stderr.write("-d | --delim= : Specify a delimiter for outout.  Default is ':'\n")
    sys.stderr.write("-s | --swm= :  Don't auto-discover SVMs, only pull data from a comma-separated list of NetApp SVMs.  [NetApp Only]\n")
    sys.stderr.write("-i | --interface= : Don't auto-discover interfaces, use the interfaces here comma-separated.  [NetApp Only]\n")
    sys.stderr.write("-z | --access_zones= : Don't auto-discover access zones.  Only pulll from a comma-separated list. [Isilon Only]\n")
    sys.stderr.write("-S | --sc_zones= : Don't auto-discover SmartConnect Zone names.  Only pull from a comma-separated list. [Isilon Only]\n")
    sys.stderr.write("array : Specify the array type: isilon|isln or netapp|ntap\n")
    sys.stderr.write("hostname : Specify the hostname of the array.  [Isilon: System Zone] [NetApp: Cluster Management\n")
    exit(0)

def ntap_set_err_check(out):
    if(out and (out.results_errno() != 0)) :
        r = out.results_reason()
        print("Connection to filer failed" + r + "\n")
        sys.exit(2)

def ntap_invoke_err_check(out):
    if(out.results_status() == "failed"):
            print(out.results_reason() + "\n")
            sys.exit(2)

def ntap_get_share_list(host, user, password, protocol, interface, do_svms):
    svm_list = []
    addr = ""
    hostname = {}
    host_lookup = ()

# Set up NetApp API session

    netapp = NaServer(host, 1, 15)
    out = netapp.set_transport_type('HTTPS')
    ntap_set_err_check(out)
    out = netapp.set_style('LOGIN')
    ntap_set_err_check(out)
    out = netapp.set_admin_user(user, password)
    ntap_set_err_check(out)

# Get list of SVMs from NetApp

    result = netapp.invoke('vserver-get-iter')
    ntap_invoke_err_check(result)
    vs_info = result.child_get('attributes-list').children_get()
    for vs in vs_info:
        vs_type = vs.child_get_string("vserver-type")
        if vs_type == "data":
            svm_list.append(vs.child_get_string('vserver-name'))

# Get list of interfaces on the NetApp.  Find the an applicable interface, grab the IP,
# then try to get a hostname from it via DNS

    result = netapp.invoke('net-interface-get-iter')
    ntap_invoke_err_check(result)
    ints = result.child_get('attributes-list').children_get()
    for i in ints:
        if interface:
            if i.child_get_string('interface-name') not in interface:
                continue
        protocols = i.child_get('data-protocols').children_get()

# Couldn't figure out how to pull the protocols properly, nasty hack.  Should clean up later

        for p in protocols:
            proto = p.sprintf()
            proto = proto.replace('<', '>')
            pf = proto.split('>')
            if pf[2] == protocol or (pf[2] == "cifs" and protocol == "smb"):
                svm = i.child_get_string('vserver')
                addr = i.child_get_string('address')
                try:
                    host_lookup = socket.gethostbyaddr(addr)
                    hostname[svm] = host_lookup[0]
                except socket.herror:
                    hostname[svm] = addr

# For each SVM, grab the NFS exports of SMB shares.  Generate the share_list structure for main()

    for svm in svm_list:
        svm_share_list = []
        if do_svms and svm not in do_svms:
            continue
        out = netapp.set_vserver(svm)
        if protocol == "nfs":
            result = netapp.invoke('nfs-exportfs-list-rules')
            ntap_invoke_err_check(result)
            exports = result.child_get('rules').children_get()
            for ex in exports:
                path = ex.child_get_string('pathname')
                if path == "/" or path.startswith("/vol/"):     # Exclude root volumes
                    continue
                svm_share_list.append(path)
        elif protocol == "cifs" or protocol == "smb":
            result = netapp.invoke('cifs-share-get-iter')
            ntap_invoke_err_check(result)
            attr = result.child_get('attributes-list').children_get()
            for sh in attr:
                path = sh.child_get_string('path')
                if path == "/":                                 # Exclude root volumes
                    continue
                svm_share_list.append(sh.child_get_string('share-name'))
        share_list[hostname[svm]] = svm_share_list
    return (share_list)

def isln_get_share_list(host, user, password, protocol, sc_zone_list, az_list):
    hostname = {}
    aliases = {}

# Set up Isilon API Session

    configuration = isi_sdk_8_0.Configuration()
    configuration.host = "https://" + host + ":8080"
    configuration.username = user
    configuration.password = password
    configuration.verify_ssl = False
    isilon = isi_sdk_8_0.ApiClient(configuration)

# Generate Access Zone list if not given on CLI

    if not az_list:
        isilon_zones = isi_sdk_8_0.ZonesApi(isilon)
        try:
            result = isilon_zones.list_zones()
        except ApiException as e:
            sys.stderr.write("Error calling list_zones: " + str(e) + "\n")
            exit (1)
        for z in result.zones:
            az_list.append(z.name)

# Look at Network pools, find an applicable pool for each access zone.  Grab the SC Zone name if available

    isilon_network = isi_sdk_8_0.NetworkApi(isilon)
    try:
         result_pools = isilon_network.get_network_pools()
    except ApiException as e:
        sys.stderr.write("Error calling network_pools: " + str(e) + "\n")
        exit(1)
    if sc_zone_list:
        for p in result_pools.pools:
            if p.sc_dns_zone in sc_zone_list:
                hostname[p.access_zone] = p.sc_dns_zone
    for p in result_pools.pools:
        if p.access_zone in hostname.keys():
            continue
        if p.sc_dns_zone:
            hostname[p.access_zone] = p.sc_dns_zone
        else:
            hostname[p.access_zone] = p.ranges[0].low

# For each access zone, grab the NFS exports or SMB shares.  Generate the share_list structure for main()

    for zone in az_list:
        alias_instance = ()
        al_list = []
        zone_share_list = []
        isilon_protocols = isi_sdk_8_0.ProtocolsApi(isilon)
        if protocol == "nfs":
            try:
                result_aliases = isilon_protocols.list_nfs_aliases(zone=zone)
            except ApiException as e:
                sys.stderr.write("Error calling nfs_aliases: " + str(e) + "\n")
                exit(1)
            for alias in result_aliases.aliases:
                alias_instance = (alias.name, alias.path)
                al_list.append(alias_instance)
            try:
                results_exports = isilon_protocols.list_nfs_exports(zone=zone)
            except ApiException as e:
                sys.stderr.write("Error calling nfs_exports: " + str(e) + "\n")
                exit(1)
            for x in results_exports.exports:
                for p in x.paths:
                    if p == "/ifs":                         # Exclude a root export
                        continue
                    found_alias = False
                    for a in al_list:
                        if p in a:
                            zone_share_list.append(a[0])
                            found_alias = True
                    if not found_alias:
                        zone_share_list.append(p)
        elif protocol == "smb" or protocol == "cifs":
            try:
                results_exports = isilon_protocols.list_smb_shares(zone=zone)
            except ApiException as e:
                sys.stderr.write("Error calling smb_shares: " + str(e) + "\n")
                exit(1)
            for x in results_exports.shares:
                if x.path == "/ifs":                        # Exclude any /ifs root shares
                    continue
                zone_share_list.append(x.name)

        share_list[hostname[zone]] = zone_share_list
    return (share_list)

def get_creds_from_file(file):
    with open(file) as fp:
        data = fp.read()
    fp.close()
    data = data.decode('uu_codec')
    data = data.decode('rot13')
    lines = data.splitlines()
    (user, password) = lines[0].split(':')
    return (user, password)


if __name__ == "__main__":
    user = ""
    password = ""
    verbose = False
    do_svm_list = []
    protocol = ""
    delim = ":"
    share_list = {}
    interface_list = []
    sc_zone_list = []
    az_list = []
    outfile = ""
    DEBUG = False

# Process arguments using getopt

    optlist, args = getopt.getopt(sys.argv[1:], 'hc:s:p:d:i:z:S:o:D', ['help', 'creds=', 'svm=', 'protocol=', 'delim=', 'interface=', 'access_zones=', 'sc_zones=', 'output', 'debug'])
    for opt, a in optlist:
        if opt in ('-h', "--help"):
            usage()
        if opt in ('-v', "--verbose"):
            verbose = True
        if opt in ('-c', "--creds"):
            if ':' in a:
                (user, password) = a.split(':')
            else:
                (user, password) = get_creds_from_file(a)
        if opt in ('-s', "--svm"):
            do_svm_list = a.split(',')
        if opt in ('-p', "--protocol"):
            protocol = a
        if opt in ('-d', "--delim"):
            delim = a
        if opt in ('-i', "--interface"):
            interface_list = a.split(',')
        if opt in ('-z', "--access_zones"):
            az_list = a.split(',')
        if opt in ('-S', "--sc_zones"):
            sc_zone_list = a.split(',')
        if opt in ('-o', "--output"):
            outfile = a
        if opt in ('-D', "--debug"):
            DEBUG = True
            verbose = True

    array = args[0]
    host = args[1]

# Prompt for user and password if not provided via -c

    if user == "":
        user = raw_input("User: ")
    if password == "":
        password = getpass.getpass("Password: ")

    if DEBUG:
        print "User: " + user
        print "Password: " + password

# Generate a list of shares based on the APIs for each array

    if array == "ntap" or array == "netapp":
        share_list = ntap_get_share_list (host, user, password, protocol, interface_list, do_svm_list)
    if array == "isln" or array == "isilon":
        share_list = isln_get_share_list(host, user, password, protocol, sc_zone_list, az_list)

# Write the results of the share list to the screen or a file

    if outfile:
        fp = open (outfile, "w")
    for host in share_list.keys():
        for share in share_list[host]:
            line = host + delim + share
            if outfile:
                fp.write(line + "\n")
            else:
                print line
    if outfile:
        fp.close()
