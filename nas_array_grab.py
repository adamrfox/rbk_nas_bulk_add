#!/usr/bin/Python

import sys
import getopt
import getpass
import socket
sys.path.append('./NetApp')
from NaServer import *

def usage():
    print "Usage info goes here"
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
    svm_share_list = []
    addr = ""
    hostname = {}
    host_lookup = ()


    netapp = NaServer(host, 1, 15)
    out = netapp.set_transport_type('HTTPS')
    ntap_set_err_check(out)
    out = netapp.set_style('LOGIN')
    ntap_set_err_check(out)
    out = netapp.set_admin_user(user, password)
    ntap_set_err_check(out)
    result = netapp.invoke('vserver-get-iter')
    ntap_invoke_err_check(result)
#    print result.sprintf()
    vs_info = result.child_get('attributes-list').children_get()
    for vs in vs_info:
        vs_type = vs.child_get_string("vserver-type")
        if vs_type == "data":
            svm_list.append(vs.child_get_string('vserver-name'))
    result = netapp.invoke('net-interface-get-iter')
    ntap_invoke_err_check(result)
    ints = result.child_get('attributes-list').children_get()
    for i in ints:
        if interface:
            if i.child_get_string('interface-name') not in interface:
                continue
        protocols = i.child_get('data-protocols').children_get()
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
                    break
                except socket.herror:
                    hostname[svm] = addr
                    break
        if hostname:
            break
    for svm in svm_list:
        if do_svms and svm not in do_svms:
            continue
        out = netapp.set_vserver(svm)
        if protocol == "nfs":
            result = netapp.invoke('nfs-exportfs-list-rules')
            ntap_invoke_err_check(result)
            exports = result.child_get('rules').children_get()
            for ex in exports:
                path = ex.child_get_string('pathname')
                if path == "/" or path.startswith("/vol/"):
                    continue
                svm_share_list.append(path)
        elif protocol == "cifs" or protocol == "smb":
            result = netapp.invoke('cifs-share-get-iter')
            ntap_invoke_err_check(result)
            attr = result.child_get('attributes-list').children_get()
            for sh in attr:
                path = sh.child_get_string('path')
                if path == "/":
                    continue
                svm_share_list.append(sh.child_get_string('share-name'))
        share_list[hostname[svm]] = svm_share_list
    return (share_list)




if __name__ == "__main__":
    user = ""
    password = ""
    verbose = False
    do_svm_list = []
    protocol = ""
    delim = ":"
    share_list = {}
    interface_list = []


    optlist, args = getopt.getopt(sys.argv[1:], 'hvc:s:p:d:i:', ['help', 'verbose', 'creds=', 'svm=', 'protocol=', 'delim=', 'interface='])
    for opt, a in optlist:
        if opt in ('-h', "--help"):
            usage()
        if opt in ('-v', "--verbose"):
            verbose = True
        if opt in ('-c', "--creds"):
            (user, password) = a.split(':')
        if opt in ('-s', ":--svm"):
            do_svm_list = a.split(',')
        if opt in ('-p', "--protocol"):
            protocol = a
        if opt in ('-d', "--delim"):
            delim = a
        if opt in ('-i', "--interface"):
            interface_list = a.split(',')

    array = args[0]
    host = args[1]
    if user == "":
        raw_input("User: ")
    if password == "":
        password = getpass.getpass("Password: ")
    if array == "ntap" or array == "netapp":
        share_list = ntap_get_share_list (host, user, password, protocol, interface_list, do_svm_list)
    print share_list

