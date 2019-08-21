#!/usr/bin/python

import sys
import subprocess
import getopt

if __name__ == "__main__":
    outfile = ""
    done = False
    export_list = []

    optlist, args = getopt.getopt(sys.argv[1:], 'o:', ['--output='])
    for opt, a in optlist:
        if opt in ('-o', '--output'):
            outfile = a
    nfs_server = args[0]
    exportfs = subprocess.Popen(['showmount', '-e', nfs_server], stdout=subprocess.PIPE)
    while not done:
        line = exportfs.stdout.readline()
        if not line:
            done = True
        else:
            if not line.startswith("/"):
                continue
            lf = line.split()
            export_list.append(lf[0])
    if outfile:
        fp = open(outfile, "a")
    for x in export_list:
        if not outfile:
            print nfs_server + ":" + x
        else:
            fp.write(nfs_server + ":" + x + "\n")
    if outfile:
        fp.close()




