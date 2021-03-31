# get_smb_shares.py
#
# A quick script to get the shares from an SMB server for rbk_nas_bulk_add
# -- Adam Fox, adam.fox@rubrik.com
#
# Note: Must be run on Windows as the library to do this isn't available for UNIX
#
from __future__ import print_function

import win32net
import win32netcon
import sys
import getopt

outfile = ""
optlist, args = getopt.getopt(sys.argv[1:], 'o:', ['output='])
for opt, a in optlist:
  if opt in ('-o', '--output'):
    outfile = a
COMPUTER_NAME = args[0] # look at this machine
INFO_LEVEL = 2

if outfile:
  fp = open(outfile, "a+")

resume = 0
while 1:
  (shares, total, resume) = \
    win32net.NetShareEnum (
      COMPUTER_NAME,
      INFO_LEVEL,
      resume,
      win32netcon.MAX_PREFERRED_LENGTH
    )
  
  for share in shares:
    if not outfile:
      print(COMPUTER_NAME + ":" + share['netname'])
    else:
      fp.write(COMPUTER_NAME + ":" + share['netname'] + "\n")
  if not resume:
    break
if outfile:
  fp.close()