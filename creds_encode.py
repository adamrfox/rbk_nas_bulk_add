#!/usr/bin/python

import getpass
import sys


user_list = []
passwd = {}
i = -1
while True:
    i += 1
    user = raw_input("Enter User (blank if done): ")
    if user == "":
        break
    user_list.append(user)
    passwd[user] = getpass.getpass("Enter Password: ")
fp = open(sys.argv[1], "w")
data = ""
for x in user_list:
    ent_s = x + ":" + passwd[x] + "\n"
    data = data + ent_s
data = data.encode('rot13')
data = data.encode('uu_codec')
fp.write (data)
fp.close()
