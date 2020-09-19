#!/usr/bin/env python3
"""
Beta Version:

Reads the directory passed and then subfolders looking for dionaea bistream files to interpret and create json for syslog to pass to logstash

"""

__author__      = "Jesse G. Lands"
__email__       = "jesselands@jesselands.com"
__github__      =

import sys,os,time
from os import listdir
from os.path import isfile, join
from pathlib import Path
import json

path = sys.argv[1]

list_subfolders = [f.path for f in os.scandir(path) if f.is_dir()]

for directory in list_subfolders:
        #print(directory)
        onlyfiles = [f for f in listdir(directory) if isfile(join(directory, f))]

        for filelisted in onlyfiles:
                values = filelisted.split('-',1)
                for attack in values:
                        if "-" in attack:
                                honeypotip = attack.split('-',1)
                                dstip = '"dst_ip":"{}",'.format(honeypotip[0])
                                listed = str(honeypotip[1])
                                listed = listed.split('-')
                                srcip = '"src_ip":"{}",'.format(listed[1])
                                dstport = '"dst_port":"{}",'.format(listed[0])
                                year = listed[3]
                                month = listed[4]
                                daytime = listed[5]
                                timestamp = '"timestamp":"{}-{}-{}",'.format(year,month,daytime)
                        else:
                                protocol = '"protocol":"{}",'.format(attack)

                filelisted = os.path.join(directory, filelisted)
                f = open(filelisted,"r").read()

                f = json.dumps(f)  #formats the contents of the file in JSON validated manner
                request = '"request":{}'.format(f)
                print("{",protocol, dstip, srcip, dstport,timestamp,request,"}")
                os.remove(filelisted)
