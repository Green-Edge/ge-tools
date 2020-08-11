#!/usr/bin/python3
# ---------------------------
# (C) 2020 by Herby
#
# V 1.0

import requests
import json
import sys
import time
#import argparse
# import os

# URLs
base_url    = "https://explorer.grid.tf/explorer/"
farms_url   = base_url + "farms?page="
gw_url      = base_url +"gateways?page="
nodes_url   = base_url + "nodes?page="
res_url     = base_url + "reservations?page="

ts_now = time.time()

def get_from_tf(url):
    p=1
    tf = []
    while 1:
        resp = requests.get(url+str(p))
        r = resp.json()
        if len(resp.text) == 3:
            break
        for a in r:
            tf.append(a)
        p += 1
    return (tf)

nodes = get_from_tf(nodes_url)
farms = get_from_tf(farms_url)
res = get_from_tf(res_url)
gw = get_from_tf(gw_url)

farmer = []
for f in farms:
    farmer.append({
        'id':f['id'],
        'name':f['name'],
        'cnt':0,
        'online' : 0
        })

ni=0
for n in nodes:
    ni += 1
    fid = n['farm_id']
    for f in farmer:
        if f['id'] == fid:
            f['cnt'] += 1
            if ts_now < n['updated']+60*10:
                f['online'] += 1

fi = 0
oi = 0
ci = 0
print ('id','\t','on','\t','cnt','\t','name')
for f in farmer:
    fi += 1
    oi += f['online']
    ci += f['cnt']
    print (f['id'],'\t',f['online'],'\t',f['cnt'],'\t',f['name'])

print (fi,'\t',oi,'\t',ci)
