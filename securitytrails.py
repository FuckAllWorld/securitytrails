#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: FuckAllWorld

import requests,re
import sys

def main():
    print("*"*40+"\n" + "Usage:python securitytrails.py google.com"+"\n"+"*"*40)

def mx(domain,body):
    list = {}
    mx_tmp =[]
    url = "https://securitytrails.com/domain/{}/dns".format(domain)
    r = requests.get(url)
    mx_regxp = re.findall("<a href=\"/list/mx/(.*?)\"",body)
    print("MX Records:")
    for i in mx_regxp:
        print(i)
    for mxlist in mx_regxp:
        if "page" not in mxlist:
            url = "https://securitytrails.com/list/mx/{}".format(mxlist)
            r = requests.get(url)
            mx_regxp = re.findall("<a href=\"/domain/.*?/dns\">(.*?)</a>",r.content.decode("utf-8"))
            count = 0
            while True:
                count += 1
                url = "https://securitytrails.com/list/mx/{}?page={}".format(mxlist,count)
                r = requests.get(url)
                print(r.url)
                mx_regxp = re.findall("<a href=\"/domain/.*?/dns\">(.*?)</a>",r.content.decode("utf-8"))
                for ii in mx_regxp:
                    mx_tmp.append(ii)
                if mx_regxp !=[]:
                    list[mxlist] = mx_regxp
                else:
                    break
    mx_set = set(mx_tmp)
    for i in mx_set:
        mxfile = open("mx.txt","a+")
        mxfile.write(i+"\n")
    mxfile.close()

def nx():
    list = {}
    ns_tmp = []
    url = "https://securitytrails.com/domain/{}/dns".format(domain)
    r = requests.get(url)
    ns_regxp = re.findall("<a href=\"/list/ns/(.*?)\"",body)
    print("NS Records:")
    for i in ns_regxp:
        print(i)
    for nslist in ns_regxp:
        if "page" not in nslist:
            url = "https://securitytrails.com/list/ns/{}".format(nslist)
            r = requests.get(url)
            ns_regxp = re.findall("<a href=\"/domain/.*?/dns\">(.*?)</a>",r.content.decode("utf-8"))
            count = 0
            while True:
                count += 1
                url = "https://securitytrails.com/list/ns/{}?page={}".format(nslist,count)
                r = requests.get(url)
                print(r.url)
                ns_regxp = re.findall("<a href=\"/domain/.*?/dns\">(.*?)</a>",r.content.decode("utf-8"))
                for ii in ns_regxp:
                    ns_tmp.append(ii)
                if ns_regxp !=[]:
                    list[nslist] = ns_regxp
                else:
                    break
    ns_set = set(ns_tmp)
    for i in ns_set:
        nsfile = open("ns.txt","a+")
        nsfile.write(i+"\n")
    nsfile.close()

def subdomain():
    list = []
    url = "https://securitytrails.com/list/apex_domain/{}".format(domain)
    r = requests.get(url)
    count = 0
    while True:
        count += 1
        url = "https://securitytrails.com/list/apex_domain/{}?page={}".format(domain,count)
        r = requests.get(url)
        print(r.url)
        sub_regxp = re.findall("<a href=\"/domain/.*?/dns\">(.*?)</a>", r.content.decode("utf-8"))
        if sub_regxp != []:
            list.append(sub_regxp)
        else:
            break
    return list


def get(domain):
    url = "https://securitytrails.com/domain/{}/dns".format(domain)
    r = requests.get(url)
    body = r.content
    return body.decode("utf-8")

if __name__ == "__main__":
    main()
    domain = sys.argv[1]
    body = get(domain)
    res_mx = mx(domain,body)
    res_nx = nx()
    print("*" * 40 + "\n" + "Result in current floder ns.txt && mx.txt" + "\n" + "*" * 40)