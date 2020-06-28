#!/usr/bin/env python3
# coding: utf-8

import os
import requests
import random
import names
import argparse
import string
import time
import matplotlib.pyplot as plt
import numpy as np
import statistics as st

def gendata(n, seed, maxvalue) :
    print('Generating',n,'data values with seed',seed,'and max value',maxvalue)
    if verbose :
        print()
    random.seed(seed)
    # return random.choices(range(1, maxvalue+1), k=n) # random.choices is available in python3.6+
    return [random.choice(range(1, maxvalue+1)) for i in range(n)]

def collectstatspost(datalist,baseurl):
    print('Collecting stats by making post requests to',baseurl)
    if verbose :
        print()
    statslist = []
    i = 1
    for item in datalist :
        # payload = {'input':item}
        # body = '{"input":%d}'%(item)
        # body = 'input=%d'%(item)
        body = '%d'%(item)
        if verbose :
            print('Sending request')
        start = time.time()
        # response=requests.post(baseurl,json=payload)
        response=requests.post(url=baseurl,data=body)
        end = time.time()
        dur = round((end-start)*1000)
        if verbose :
            print('%03d'%(i)+'. ','Time Taken :',str(dur),'ms Response :',response.text.strip(),'for',item)
        statslist += [dur]
        i += 1
    if verbose :
        print()
    return statslist 

def collectstatspostcs(datalist,baseurl,filename):
    print('Collecting stats by making post requests to',baseurl)
    print('Saving stats in',filename)
    f = open(filename, 'a')
    if verbose :
        print()
    statslist = []
    i = 1
    for item in datalist :
        payload = {'input':item}
        print('ol starting')
        os.system('cd ~/Desktop/open-lambda && sudo ./ol worker -d')
        # time.sleep(10)
        # input()
        if verbose :
            print('Sending request')
        start = time.time()
        response=requests.post(baseurl,json=payload)
        end = time.time()
        response.close()
        time.sleep(1)
        # time.sleep(20)
        print('ol stopping')
        os.system('cd ~/Desktop/open-lambda && sudo ./ol kill')
        time.sleep(1)
        ii = 0
        while os.popen('sudo find /home/nbs/Desktop/open-lambda/default-ol/worker/worker.pid').read() and ii < 10:
            ii += 1
            print('Worker not dead yet, Sleeping for 1 second, File worker.pid is still present')
            os.system('cd ~/Desktop/open-lambda && sudo ./ol kill')
            time.sleep(1)
        if ii == 10 :
            f.write("%d\n"%(dur))
            f.close()
            exit()    
            # time.sleep(20)
            # input()
        dur = round((end-start)*1000)
        if verbose :
            print('%03d'%(i)+'. ','Time Taken :',str(dur),'ms Response :',response.text.strip(),'for',item)
        statslist += [dur]
        f.write("%d\n"%(dur))
        i += 1
    if verbose :
        print()
    f.close()
    return statslist

def loadstats(filename):
    print('Loading stats from',filename)
    if verbose :
        print()
    f = open(filename, 'r')
    statslist = []
    for line in f:
        if verbose :
            print(line.strip())
        #print(line)
        statslist += [int(line)] 
        #round function returns type as int by default (decimal places to keep is 0) otherwise float
    f.close()
    if verbose :
        print()
    return statslist    

def savestats(filename, statslist) :
    print('Saving stats in',filename)
    f = open(filename, 'w')
    #f.write('Actual Time (ms)\n')
    for item in statslist:
        f.write("%d\n"%(item))
    if verbose :
        print()
    f.close()

# def gengraph(data, labels) :
#     _, ax = plt.subplots()
#     pos = np.array(range(len(data))) + 1

#     bp = ax.boxplot(data, positions=pos,
#                     notch=1,
#                     labels = labels)

#     # ax.set_xlabel('Response Time for Multi-Tenant Systems')
#     ax.set_ylabel('Response Time (ms)')
#     plt.setp(bp['whiskers'], color='k', linestyle='-')
#     plt.setp(bp['fliers'], markersize=3.0)
#     axes = plt.gca()
#     axes.set_ylim([0,16])
#     # plt.title('Novo Isolates CGI Controller')
#     plt.show()

def gengraph(data, labels) :
    data = [round(st.mean(datalist)) for datalist in data]
    plt.xticks(range(len(data)), labels)
    # plt.xlabel('Class')
    plt.ylabel('Memory Used (KB)')
    # plt.title('I am title')
    plt.bar(range(len(data)), data, width=0.2) 
    plt.show()

# create the datalist
# make post requests
# save the stats
# do this for both isolcon and open-lambda
# merge the two stats
# create the graph


if __name__ == "__main__":
    # Following options :
    # gen data : filename // where it is to be put, automatically calls loaddata
    # load data : filename // same as above but only loading data
    # make post calls : baseurlpost and filename where to put stats // for making post calls
    # parse post stats : filename of ^^ stats, filename for parsing cloudwatch logs
    # make get calls : baseurlget and filename where to put stats // for making get calls
    # parse get stats : filename of ^^ stats, filename for parsing cloudwatch logs
    parser = argparse.ArgumentParser(description='Oracle for doing everything')
    # argument for datafile
    parser.add_argument('-v', '--verbose', help='Increase output verbosity', action='store_true')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-gr', '--generaterequests', nargs=5, help='Make POST requests : Number of requests, Initial seed, Maximum value, URL for Post, Filename for storing stats')
    group.add_argument('-grcs', '--generaterequestscold', nargs=5, help='Make POST requests for measuring cold starts : Number of requests, Initial seed, Maximum value, URL for Post, Filename for storing stats')
    group.add_argument('-gg', '--generategraphs', nargs=2, help='Generate graph : Filenames for stats comma separated, Names for these stats in the graph comma separated')
    args = parser.parse_args()
    
    global verbose
    verbose = args.verbose
    
    if args.generaterequests :
        rargs = args.generaterequests
        inputlist = gendata(int(rargs[0]), int(rargs[1]), int(rargs[2]))
        statslist = collectstatspost(inputlist, rargs[3])
        savestats(rargs[4], statslist)
    
    if args.generaterequestscold :
        rargs = args.generaterequestscold
        inputlist = gendata(int(rargs[0]), int(rargs[1]), int(rargs[2]))
        statslist = collectstatspostcs(inputlist, rargs[3], rargs[4])
    
    
    if args.generategraphs :
        gargs = args.generategraphs
        filenames = gargs[0].split(',')
        plotnames = gargs[1].split(',')
        stats = []
        for filename in filenames :
            stats.append(loadstats(filename))
        gengraph(stats, plotnames)