#!/usr/bin/env python
#coding=utf-8

import logging
from dpkt.tftp import ENOSPACE

# silence these loggers
logging.getLogger().setLevel("CRITICAL")
logging.getLogger("driller.fuzz").setLevel("INFO")

l = logging.getLogger("driller")
l.setLevel("INFO")

import os
import sys
import redis
import driller.tasks
import driller.config as config
import shutil

'''
Large scale test script. Should just require pointing it at a directory full of binaries.
'''

#def start(binary_dir):
def start(afl_engine):
    #配置好了目标程序的目录
    name_path="/home/xiaosatianyu/infomation/git-2/lava_corpus/lava_corpus/LAVA-1/branches.txt"
    f=open(name_path,'r')
    
    for line in f.readlines():
        target_path="file-5.22."+line.strip('\n') #去掉 '\n'
        target_path=os.path.join(os.path.dirname(name_path),target_path,"lava-install/bin")
        if not os.path.exists(target_path):
            l.warn("error, there is no %s",target_path)
        jobs = [ ]
        binary_dir=target_path #目标程序的目录
        binaries = os.listdir(binary_dir)
        
        for binary in binaries: #遍历多个目标程序, 这里是程序名称
            if binary.startswith("."):
                continue 
            pathed_binary = os.path.join(binary_dir, binary) #生成目标完整路径
            if os.path.isdir(pathed_binary):
                continue
            if not os.access(pathed_binary, os.X_OK):
                continue
            #往任务中添加目标程序
            identifier = binary  
            jobs.append(pathed_binary) 
        
    input_from="file" # the parameter to indicate the where does the input come from, stdin or file
    afl_input_para=["@@"] # #such as ["@@", "/tmp/shelfish"]
    l.info("%d binaries found", len(jobs))
    #l.debug("binaries: %r", jobs)

    # send all the binaries to the celery queue 任务调度器
    filter_t = set()  #可能记录已经被破解的程序
    jobs = filter(lambda j: j not in filter_t, jobs) #过滤出没有破解的程序

    l.info("going to work on %d", len(jobs))

    for binary_path in jobs:     #这里是clery下 task模块中的delay函数
        #driller.tasks.fuzz.delay(binary) #这里的delay是对fuzz这个函数用的 是celery的函数
        driller.tasks.fuzz(binary_path,input_from,afl_input_para,afl_engine) #这里的delay是对fuzz这个函数用的 是celery的函数

    l.info("listening for crashes..")

    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
    p = redis_inst.pubsub() #这是一个订阅发布器
    p.subscribe("crashes") #订阅 crashed 频道, 在fuzz函数中发射的

    cnt = 1
    for msg in p.listen():
        if msg['type'] == 'message':
            l.info("[%03d/%03d] crash found for '%s'", cnt, len(jobs), msg['data'])
            cnt += 1

#挖掘file类型
def main(argv):
    fast_mode=argv[1] 
    if fast_mode=='0':
        fast_mode=False
    else:
        fast_mode=True        
    start(fast_mode)
    
    
if __name__ == "__main__":
    sys.exit(main(sys.argv))
