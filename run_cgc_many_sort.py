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


'''
Large scale test script. Should just require pointing it at a directory full of binaries.
'''


#def start(binary_dir):
def start(binary,afl_engine):
    #针对cgc程序
    binary_dir=config.BINARY_DIR_CGC #yyy
    jobs = [ ]
    jobs_input_sort = [ ]
    binaries = os.listdir(binary_dir)
    if binary is not None: #这里配置单目标
        binaries=[binary] # handle
    
    #input_from="file" # the parameter to indicate the where does the input come from, stdin or file
    #afl_input_para=["@@"] # #such as ["@@", "/tmp/shelfish"]
    
    input_from="stdin" # the parameter to indicate the where does the input come from, stdin or file
    afl_input_para=[] # #such as ["@@", "/tmp/shelfish"]
    binaries.sort()
    for binary in binaries: #遍历多个目标程序, 这里是程序名称
        if binary.startswith("."):
            continue 

        pathed_binary = os.path.join(binary_dir, binary) #生成目标完整路径
        if os.path.isdir(pathed_binary):
            continue
        if not os.access(pathed_binary, os.X_OK):
            continue
        
        ##annotation by yyy------------------------
        #去掉'_'后缀的内容
#         identifier = binary[:binary.rindex("_")]  #rindex表示 返回第一个'_'符号的下标 没有'_'就会出错
#         # remove IPC binaries from largescale testing ; IPC binary 是什么
#         if (identifier + "_02") not in binaries:
#             jobs.append(binary) #添加没有'_02'后缀的程序
        ##end  ----------------------------------
        
        identifier = binary  
        if '-sort' in pathed_binary:
            jobs_input_sort.append(pathed_binary) #input sort对比对象的程序
        else:
            jobs.append(pathed_binary)  #正常的程序
        
    l.info("%d binaries found", len(jobs))
    l.debug("binaries: %r", jobs)

    # send all the binaries to the celery queue 任务调度器
    l.info("%d binaries found", len(jobs))

    filter_t = set()  #可能记录已经被破解的程序
    # yyy
#     try:
#         pwned = open("pwned").read()  #pwned是什么 打开一个文件?
#         for pwn in pwned.split("\n")[:-1]:
#             filter_t.add(pwn)
#         l.info("already pwned %d", len(filter_t))
#     except IOError:
#         pass
    # yyy
    jobs = filter(lambda j: j not in filter_t, jobs) #过滤出没有破解的程序
    jobs.sort()
    l.info("going to work on %d", len(jobs))

    for binary_path in jobs:     #这里是clery下 task模块中的delay函数
        #driller.tasks.fuzz.delay(binary_path,input_from,afl_input_para,afl_engine) #这里的delay是对fuzz这个函数用的 是celery的函数
        driller.tasks.fuzz(binary_path+'-sort', input_from,afl_input_para,afl_engine,comapre_afl=False, inputs_sorted=True)

    l.info("listening for tasks..")

#     redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
#     p = redis_inst.pubsub() #这是一个订阅发布器
#     p.subscribe("crashes") #订阅 crashed 频道, 在fuzz函数中发射的
# 
#     cnt = 1
#     for msg in p.listen():
#         if msg['type'] == 'message':
#             l.info("[%03d/%03d] crash found for '%s'", cnt, len(jobs), msg['data'])
#             cnt += 1
      
    ##监听task完成情况
    redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)
    p = redis_inst.pubsub() #这是一个订阅发布器
    p.subscribe("tasks") #订阅 crashed 频道, 在fuzz函数中发射的
    
    for msg in p.listen():
        if msg['type'] == 'message':
            l.info("task: %s",msg['data'])      


  
def main(argv):
    ##annotation by yyy------------------------
#     if len(argv) < 2:
#         print "usage: %s <binary_dir>" % argv[0]
#         return 1
   
#     binary_dir = sys.argv[1] #这里的参数和config中的参数有什么区别?

#     start(binary_dir)
    
    #针对cgc程序
    
    binary=None
    if len(argv)<2:
        afl_engine="default"  ## fast yyy or default; default is shelfish-afl
    else:    
        afl_engine=argv[1] #"fast" "yyy"
            
    start(binary,afl_engine)
    ## end ---------------------
    
    
    
if __name__ == "__main__":
    
    sys.exit(main(sys.argv))
