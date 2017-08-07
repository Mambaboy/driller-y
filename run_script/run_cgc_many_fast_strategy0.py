#!/usr/bin/env python
#coding=utf-8

import logging
from dpkt.tftp import ENOSPACE
from networkx.algorithms.coloring.greedy_coloring import strategy_connected_sequential

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
def start(binary,afl_engine,strategy_id):
    #针对cgc程序
    binary_dir=config.BINARY_DIR_CGC #yyy
    jobs = [ ]
    jobs_input_sort = [ ]
    binaries = os.listdir(binary_dir)
    binaries.sort()
    if binary is not None: #这里配置单目标
        binaries=[binary] # handle
    
    #input_from="file" # the parameter to indicate the where does the input come from, stdin or file
    #afl_input_para=["@@"] # #such as ["@@", "/tmp/shelfish"]
    
    input_from="stdin" # the parameter to indicate the where does the input come from, stdin or file
    afl_input_para=[] # #such as ["@@", "/tmp/shelfish"]
    
    for binary in binaries: #遍历多个目标程序, 这里是程序名称
        if binary.startswith("."):
            continue 

        pathed_binary = os.path.join(binary_dir, binary) #生成目标完整路径
        if os.path.isdir(pathed_binary):
            continue
        if not os.access(pathed_binary, os.X_OK):
            continue
        
        if '#' in pathed_binary:
            jobs_input_sort.append(pathed_binary) #input sort对比对象的程序
        else:
            jobs.append(pathed_binary)  #原始的程序
            
    l.info("%d binaries found", len(jobs))
    l.debug("binaries: %r", jobs)

    # send all the binaries to the celery queue 任务调度器
    l.info("%d binaries found", len(jobs))

    jobs.sort()
    l.info("going to work on %d", len(jobs))

    for binary_path in jobs:     #这里是clery下 task模块中的delay函数
        #driller.tasks.fuzz.delay(binary_path,input_from,afl_input_para,afl_engine) #这里的delay是对fuzz这个函数用的 是celery的函数
        driller.tasks.fuzz(binary_path+'#0', input_from,afl_input_para,afl_engine,comapre_afl=False, inputs_sorted=True,strategy_id=strategy_id)

    l.info("this task ends")
  
def main(argv):
#     strategy_id
#     /* 00 */ NO_SORT_0,
#     /* 01 */ Random_Sort_1,
#     /* 02 */ BT_dup_Sort_2,
#     /* 03 */ BT_no_dup_Sort_3,
#     /* 04 */ BA_Sort_4,
#     /* 05 */ MIn_Max_Sort_5,
#     /* 06 */ Short_first_Sort_6,
#     /* 07 */ Short_by_hamming_7,
    binary=None
    afl_engine="fast"  
    start(binary,afl_engine,'0')
    ## end ---------------------
    
if __name__ == "__main__":
    sys.exit(main(sys.argv))
