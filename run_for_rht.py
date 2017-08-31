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
def start(binary,afl_engine,strategy_id):
    binary_dir=config.BINARY_DIR_UNIX
    jobs = [ ]
    binaries = os.listdir(binary_dir)
      
    #都是stdin输入    
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
        identifier = binary  
        jobs.append(pathed_binary)  #添加的是路径
        
    l.info("%d binaries found", len(jobs))
    l.debug("binaries: %r", jobs)

    for binary_path in jobs:
        driller.tasks.fuzz(binary_path, input_from,afl_input_para,afl_engine,
                           comapre_afl=False, inputs_sorted=True,
                           strategy_id=strategy_id,time_limit=config.FUZZ_LIMIT,
                           multi_afl=True)
    l.info("end task")

def main(argv):
    binary=None
    afl_engine=config.AFL_Shellfish_unix
    strategy_id='0'
    start(binary,afl_engine,strategy_id)
    
if __name__ == "__main__":
    sys.exit(main(sys.argv))
