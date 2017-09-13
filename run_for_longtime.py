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



def start(afl_engine):
    
    while(1):
        binary_dir=config.BINARY_DIR_UNIX
        jobs = [ ]
        binaries = os.listdir(binary_dir)
          
        #input_from="stdin" # the parameter to indicate the where does the input come from, stdin or file
        #afl_input_para=[] # #such as ["@@", "/tmp/shelfish"]
        
        input_from="file" # the parameter to indicate the where does the input come from, stdin or file
        afl_input_para=['-a','@@'] # #such as ["@@", "/tmp/shelfish"]
        
        for binary in binaries: #遍历多个目标程序, 这里是程序名称
            if binary.startswith("."):
                continue 
            pathed_binary = os.path.join(binary_dir, binary) #生成目标完整路径
            if os.path.isdir(pathed_binary):
                continue
            if not os.access(pathed_binary, os.X_OK):
                continue
            jobs.append(pathed_binary)  #添加的是路径, 目标程序
            
        l.info("%d binaries found", len(jobs))
        l.debug("binaries: %r", jobs)
        
        for binary_path in jobs:
            driller.tasks.fuzz(binary_path, input_from,afl_input_para,afl_engine,
                               comapre_afl=False, inputs_sorted=True,
                               time_limit=None,
                               multi_afl=True,driller_engine=True)
        l.info("end task")

        
def main(argv):
    afl_engine=config.AFL_Shellfish_unix
    start(afl_engine)
    
    
#监听目标目录, 每隔10分钟读取一下目标程序
    
if __name__ == "__main__":
    sys.exit(main(sys.argv))
