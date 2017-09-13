#!/usr/bin/env python
#coding=utf-8

import logging
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
import json
import driller.dogfeeder as dogfeeder
import stat
import subprocess

'''
Large scale test script. Should just require pointing it at a directory full of binaries.
'''

class Collect_Traffic():
    def __init__(self):
        self.procs=[]
    
    def start(self):
        #traffic
        python_path=sys.executable
        args=[python_path]
        start_traffic_path=config.traffic_path
        args += [start_traffic_path]
        p = subprocess.Popen(args)  
        self.procs.append(p)
    def kill (self):
        for p in self.procs:
            p.terminate()
            p.wait()
        
    def __del__(self):
        self.kill()

def start(afl_engine,robot):
    #读取json
    global_json=config.Global_json
    #从原来的json中读取
    if os.path.exists(global_json):
        f=open(global_json,'rt')
        info_dict=json.load(f)#是一个字典
        f.close()
    else:
        l.error("no global json")
        
    #读取watch dog
    freq=info_dict["WatchDog"]["FeedInterval"]
    feed= os.path.join(info_dict["ShareDir"],"dogfood")
    if not os.path.exists(feed): 
        os.makedirs(feed) 
    dog=dogfeeder.FeedDog("afl",freq,feed)
    #删除旧的
    for item in os.listdir(feed):
        if "afl" in item:
            os.remove(os.path.join(feed,item))
      
    dog.start()
    
    # start traffic
    trafic=Collect_Traffic()
    trafic.start()
    
      
    while(1):
        try:
            #binary_dir=config.BINARY_DIR_UNIX
            binary_dir=info_dict["CBDir"]
            input_from="stdin" # the parameter to indicate the where does the input come from, stdin or file
            afl_input_para=[] # #such as ["@@", "/tmp/shelfish"]
            
            jobs = [ ]
            if not robot:
                binaries = os.listdir(binary_dir)
                   
                for binary in binaries: #遍历多个目标程序, 这里是程序名称   怎么名字都变成unicode了
                    binary = binary.encode("ascii") 
                    if binary.startswith("."):
                        continue 
                    pathed_binary = os.path.join(binary_dir, binary) #生成目标完整路径
                    if os.path.isdir(pathed_binary):
                        continue
                    if not os.access(pathed_binary, os.X_OK):
                        os.chmod(pathed_binary, stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO);
                        #continue
                    if ".json" in   binary:
                        continue
                    jobs.append(pathed_binary)  #添加的是路径, 目标程序
            else:
                for i in os.listdir(binary_dir):
                    if ".json" in i:
                        cb_json_path=os.path.join(binary_dir,i) 
                        break
                f=open(cb_json_path,'rt')
                cb_dict=json.load(f)#是一个字典
                f.close()
                for item in cb_dict["CBs"]:
                    if os.path.exists(item["CB"]):
                        os.chmod(item["CB"], stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO);
                        jobs.append(item["CB"])
            
                
            l.info("%d binaries found", len(jobs))
            l.debug("binaries: %r", jobs)
            
            for binary_path in jobs:
                binary_path = binary_path.encode("ascii") 
                driller.tasks.fuzz(binary_path, input_from,afl_input_para,afl_engine,
                                   comapre_afl=False, inputs_sorted=True,
                                   time_limit=config.FUZZ_LIMIT,
                                   multi_afl=True,driller_engine=False)
            l.info("end task")
        except Exception as e:
            #print e
            continue    

def main(argv):
    afl_engine=config.AFL_Shellfish_unix
    robot=False
    start(afl_engine,robot)
    
    
#监听目标目录, 每隔10分钟读取一下目标程序
    
if __name__ == "__main__":
    sys.exit(main(sys.argv))
