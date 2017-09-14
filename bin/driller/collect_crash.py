#!/usr/bin/env python
# coding=utf-8

import os
import sys
import logging
import driller.config as config
import time
import shutil
import tempfile
import subprocess
import signal
import angr
import json
from __builtin__ import str
import hashlib

l = logging.getLogger("driller.collect_crash")



##配置-----------------------------
''' 
listen for new inputs produced by driller
:param crash_source_dir: directory to places new inputs
:param crash_binary_dir: redis crash_binary_dir on which the new inputs will be arriving
'''
#arg1
crash_source_dir = sys.argv[1].strip()  #完整的目录,有很多fuzzing引擎
print ("crash_source_dir is %s " % crash_source_dir)
if not os.path.exists(crash_source_dir):
    l.error("not source dir")
#arg2
crash_dir = sys.argv[2].strip()  #总的目录
if not os.path.exists(crash_dir):
    os.mkdir(crash_dir)
print ("crash_dir is %s" % crash_dir)
#arg3
binary_path=sys.argv[3].strip() 
binary=os.path.basename(binary_path).strip()

#the target to copy
crash_binary_dir=os.path.join(crash_dir,binary) 
print crash_binary_dir 
if not os.path.exists(crash_binary_dir):
    os.mkdir(crash_binary_dir)


#从对应的json读取信息
info_dict=dict()
json_path=os.path.join(crash_dir ,binary+'.json') #每个目标程序下
#如果有,则从原来的json中读取
try:
    if os.path.exists(json_path):
        f=open(json_path,'rt')
        info_dict=json.load(f)#是一个字典
        f.close()
except Exception as e:
    pass        
    
#读取CBs.json
global_json=config.Global_json
if os.path.exists(global_json):
    f=open(global_json,'rt')
    global_dict=json.load(f)#是一个字典
    f.close()
else:
    l.error("no global json")
  
cb_dir=global_dict["CBDir"] 

for i in os.listdir(cb_dir):
    if ".json" in i:
        cb_json_path=os.path.join(cb_dir,i) 
        break

flag=False    
try:   
    f=open(cb_json_path,'rt')
    cb_dict=json.load(f)#是一个字典
    f.close()
    for item in cb_dict["CBs"]: #item是list
        if os.path.basename(item["CB"]) == binary:
            flag=True
            Round= item["Round"]
            ChallengeID=item["ChallengeID"]
            CB=item["CB"]
            PullTime=item["PullTime"]
            ReadAddress=item["ReadAddress"]
            WriteAddress=item["WriteAddress"]
            WriteValue=item["WriteValue"]
            OWEIP=item["OWEIP"]
            break
except Exception as e:
    pass        

if not flag:    
    Round= 0
    ChallengeID=65
    CB=binary_path
    PullTime="time here",
    ReadAddress="0xdeadbeaf"
    WriteAddress="0xdeadbeaf"
    WriteValue="0xdeadbeaf"
    OWEIP="0xdeadbeaf"

#准备目标程序的json
#第一次生成 BasicInfo
if not info_dict.has_key("BasicInfo"):
    info_dict["BasicInfo"]={
                    "Round": Round,
                    "ChallengeID": ChallengeID,
                    "CB": CB,
                    "PullTime": PullTime,
                    "ReadAddress": ReadAddress,
                    "WriteAddress": WriteAddress,
                    "WriteValue": WriteValue,
                    "OWEIP": OWEIP
        }
#第一次生成Crashes
if not info_dict.has_key("Crashes"):
    info_dict["Crashes"]=list() #针对当前程序，新建一个字典

#读取crash point
crash_address_path=os.path.join(crash_binary_dir,"crash_address") #保存crash点的文件
crash_block_set=set()
#读取已有崩溃点信息
if os.path.exists(crash_address_path):
    with open(crash_address_path,"r") as f:
        while 1:
            line= f.readline().split('\n')[0]
            if not line :
                break
            if len(line)>0 :
                crash_block_set.update([line])


# 记录已经测试过的测试用例目录加文件名称
cache_list=set() 


#old_block_set=crash_block_set.copy()

#configure
#配置对应的qemu
qemu_dir=config.collect_qemu #来自于tracer
#自适应
p = angr.Project(binary_path)
platform = p.arch.qemu_name
if platform == 'i386':
    tracer_qemu = os.path.join(qemu_dir, "shellphish-qemu-linux-i386")
elif platform == 'x86_64': 
    tracer_qemu = os.path.join(qemu_dir, "shellphish-qemu-linux-x86_64")
elif platform == 'cgc': 
    tracer_qemu = os.path.join(qemu_dir, "shellphish-qemu-cgc-tracer")
else:
    print "no qemu\n"
##结束配置

##各种函数------------------------------------------------------------------------------
#判断唯一性                
def run(test_path):
    test_from="crash"
    input_from="stdin"
   
    #筛选测试用例
    input_data_path=test_path
    #返回信号和崩溃点
    signal,crash_address=dynamic_trace(tracer_qemu,input_data_path,binary_path,test_from,input_from)
    signal=str(signal)
    return (signal, crash_address)

def dynamic_trace(tracer_qemu,input_path,target_binary,test_from,input_from,add_env=None):
        '''
        record the executed BBs of a testcase
        @param input_from: read from file or stdin 
        '''
        signal=0 #默认正常退出
        lname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-")
        args = [tracer_qemu]
        
        is_crash_case = False  # 处理crash时的flag,只记录崩溃处的基本块 ba
        crash_addr=[]
        args += ["-d", "exec", "-D", lname, target_binary]
        if input_from=="file":
            args += [input_path]
        elif input_from=="stdin":
            pass 
        else:
            l.error("input_from is error")   
        
        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull  # 扔掉输出
            p = subprocess.Popen(
                    args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=devnull
                    )
                    
            #如果是stdin程序 
            if input_from=="stdin":
                f=open(input_path, 'rb')
                input_stdin=f.read()
                f.close()
                _,_= p.communicate(input_stdin)#读取测试用例,输入 加'\n'后可以多次
                
            ret = p.wait() #等待返回结果
            
            # did a crash occur?
            if ret < 0:
                #所有负数都要
                #if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                if 1:
                    l.info("input caused a crash (signal %d)\
                            during dynamic tracing", abs(ret))
                    signal=abs(ret)
                    l.info("entering crash mode")
                    is_crash_case =True #表示这是一个crash测试用例
                    #print input_path

            stdout_f.close()
        # end 得到一个轨迹
        
        #开始处理执行轨迹
        with open(lname, 'rb') as f:
            trace = f.read() #得到轨迹
#         addrs = [int(v.split('[')[1].split(']')[0], 16)
#                  for v in trace.scrash_block_setplit('\n')
#                  if v.startswith('Trace')]  # 得到所有的基本块地址 int类型
        
#         addrs = [v.split('[')[1].split(']')[0]
#                  for v in trace.split('\n')
#                  if v.startswith('Trace')] # 得到所有的基本块地址,删掉了别的内容 str类型
            if len(trace)==0:
                return (signal,None) # None 表示没有收集到路径 ，[]表示没有奔溃点
        #addrs = [v.split('[')[1].split(']')[0] for v in trace.split('\n') if v.startswith('Trace')] # 得到所有的基本块地址,这里保留函数名称 str类型
        #addrs_set=set()
        #addrs_set.update(addrs)  # 去掉重复的轨迹
        
        # grab the faulting address
        if is_crash_case:
            #crash_addr = int(trace.split('\n')[-2].split('[')[1].split(']')[0],16) #最后一个基本块 address
            #print trace
            #print trace.split('\n')[-2]
            #print trace.split('\n')[-1]#这个是空格
            crash_addr = [ trace.split('\n')[-2].split('[')[1].split(']')[0] ]         #最后一个基本块 address 奔溃点的地址  
        os.remove(lname)#删除记录测试用例轨迹的临时文件
        return (signal,crash_addr)  #


def filter_out(tc_path):
    signal,crash_address=run(tc_path)
    if signal == '0':
        return #表示没有崩溃
    
    Unique="error-to-judge"
    CrashAddress="error-to-get"
    #如果不能收集奔溃点
    if crash_address is None:
        tag="no_address"
        new_path=os.path.join(crash_binary_dir,tag,signal,tc[0:9])+'_'+subdir+'_'+binary #重命名
        if not os.path.exists(os.path.dirname(new_path)):
            os.makedirs(os.path.dirname(new_path)) #创建多层目录 
        shutil.copyfile(tc_path, new_path) #copy to the tmp dir
    #如果可以收集崩溃点，且是新的
    elif len(crash_address)>0 and not crash_address[0] in crash_block_set:
        if not os.path.exists(os.path.join(crash_binary_dir,signal)):
            os.makedirs(os.path.join(crash_binary_dir,signal))
        new_path=os.path.join(crash_binary_dir,signal,tc[0:9])+'_'+subdir+'_'+binary #重命名
        if os.path.exists(new_path): #是否已经存在了   
            return
        crash_block_set.update(crash_address) #记录的是崩溃处的地址
        shutil.copyfile(tc_path, new_path) #copy to the tmp dir 
        Unique="true"
        CrashAddress=crash_address[0]
    #如果可以收集崩溃点，但是重复的   
    elif  crash_address[0] in crash_block_set:
        tag="redundant"
        new_path=os.path.join(crash_binary_dir,tag,signal,tc[0:9])+'_'+subdir+'_'+binary #重命名
        tmp_path=os.path.join(crash_binary_dir,signal,tc[0:9])+'_'+binary+'_traffic' #如果已经放在uniqe目录了
        # 如果已经收集过了,既有对应文件了
        if os.path.exists(new_path) or os.path.exists(tmp_path):
            return
        
        if not os.path.exists(os.path.dirname(new_path)):
            os.makedirs(os.path.dirname(new_path)) #创建多层目录
             
        shutil.copyfile(tc_path, new_path) #copy to the tmp dir
        Unique="false"
        CrashAddress=crash_address[0]
        
    #对应的information中添加信息
    Signal=signal
    #计算hash
    with open(new_path,'rb') as f:
        md5obj = hashlib.md5()
        md5obj.update(f.read())
        Hash = md5obj.hexdigest()
    CrashTime=time.strftime('%H:%M:%S',time.localtime(time.time()))
    CrashFileName=new_path
    
    crash_item = {
                "CrashTime": CrashTime,
                "Signal": Signal,
                "CrashAddress": CrashAddress,
                "Hash": Hash,
                "Unique":Unique,
                "CrashFile": CrashFileName,
                "Engine":"AFL"
    }
    info_dict["Crashes"].append(crash_item)#增加一个
        
#开始循环
while(1):
    #遍历新的目录
    for subdir in sorted(os.listdir(crash_source_dir)):
        if "driller" in subdir or "traffic" in subdir:
            continue
        sub_crash_path=os.path.join(crash_source_dir,subdir,"crashes")
        if not os.path.exists(sub_crash_path):
            time.sleep(10)
        #遍历crash
        for tc in sorted(os.listdir(sub_crash_path)):
            if 'README' in tc :
                continue
            #mark the tag
            tc_path=os.path.join(sub_crash_path,tc)
            tc_tag=os.path.join(subdir,tc) #放在 cache_list 中的 换个进程就没有了,重跑方式会有太多的重复
            if tc_tag in cache_list:
                continue
            else:
                cache_list.update([tc_tag])
            #筛选
            filter_out(tc_path)
    
    #save the json
    with open(json_path,"wt") as f:
        #f.write(json.dumps(information_dict))
        json.dump(info_dict,f) #ok
        
    #save the crash点
    with open(crash_address_path,"wt") as f:
        for address in crash_block_set:
            f.write(address)
            f.write('\n')
        
    #print "wait for another"
    time.sleep(10)#每隔30秒运行一次
