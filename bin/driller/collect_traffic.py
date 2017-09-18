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

##各种函数------------------------------------------------------------------------------
#判断唯一性                
def run(test_path,tracer_qemu,binary_path):
    test_from="crash"
    input_from="stdin"
   
    #筛选测试用例
    input_data_path=test_path
    #返回信号和崩溃点
    cur_signal,crash_address=dynamic_trace(tracer_qemu,input_data_path,binary_path,test_from,input_from)
    cur_signal=str(cur_signal)
    return (cur_signal, crash_address)

def dynamic_trace(tracer_qemu,input_path,target_binary,test_from,input_from,add_env=None):
        '''
        record the executed BBs of a testcase
        @param input_from: read from file or stdin 
        '''
        cur_signal=0 #默认正常退出
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
                if abs(ret) == signal.SIGSEGV: #or abs(ret) == signal.SIGILL:
                #if 1:
                    l.info("input caused a crash (signal %d)\
                            during dynamic tracing", abs(ret))
                    cur_signal=abs(ret)
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
                return (cur_signal,None) # None 表示没有收集到路径 ，[]表示没有奔溃点
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
        return (cur_signal,crash_addr)  #


def filter_out(tc_path,tracer_qemu,binary_path,crash_binary_dir,crash_block_set,binary_dict):
    '''
    @param tc_path:  对应crash的路径
    @param tracer_qemu 用于筛选的qemu路径
    @param binary_path:  目标程序的路径
    @param crash_binary_dir: 准备存放的crash的路径
    @param crash_block_set:  记录crash奔溃的set
    @param binary_dict: 记录该binary的crash的dict
    @param tc_path: 
    @param tc_path: 
    
    '''
    cur_signal,crash_address=run(tc_path,tracer_qemu,binary_path)
    if cur_signal == '0':
        return #表示没有崩溃
    
    Unique="error-to-judge"
    CrashAddress="error-to-get"
    tc=os.path.basename(tc_path)
    binary=os.path.basename(binary_path)
    #如果不能收集奔溃点
    if crash_address is None:
        tag="no_address"
        new_path=os.path.join(crash_binary_dir,tag,cur_signal,tc[0:9])+'_'+binary+'_traffic' #重命名
        if not os.path.exists(os.path.dirname(new_path)):
            os.makedirs(os.path.dirname(new_path)) #创建多层目录 
        shutil.copyfile(tc_path, new_path) #copy to the tmp dir
    #如果可以收集崩溃点，且是新的
    elif len(crash_address)>0 and not crash_address[0] in crash_block_set:
        if not os.path.exists(os.path.join(crash_binary_dir,cur_signal)):
            os.makedirs(os.path.join(crash_binary_dir,cur_signal))
        new_path=os.path.join(crash_binary_dir,cur_signal,tc[0:9])+'_'+binary+'_traffic'#重命名
        if os.path.exists(new_path): #是否已经存在了   
            return
        crash_block_set.update(crash_address) #记录的是崩溃处的地址
        shutil.copyfile(tc_path, new_path) #copy to the tmp dir 
        Unique="true"
        CrashAddress=crash_address[0]
    #如果可以收集崩溃点，但是重复的   
    elif  crash_address[0] in crash_block_set:
        tag="redundant"
        new_path=os.path.join(crash_binary_dir,tag,cur_signal,tc[0:9])+'_'+binary+'_traffic' #重命名
        tmp_path=os.path.join(crash_binary_dir,cur_signal,tc[0:9])+'_'+binary+'_traffic' #如果已经放在uniqe目录了
        # 如果已经收集过了,既有对应文件了
        if os.path.exists(new_path) or os.path.exists(tmp_path):
            return
        
        if not os.path.exists(os.path.dirname(new_path)):
            os.makedirs(os.path.dirname(new_path)) #创建多层目录 
        shutil.copyfile(tc_path, new_path) #copy to the tmp dir
        Unique="false"
        CrashAddress=crash_address[0]
        
    #对应的information中添加信息
    Cur_Signal=cur_signal
    #计算hash
    with open(new_path,'rb') as f:
        md5obj = hashlib.md5()
        md5obj.update(f.read())
        Hash = md5obj.hexdigest()
    CrashTime=time.strftime('%H:%M:%S',time.localtime(time.time()))
    CrashFileName=new_path
    
    crash_item = {
                "CrashTime": CrashTime,
                "Signal": Cur_Signal,
                "CrashAddress": CrashAddress,
                "Hash": Hash,
                "Unique":Unique,
                "CrashFile": CrashFileName,
                "Engine":"afl"
    }
    binary_dict["Crashes"].append(crash_item)#增加一个
        

global  global_dict

def main():
    #遍历workspace下的目录下的traffic目录
    #读取globaljson
    #读取json
    global_json=config.Global_json
    #从原来的json中读取
    if os.path.exists(global_json):
        f=open(global_json,'rt')
        global_dict=json.load(f)#是一个字典
        f.close()
    else:
        l.error("no global json")
    
    driller_workplace= global_dict["dig"]["workdir"]
    if not os.path.exists(driller_workplace):
        os.makedirs(driller_workplace)
    binary_cache_list=set()
    while(1):
        try:
            #遍历每个binary目录
            for binary in os.listdir(driller_workplace):
                binary_path=os.path.join(global_dict["CBDir"],binary)
                binary_workplace=os.path.join(driller_workplace,binary)
                binary_traffic_crashes=os.path.join(binary_workplace,"sync","traffic","crashes")
                if  not os.path.exists(binary_traffic_crashes):
                    continue
                #配置每个binary的信息
                # 记录已经测试过的测试用例目录加文件名称
                 
                #1. 从原来json读取信息 或者新建
                binary_crash_dict=dict()
                crash_json_path=os.path.join(global_dict["CrashDir"] ,binary+'.json') #每个目标程序下
                
                #如果有,则从原来的json中读取
                if os.path.exists(crash_json_path):
                    try: 
                        f=open(crash_json_path,'rt')
                        binary_crash_dict=json.load(f)#是一个字典
                        f.close()
                    except Exception as e:
                        continue    
                else:
                    #生成新的json
                    binary_crash_dict=dict()
                    #读取CBs.json,获取基本信息
                    cb_dir=global_dict["CBDir"] 
                    for i in os.listdir(cb_dir):
                        if ".json" in i:
                            cb_json_path=os.path.join(cb_dir,i) 
                            break
                    try:   
                        f=open(cb_json_path,'rt')
                        cb_dict=json.load(f)#是一个字典
                        f.close()
                    except Exception as e:
                        continue
                    
                    flag=False
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
                    if not binary_crash_dict.has_key("BasicInfo"):
                        binary_crash_dict["BasicInfo"]={
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
                    if not binary_crash_dict.has_key("Crashes"):
                        binary_crash_dict["Crashes"]=list() #针对当前程序，新建一个字典
                        
                ##2.读取crash point
                binary_crash_address_path=os.path.join(global_dict["CrashDir"] ,binary,'crash_address')
                binarry_crash_set=set()
                if os.path.exists(binary_crash_address_path):
                    with open(binary_crash_address_path,"r") as f:
                        while 1:
                            line= f.readline().split('\n')[0]
                            if not line :
                                break
                            if len(line)>0 :
                                binarry_crash_set.update([line])
                      
                #3. 配置对应的qemu
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
                
                #4. 遍历traffic下的crash
                for tc in sorted(os.listdir(binary_traffic_crashes)):
                    if 'README' in tc :
                        continue
                    #4.1mark the tag
                    tc_path=os.path.join(binary_traffic_crashes,tc)
                    tc_tag=binary+tc 
                    if tc_tag in binary_cache_list:
                        continue
                    else:
                        binary_cache_list.update([tc_tag])
                    #筛选
                    crash_binary_dir=os.path.join(global_dict["CrashDir"],binary)
                    filter_out(tc_path,tracer_qemu,binary_path,crash_binary_dir,binarry_crash_set,binary_crash_dict)
               
                #5. save the json
                with open(crash_json_path,"wt") as f:
                    #f.write(json.dumps(information_dict))
                    json.dump(binary_crash_dict,f) #ok
                    
                #6. save the crash点
                with open(binary_crash_address_path,"wt") as f:
                    for address in binarry_crash_set:
                        f.write(address)
                        f.write('\n')
        except Exception as e:
            print ("error is %s, in collect_traffic,just ignore and waiting" %e)
            continue    
    print "wait for another"
    time.sleep(30)#每隔30秒运行一次
        
        
#监听目标目录, 每隔10分钟读取一下目标程序
if __name__ == "__main__": 
    print "begin in traffic"
    sys.exit(main())
