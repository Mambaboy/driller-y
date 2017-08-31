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

l = logging.getLogger("driller.collect_crash")

''' 
listen for new inputs produced by driller

:param crash_source_dir: directory to places new inputs
:param crash_target_dir: redis crash_target_dir on which the new inputs will be arriving
'''
def dynamic_trace(tracer_qemu,input_path,target_binary,output_dir,test_from,input_from,add_env=None):
        '''
        record the executed BBs of a testcase
        @param input_from: read from file or stdin 
        '''
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
                    stderr=devnull,
                    env=add_env
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
        
        addrs = [v.split('[')[1] for v in trace.split('\n') if v.startswith('Trace')] # 得到所有的基本块地址,这里保留函数名称 str类型
        addrs_set=set()
        addrs_set.update(addrs)  # 去掉重复的轨迹
        
        # grab the faulting address
        if is_crash_case:
            #crash_addr = int(trace.split('\n')[-2].split('[')[1].split(']')[0],16) #最后一个基本块 address
            #print trace
            #print trace.split('\n')[-2]
            #print trace.split('\n')[-1]#这个是空格
            crash_addr = [trace.split('\n')[-2].split('[')[1]]         #最后一个基本块 address 奔溃点的地址
        
        #输出每个测试用例的轨迹
        #配置每个测试用例的输出名称
        input_name =os.path.basename(input_path)
        input_name = 'id'+input_name.split("id:")[-1].split(",")[0]
        
        os.remove(lname)#删除记录测试用例轨迹的临时文件
        return (addrs,crash_addr,addrs_set)  #返回一个list  如果是crash,addrs是包括最后一个的    


crash_source_dir = sys.argv[1]  #完整的目录,有很多fuzzing引擎
crash_target_dir = sys.argv[2]
binary_path=sys.argv[3]
binary=os.path.basename(binary_path)
tmp_dir=os.path.join("/tmp",binary)

l = logging.getLogger("driller.listen")

if not os.path.exists(crash_source_dir):
    l.error("no crash_source_dir")

#the target to copy
crash_target_dir=os.path.join(crash_target_dir,binary)  
if not os.path.exists(crash_target_dir):
    os.mkdir(crash_target_dir)

#创建临时目录    
if os.path.exists(tmp_dir):
    shutil.rmtree(tmp_dir)
os.mkdir(tmp_dir)

#创建json
json_path=os.path.join(crash_target_dir,"information.json")

#crash point
crash_block_set=set()
while(1):
    time.sleep(30)#每隔30秒运行一次
    #先复制到一个临时目录,改名
    for subdir in os.listdir(crash_source_dir):
        if "driller" in subdir:
            continue
        sub_crash_path=os.path.join(crash_source_dir,subdir,"crashes")
        if not os.path.exists(sub_crash_path):
            time.sleep(10)
        for tc in os.listdir(sub_crash_path):
            if 'README' in tc :
                continue
            #rename
            tc_path=os.path.join(sub_crash_path,tc)
            new_path=os.path.join(tmp_dir,tc[0:9])+'_'+subdir+'_'+binary
            #copy for only one time
            if not os.path.exists(new_path):
                shutil.copyfile(tc_path, new_path) #copy to the tmp dir
    #end rename and copy
    
    #配置对应的qemu
    qemu_dir="/home/xiaosatianyu/workspace/git/driller-yyy/shellphish-qemu/shellphish_qemu/bin" #来自于tracer
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
        
    output_dir=None
    test_from="crash"
    input_from="stdin"
    
    #filter the crash, 要逆序排列
    crash_list=os.listdir(tmp_dir)
    crash_list.sort(reverse=True) 
    #筛选测试用例
    for crash_input in crash_list:
        input_data_path = os.path.join(tmp_dir, crash_input) 
        addrs,crash_address,_=dynamic_trace(tracer_qemu,input_data_path,binary_path,output_dir,test_from,input_from)#记录对应测试用例的轨迹
        #得到崩溃点
        #这里可以使用set得到不重复的 trace
        if len(crash_address)>0 and not crash_address[0] in crash_block_set:
            crash_block_set.update(crash_address) #记录的是崩溃处的地址
            
            #copy to the target dir
            new_path=os.path.join(crash_target_dir,crash_input)
            if not os.path.exists(new_path):
                shutil.copyfile(input_data_path, new_path) #copy to the target dir
                #这里应该要往jason中加一些内容
                test_info={'bigberg': 1 ,"test":2}
                with open(json_path,"a") as f:
                    json.dump(test_info,f) #ok
                    json.dump('\n',f) #ok
                
                