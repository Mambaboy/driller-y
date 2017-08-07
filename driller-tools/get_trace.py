# coding=utf-8
import tracer
import logging
import os
import sys
import tempfile
import subprocess
import angr
import signal
import shutil
from angr.simos import os_mapping
import trace

l = logging.getLogger("tracer.Tracer")

def dynamic_trace(tracer_qemu,input_path,target_binary,output_dir,test_from,input_from,add_env):
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
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("input caused a crash (signal %d)\
                            during dynamic tracing", abs(ret))
                    l.info("entering crash mode")
                    is_crash_case =True #表示这是一个crash测试用例
                    print input_path

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
        
        #应该根据来源保存,如果是crash,则添加名称
        if 1:
            if is_crash_case:
                input_name+='crashes'
#             else:
#                 input_name+='queue'
        
        #根据执行结果保存,修改保存目录
        if 0:  
            if is_crash_case:
                test_from='crash'
            else:
                test_from='queue'    
        
        write_each_trace(output_dir,input_name, addrs, addrs_set, test_from)
            
        os.remove(lname)#删除记录测试用例轨迹的临时文件
        return (addrs,crash_addr,addrs_set)  #返回一个list  如果是crash,addrs是包括最后一个的

def write_out_all_trace(trace_set,crash_set,output_dir,trace_num_dict,trace_num_dict_set): #包括crash和queue
    #输出目录
    add_trace = os.path.join(output_dir, "trace_all")
    crash_addrs= os.path.join(output_dir, "all_crashes_addrs")  #只记录崩溃处的位置
    trace_num= os.path.join(output_dir, "trace_num")
    trace_num_set= os.path.join(output_dir, "trace_num_set")
    
    if os.path.exists(add_trace):
        os.remove(add_trace)
    if os.path.exists(crash_addrs):
        os.remove(crash_addrs)  
    if os.path.exists(trace_num):
        os.remove(trace_num)  
    if os.path.exists(trace_num_set):
        os.remove(trace_num_set)     
    
    #输出所有轨迹地址集合 (16进制)
    with open(add_trace+"hex", 'a') as ofp:
        for v in trace_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
                
    #输出所有轨迹地址集合 (10进制)
    with open(add_trace, 'a') as ofp:
        for v in trace_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            a=int(a,16)
            a=str(a)
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
    #---------------------------------------------
    
    
    #输出崩溃点地址集合 (16进制)
    with open(crash_addrs+"hex", 'a') as ofp:
        for v in crash_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
                
    #输出崩溃点地址集合  (10进制)
    with open(crash_addrs, 'a') as ofp:
        for v in crash_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            a=int(a,16)
            a=str(a)
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')  
    #  -----------------------------------------------------------------------------
    
    
    
    # 输出基本块数量, 包含重复的
    with open(trace_num, 'a') as ofp:
        ofp.write("all_num is(no duplicate) :"+str(len(trace_set)) )
        ofp.write('\n')
        for k,v in trace_num_dict.iteritems():
            a=k+":"+str(v)
            ofp.write(a)  # 将内容输出到目标目录
            ofp.write('\n')    
    #  -----------------------------------------------------------------------------
    
    
    # 输出基本块数量, 不包含重复的
    with open(trace_num_set, 'a') as ofp:
        ofp.write("all_num is(no duplicate) :"+str(len(trace_set)) )
        ofp.write('\n')
        for k,v in trace_num_dict_set.iteritems():
            a=k+":"+str(v)
            ofp.write(a)  # 将内容输出到目标目录
            ofp.write('\n')             

def write_each_trace(output_dir,input_name, test_trace, test_trace_set,test_from):
    
    '''
    @param output_dir: the output directory
    @param input_name:  the id of the test_case
    @param test_trace: the trace of the test_case 
    @param test_from: indicate what is the test-case
    '''
    
    #选择输出目录
    if test_from=='queue':
        out_trace = os.path.join(output_dir, "queue")
    elif test_from=='crash':
        out_trace = os.path.join(output_dir, "crashes")
    else:
        print"error test_from"
        exit(1)  
    
    test_trace_set=set()
    test_trace_set.update(test_trace)   #利用set除去重复部分,但是失去了顺序
    filename=os.path.join(out_trace, input_name)
    
    #十进制 轨迹
    with open(filename, 'a') as ofp:
#         for v in test_trace_set: #去重
        for v in test_trace: #保持了有序性
            a=v.split(']')[0]
            b=v.split(']')[1]
            a=int(a,16)
            a=str(a)
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
    
    #十六进制 轨迹
    with open(filename+"hex", 'a') as ofp:
#         for v in test_trace_set: #去重
        for v in test_trace: #保持了有序性
            a=v.split(']')[0]
            b=v.split(']')[1]
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')   
            
            
                 
def start_get_trace(binary_path,data_dir):
    #配置对应的qemu
    qemu_dir="/home/xiaosatianyu/workspace/git/driller-yyy/shellphish-qemu/shellphish_qemu/bin" #来自于tracer
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
        exit(1)     
        
    #配置测试用例输入目录,这个是当个afl引擎的情况
    #input_from ="file" 
    input_from = "stdin"
    
    queue_dir = os.path.join(data_dir, "queue")  # AFL生成测试用例的目录
    #queue_dir = "/home/xiaosatianyu/Desktop/driller-desk/seed"
    #queue_dir=os.path.join("/tmp/driller",os.path.basename(binary_path),"driller/queue")
    
    crash_dir = os.path.join(data_dir, "crashes")  # AFL生成测试用例的目录
    
    if not os.path.exists(queue_dir) and not os.path.exists(crash_dir):
        return 0
    
    #配置输出目录  #创建目录
    output_dir=os.path.join("/tmp/traces",os.path.basename(binary_path))
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir) #删除工作目录
    os.makedirs(output_dir)
    os.makedirs(os.path.join(output_dir,"queue"))  #保存
    os.makedirs(os.path.join(output_dir,"crashes"))
    
    #配置环境变量
    add_env={"HOME": os.environ["HOME"]}   
    
    # 完成配置-------------- ------------------------------------------------------
    
    trace_set=set() #记录所有的基本块,包含queue和crash下的
    crash_block_set=set() #记录所有崩溃的最后一个基本块
    trace_num_dict=dict() #记录基本块的数量 包含重复的
    trace_num_dict_set=dict() #记录基本块的数量 不包含重复的
    
    #read test-cases
    if os.path.isdir(queue_dir):
        queue_inputs = filter(lambda d: not d.startswith('.'), os.listdir(queue_dir))  # queue下的测试用例
    else:
        queue_inputs=[]   
        
    # read crash     
    if os.path.isdir(crash_dir):
        crash_inputs = filter(lambda d: not d.startswith('.') and not d.startswith('R'), os.listdir(crash_dir))  # crash下的测试用例
    else:
        crash_inputs=[]
        
    #遍历queue目录. 得到测试用例的执行轨迹; 如果是driller的queue目录下也会有crash 
    for queue_input in queue_inputs:
        input_data_path = os.path.join(queue_dir, queue_input) 
        test_from="queue" # 也包括任意目录下的测试用例
        addrs,crash_address,addrs_set=dynamic_trace(tracer_qemu,input_data_path,binary_path,output_dir,test_from, input_from, add_env=add_env)#记录对应测试用例的轨迹
        
        #得到轨迹
        # 这里可以使用set得到不重复的 trace
        trace_set.update(addrs)
        crash_block_set.update(crash_address) #记录的是崩溃处的地址  
        trace_num_dict.update({os.path.basename(input_data_path):len(addrs)})
        trace_num_dict_set.update({os.path.basename(input_data_path):len(addrs_set)})
        
    #遍历crash目录. 得到测试用例的执行轨迹
    for crash_input in crash_inputs:
        input_data_path = os.path.join(crash_dir, crash_input) 
        test_from="crash"
        addrs,crash_address,_=dynamic_trace(tracer_qemu,input_data_path,binary_path,output_dir,test_from,input_from,add_env=add_env)#记录对应测试用例的轨迹
        
        #得到轨迹
        #这里可以使用set得到不重复的 trace
        trace_set.update(addrs)    
        crash_block_set.update(crash_address) #记录的是崩溃处的地址 

    #输出所有的轨迹到文件
    write_out_all_trace(trace_set,crash_block_set,output_dir,trace_num_dict,trace_num_dict_set)
    
    return len(queue_input)#返回测试用例的数量


if __name__ == "__main__":
    print "start!\n"
    binaries_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"
    binaries_dir="/home/xiaosatianyu/CTF/AFL-execution/target"
    target_pros=os.listdir(binaries_dir)
    target_pros.sort()
    if os.path.exists("/tmp/traces"):
        shutil.rmtree("/tmp/traces")
    os.makedirs("/tmp/traces")
    
    
    #data_dir= os.path.join("/tmp/driller",os.path.basename(binary_path),"sync/fuzzer-master")
    
    for pro in target_pros:
        binary_path=os.path.join(binaries_dir,pro)
        data_dir="/tmp/sync-ctf/1"
        num=start_get_trace(binary_path,data_dir) #收集符号执行产生的数量
        if num!=0:
            print "get %s ok" % os.path.basename(binary_path)
    print "end!\n"
    sys.exit()
