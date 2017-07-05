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

def dynamic_trace(tracer_qemu,input_path,target_binary,output_dir,test_from_dir,input_from,add_env):
        '''
        record the executed BBs of a testcase
        @param input_from: read from file or stdin 
        '''
        lname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-")
        args = [tracer_qemu]
        
        is_crash_case = False  # 处理crash时的flag,只记录崩溃处的基本块
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
                    #stdout=stdout_f,
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    env=add_env
                    )
            #如果是stdin程序 
            if input_from=="stdin":
                f=open(input_path, 'rb')
                input=f.read()
                f.close()
                _,_= p.communicate("1\n2")#读取测试用例,输入 加'\n'后可以多次
                
            ret = p.wait() #等待返回结果
            
            # did a crash occur?
            if ret < 0:
                if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                    l.info("input caused a crash (signal %d)\
                            during dynamic tracing", abs(ret))
                    l.info("entering crash mode")
                    is_crash_case =True #表示这是一个crash测试用例

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
        
        # grab the faulting address
        if is_crash_case:
            #crash_addr = int(trace.split('\n')[-2].split('[')[1].split(']')[0],16) #最后一个基本块 address
            #print trace
            #print trace.split('\n')[-2]
            #print trace.split('\n')[-1]#这个是空格
            crash_addr = [trace.split('\n')[-2].split('[')[1]]         #最后一个基本块 address
        
        
        #输出每个测试用例的轨迹
        #配置每个测试用例的输出名称
        input_name=os.path.basename(input_path)
        input_name = 'id'+input_name.split("id:")[-1].split(",")[0]
        
        #应该根据来源保存
        if 0:
            if is_crash_case:
                input_name+='crashes'
            else:
                input_name+='queue'
        #根据执行结果保存  
        if 1:  
            if is_crash_case:
                test_from_dir='crashes'
            else:
                test_from_dir='queue'    
        addrs_set=set()
        addrs_set.update(addrs)  # 去掉重复的
        write_each_trace(output_dir,input_name, addrs, addrs_set, test_from_dir)
            
        os.remove(lname)#删除记录测试用例轨迹的临时文件
        return (addrs,crash_addr,addrs_set)  #返回一个list  如果是crash,addrs是包括最后一个的

def write_out_all_trace(trace_set,crash_set,output_dir,trace_num_dict,trace_num_dict_set): #包括crash和queue
    #输出目录
    out_trace = os.path.join(output_dir, "trace_all")
    out_crash= os.path.join(output_dir, "crashes_blocks")  #只记录崩溃处的位置
    trace_num= os.path.join(output_dir, "trace_num")
    trace_num_set= os.path.join(output_dir, "trace_num_set")
    
    if os.path.exists(out_trace):
        os.remove(out_trace)
    if os.path.exists(out_crash):
        os.remove(out_crash)  
    if os.path.exists(trace_num):
        os.remove(trace_num)  
    if os.path.exists(trace_num_set):
        os.remove(trace_num_set)     
    
    #输出所有轨迹地址集合 (16进制)
    with open(out_trace+"hex", 'a') as ofp:
        for v in trace_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
                
    #输出所有轨迹地址集合 (10进制)
    with open(out_trace, 'a') as ofp:
        for v in trace_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            a=int(a,16)
            a=str(a)
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
    #---------------------------------------------
    #输出崩溃点地址集合 (16进制)
    with open(out_crash+"hex", 'a') as ofp:
        for v in crash_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
                
    #输出崩溃点地址集合  (10进制)
    with open(out_crash, 'a') as ofp:
        for v in crash_set:
            a=v.split(']')[0]
            b=v.split(']')[1]
            a=int(a,16)
            a=str(a)
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')  
            
    # 输出基本块数量, 包含重复的
    with open(trace_num, 'a') as ofp:
        ofp.write("all_num is(no duplicate) :"+str(len(trace_set)) )
        ofp.write('\n')
        for k,v in trace_num_dict.iteritems():
            a=k+":"+str(v)
            ofp.write(a)  # 将内容输出到目标目录
            ofp.write('\n')    
    
    # 输出基本块数量, 不包含重复的
    with open(trace_num_set, 'a') as ofp:
        ofp.write("all_num is(no duplicate) :"+str(len(trace_set)) )
        ofp.write('\n')
        for k,v in trace_num_dict_set.iteritems():
            a=k+":"+str(v)
            ofp.write(a)  # 将内容输出到目标目录
            ofp.write('\n')             

def write_each_trace(output_dir,input_name, test_trace, test_trace_set,from_dir):
    
    '''
    @param output_dir: the output directory
    @param input_name:  the id of the test_case
    @param test_trace: the trace of the test_case 
    @param from_dir: indicate what is the test-case
    '''
    
    #选择输出目录
    if from_dir=='queue':
        out_trace = os.path.join(output_dir, "queue")
    elif from_dir=='crashes':
        out_trace = os.path.join(output_dir, "crashes")
    else:
        print"no queue or crashes"
        exit(1)  
    
    test_trace_set=set()
    test_trace_set.update(test_trace)   #利用set除去重复部分,但是失去了顺序
    filename=os.path.join(out_trace, input_name)
    
    #十进制 轨迹
    with open(filename, 'a') as ofp:
        #for v in test_trace_set:
        for v in test_trace: #保持了有序性
            a=v.split(']')[0]
            b=v.split(']')[1]
            a=int(a,16)
            a=str(a)
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')
    
    #十六进制 轨迹
    with open(filename+"hex", 'a') as ofp:
        #for v in test_trace_set:
        for v in test_trace: #保持了有序性
            a=v.split(']')[0]
            b=v.split(']')[1]
            ofp.write(a+b)  # 将内容输出到目标目录
            ofp.write('\n')   
            
            
                 
def start_get_trace(target_binary):
    
    #配置目标程序
    #target_binary = "/home/xiaosatianyu/Desktop/driller/binary-cgc/YAN01_00016" #这个可以读取 bmp2tiff claw32
    #target_binary = "/home/xiaosatianyu/Desktop/afl-yyy/target/brancher" #这个可以读取 bmp2tiff claw32
    
    #配置对应的qemu
    qemu_dir="/home/xiaosatianyu/workspace/git/driller-yyy/shellphish-qemu/shellphish_qemu/bin"
    #p = angr.Project(target_binary)
    #platform = p.arch.qemu_name
    platform = 'cgc'
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
    
    afl_dir="/tmp/driller/file/sync/fuzzer-master"
    #test_case_dir = os.path.join(afl_dir, "queue")  # AFL生成测试用例的目录
    #test_case_dir = "/home/xiaosatianyu/Desktop/driller/seed"
    #test_case_dir = "/tmp/driller/YAN01_00016/driller"
    test_case_dir=os.path.join("/tmp/driller",os.path.basename(target_binary),"driller/queue")
    
    crash_dir = os.path.join(afl_dir, "crashes")  # AFL生成测试用例的目录
    
    #配置输出目录
    target_base=os.path.basename(target_binary) #在tmp/程序名 下
    output_dir=os.path.join("/tmp/traces",target_base)
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir) #删除工作目录
    
    #创建目录
    os.makedirs(output_dir)
    os.makedirs(os.path.join(output_dir,"queue"))  #保存
    os.makedirs(os.path.join(output_dir,"crashes"))
    
    #配置环境变量
    add_env={"HOME": os.environ["HOME"]}   
    
    #完成配置----
    
    trace_set=set() #记录所有的基本块,包含queue和crash下的
    crash_block_set=set() #记录所有崩溃的最后一个基本块
    trace_num_dict=dict() #记录基本块的数量 包含重复的
    trace_num_dict_set=dict() #记录基本块的数量 不包含重复的
    
    #read test-cases
    if os.path.isdir(test_case_dir):
        queue_inputs = filter(lambda d: not d.startswith('.'), os.listdir(test_case_dir))  # queue下的测试用例
    else:
        queue_inputs=[]   
        
    # read crash     
    if os.path.isdir(crash_dir):
        crash_inputs = filter(lambda d: not d.startswith('.') and not d.startswith('R'), os.listdir(crash_dir))  # crash下的测试用例
    else:
        crash_inputs=[]
        
    #遍历queue目录. 得到测试用例的执行轨迹 driller的queue目录下也会有crash
    for input_file in queue_inputs:
        input_data_path = os.path.join(test_case_dir, input_file) 
        test_from_dir="queue" # 也包括任意目录下的测试用例
        addrs,crash_address,addrs_set=dynamic_trace(tracer_qemu,input_data_path,target_binary,output_dir,test_from_dir, input_from, add_env=add_env)#记录对应测试用例的轨迹
        
        # 这里可以使用set得到不重复的 trace
        trace_set.update(addrs)
        crash_block_set.update(crash_address) #记录的是崩溃处的地址  
        trace_num_dict.update({os.path.basename(input_data_path):len(addrs)})
        trace_num_dict_set.update({os.path.basename(input_data_path):len(addrs_set)})
        
    #遍历crash目录. 得到测试用例的执行轨迹
    for input_file in crash_inputs:
        input_data_path = os.path.join(crash_dir, input_file) 
        test_from_dir="crash"
        addrs,crash_address,_=dynamic_trace(tracer_qemu,input_data_path,target_binary,output_dir,test_from_dir,input_from,add_env=add_env)#记录对应测试用例的轨迹
        #这里可以使用set得到不重复的 trace
        trace_set.update(addrs)    
        crash_block_set.update(crash_address) #记录的是崩溃处的地址 

    #输出所有的轨迹到文件
    write_out_all_trace(trace_set,crash_block_set,output_dir,trace_num_dict,trace_num_dict_set)
    
   
    
    return len(queue_inputs) #返回符号执行生成的数量
    
if __name__ == "__main__":
    print "start!\n"
    binaries_dir="/home/xiaosatianyu/Desktop/driller/生成数量多的cgc"
    target_pros=os.listdir(binaries_dir)
    target_pros.sort()
    if os.path.exists("/tmp/traces"):
        shutil.rmtree("/tmp/traces")
    os.makedirs("/tmp/traces")
    sym_num_path="/tmp/traces/num_of_symbolic_gen"
    if os.path.exists(sym_num_path):
        os.remove(sym_num_path)
    
    ofp=open(sym_num_path, 'a')    
    for i in target_pros:
        target_pro=os.path.join(binaries_dir,i)
        num=start_get_trace(target_pro) #收集符号执行产生的数量
        ofp.write(os.path.basename(target_pro)+" generate "+str(num)+"\n")
        ofp.flush()
        print "get %s ok" % os.path.basename(target_pro)
    print "end!\n"
    sys.exit()
