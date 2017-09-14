#coding=utf-8
import os
import time
import pcap
import redis
import fuzzer
import logging
import hashlib
import subprocess
from celery import Celery
import config
from driller import Driller

import sort_strategy

from sys import argv
import simuvex
import shutil
import signal
import sys
import gc
import json


l = logging.getLogger("driller.tasks")
#l.setLevel(logging.DEBUG)

#backend_url = "redis://%s:%d" % (config.REDIS_HOST, config.REDIS_PORT) #
app = Celery('tasks', broker=config.BROKER_URL, backend=config.Backend_URL) #
app.conf.CELERY_ROUTES = config.CELERY_ROUTES
app.conf['CELERY_ACKS_LATE'] = True
app.conf['CELERYD_PREFETCH_MULTIPLIER'] = 1

redis_pool = redis.ConnectionPool(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #



def get_fuzzer_id(input_data_path): #get testcase-id in the queue catalog 
    # get the fuzzer id
    abs_path = os.path.abspath(input_data_path)
    if "sync/" not in abs_path or "id:" not in abs_path:
        l.warning("path %s, cant find fuzzer id", abs_path)
        return "None"
    fuzzer_name = abs_path.split("sync/")[-1].split("/")[0]
    input_id = abs_path.split("id:")[-1].split(",")[0]
    return fuzzer_name + ",src:" + input_id  # 

@app.task
def drill(binary_path, input_data, input_data_path, bitmap_hash, tag, input_from, afl_input_para,time_limit_for_pro):
    '''
    @param time_limit_for_pro:针对每个目标程序的执行时间
    @param tag: 后传给listern的一个标记,在新测试用例生成是加的名字
    @param time_limit_for_pro:  每个driller的时间
    '''
    binary=os.path.basename(binary_path)
    redis_inst = redis.Redis(connection_pool=redis_pool) #
    fuzz_bitmap = redis_inst.hget(binary + '-bitmaps', bitmap_hash)  #get the bitmap   ##这是一个长传的字符,131072个字符.可以用[]读取,但是不能赋值
    if fuzz_bitmap is None:
        fuzz_bitmap="\xff" * 131072 #debug用,或者是纯符号执行是用
    #--------------------------------------------------------------   
    if input_from=="stdin":
        yargv=None
        add_fs=None
        add_exclude_sim_pro=[]
    elif input_from=="file":
        if  afl_input_para is None:
            l.error("the afl_input_para in driller is error")
        for pro in xrange(len(afl_input_para)):
            if afl_input_para[pro]=="@@":
                afl_input_para[pro]=afl_input_para[pro].replace("@@",input_data_path)
                break
        yargv=[binary_path]+afl_input_para
        
        input_Simfile = simuvex.SimFile(input_data_path, 'rw', size=500) #
        add_fs = {
        input_data_path: input_Simfile
        } 
        add_exclude_sim_pro=[]
    else:
        l.error("the input argv in driller is error")
    #add_env={"HOME": os.environ["HOME"]}   
    add_env=None
    #complete confifure --------------------------------------------------------  

    if time_limit_for_pro is None:
        sy_ex_time_limit=None
    else:   
        sy_ex_time_limit=time_limit_for_pro/3
    driller = Driller(binary_path, input_data, input_data_path, fuzz_bitmap, tag, redis=redis_inst,argv=yargv,
                      add_fs=add_fs,add_env=add_env,add_exclude_sim_pro=add_exclude_sim_pro,
                      time_limit_for_pro=time_limit_for_pro, sy_ex_time_limit=sy_ex_time_limit
                      ) 
    try:
        return driller.drill() #
    #except AttributeError as e:  #debug
    except Exception as e:
        l.error("encountered %r exception when drilling into \"%s\"", e, binary) 
        l.error("input was %r", input_data)

def input_filter(fuzzer_dir, inputs): #

    traced_cache = os.path.join(fuzzer_dir, "traced")
    traced_inputs = set()
    if os.path.isfile(traced_cache):
        with open(traced_cache, 'rb') as f:
            traced_inputs = set(f.read().split('\n')) 
    new_inputs = filter(lambda pro: pro not in traced_inputs, inputs)

    with open(traced_cache, 'ab') as f:
        for new_input in new_inputs:
            f.write("%s\n" % new_input)
    return new_inputs

def has_drilled_and_add(fuzzer_dir, input_file): #
    traced_cache = os.path.join(fuzzer_dir, "traced")
    traced_inputs = set()
    if os.path.isfile(traced_cache):
        with open(traced_cache, 'rb') as f:
            traced_inputs = set(f.read().split('\n')) 
            
    if input_file in traced_inputs:
        return True #has drilled
    else:
        #add to the traced_inputs
        with open(traced_cache, 'ab') as f:
            f.write("%s\n" % input_file)
        return False #not driller and add

def request_drilling(fzr):  
    '''
    request a drilling job on a fuzzer object

    :param fzr: fuzzer object to request drilling on behalf of, this is needed to fine the input input queue
    :return: list of celery AsyncResults, we accumulate these so we can revoke them if need be
    '''

    d_jobs = [ ] #
    bitmap_f = os.path.join(fzr.out_dir, "fuzzer-master", "fuzz_bitmap") 
    
    ##to assure the file is exit
    l.info("waiting for fuzz_bitmap")
    while not os.path.exists(bitmap_f):
        pass
    ##end--------------------------------------------------------
    l.info("fuzz_bitmap is generated, go on")
               
    bitmap_data = open(bitmap_f, "rb").read() #bitmap
    bitmap_hash = hashlib.sha256(bitmap_data).hexdigest() #
    redis_inst = redis.Redis(connection_pool=redis_pool) #
    redis_inst.hset(fzr.binary_id + '-bitmaps', bitmap_hash, bitmap_data) # 构建hash对
    
    #bitmap_hash=None # for debug
    #------------------------------------------------------------------------

    ##get inputs  according the strategy_id
    in_dir = os.path.join(fzr.out_dir, "fuzzer-master", "queue")
    if (fzr.strategy_id == '0'):
        '''NO_SORT_0'''
        inputs=sort_strategy.no_sort_0(in_dir, fzr)
        l.info("strategy 0 successfull")
#         time.sleep(60)
        
    elif (fzr.strategy_id == '1'):
        '''Random_Sort_1'''
        inputs=sort_strategy.random_sort_1(in_dir, fzr)
        l.info("strategy 1 successfull")
#         time.sleep(60)
        
    elif (fzr.strategy_id == '2'):
        '''BT_dup_Sort_2'''
        inputs=sort_strategy.BT_dup_sort_2(in_dir, fzr)
        l.info("strategy 2 successfull")
#         time.sleep(60)
        
    elif (fzr.strategy_id == '3'):
        '''BT_no_dup_Sort_3'''
        inputs=sort_strategy.BT_nodup_sort_3(in_dir, fzr)
        l.info("strategy 3 successfull")
#         time.sleep(60)
        
    elif (fzr.strategy_id == '4'):
        '''BA_Sort_4'''
        inputs=sort_strategy.BA_sort_4(in_dir, fzr)
        l.info("strategy 4 successfull")
#         time.sleep(60)
        
    elif (fzr.strategy_id == '5'):
        '''Min_Max_Sort_5'''
        inputs=sort_strategy.min_max_sort_5(in_dir, fzr)
        #这里再想一个法子,第一个和逆序
        
        l.info("strategy 5 successfull")
#         time.sleep(60)
        
    elif (fzr.strategy_id == '6'):
        '''Short_first_Sort_6'''
        inputs=sort_strategy.short_first_sort_6(in_dir, fzr)
        l.info("strategy 6 successfull")
#         time.sleep(60)
        
    elif (fzr.strategy_id == '7'):
        '''Short_by_hamming_7'''
        inputs=sort_strategy.hamming_sort_7(in_dir, fzr)
        l.info("strategy 7 successfull")
#         time.sleep(60)
        
    else:
        l.error("the strategy_id is not right")
    
    # filter inputs which have already been sent to driller
#     inputs = input_filter(os.path.join(fzr.out_dir, "fuzzer-master"), inputs) # 删除已经跟踪的,这里会把inputs中的都记录下
    #------------------------------------------------------------------------
    
    # submit a driller job for each item in the queue  
    num=0
    for input_file in inputs: 
        if fzr.timed_out():
            l.info("fuzzzer time out ")
            break #如果fuzzer停了,符号执行也停
        # filter inputs which have already been sent to driller and add the undrilled into traced_cache
        if  has_drilled_and_add(os.path.join(fzr.out_dir, "fuzzer-master"), input_file):
            continue
        num+=1 #每跑一个都加1
        input_data_path = os.path.join(in_dir, input_file) #这里即使input_file是绝对路径也没有关系
        input_data = open(input_data_path, "rb").read()  # 
        # d_jobs.append(drill.delay(fzr.binary_id, input_data, bitmap_hash, get_fuzzer_id(input_data_path)))
        d_jobs.append(
                drill(
                fzr.binary_path,
                input_data, 
                input_data_path, 
                bitmap_hash, 
                get_fuzzer_id(input_data_path), #tag
                input_from=fzr.input_from, 
                afl_input_para=fzr.afl_input_para,
                time_limit_for_pro=fzr.time_limit)
                )  # 
        #除了 不排序和随机排序的,其他的每测试一个测试用例后重新排序
        if num >0 and fzr.strategy_id !='0' and fzr.strategy_id !='1':
            break
        
    return d_jobs #当前的测试用例跑完了,退出看看time_out,没有的

def start_listener(fzr):
    '''
    start a listener for driller inputs
    '''

    driller_queue_dir = os.path.join(fzr.out_dir, "driller", "queue") #
    crash_binary_dir = "%s-generated" % fzr.binary_id  #

    # find the bin directory listen.py will be installed in
    base = os.path.dirname(__file__)

    while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
        base = os.path.join(base, "..")

    if os.path.abspath(base) == "/":
        raise Exception("could not find driller listener install directory")
    python_path=sys.executable
    args=[python_path]
    args += [os.path.join(base, "bin", "driller", "listen.py"), driller_queue_dir, crash_binary_dir]
    p = subprocess.Popen(args) #这里可能不在虚拟环境中

    # add the proc to the fuzzer's list of processes
    fzr.procs.append(p) #
    
    
def start_collecting_crash(fzr):
    '''
    collecting the crash generated to a target config.CRASH, 这个进程每隔1分钟运行一下, 复制crash到指定的目录
    '''    
    crash_source_dir = fzr.out_dir #
    crash_binary_dir=config.CRASH_DIR
    #读取crash输出目录
    global_json=config.Global_json
    #从原来的json中读取
    if os.path.exists(global_json):
        f=open(global_json,'rt')
        info_dict=json.load(f)#是一个字典
        f.close()
    else:
        l.error("no global json")
    crash_binary_dir=info_dict["CrashDir"]   
    
    # find the bin directory listen.py will be installed in
    base = os.path.dirname(__file__)
    while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
        base = os.path.join(base, "..")
    if os.path.abspath(base) == "/":
        raise Exception("could not find driller listener install directory")
    
    python_path=sys.executable
    args=[python_path]
    args += [os.path.join(base, "bin", "driller", "collect_crash.py"), crash_source_dir, crash_binary_dir, fzr.binary_path]
    p = subprocess.Popen(args) 

    # add the proc to the fuzzer's list of processes
    fzr.procs.append(p) #
    

def clean_redis(fzr):
    redis_inst = redis.Redis(connection_pool=redis_pool)

    # delete all catalogued inputs
    redis_inst.delete("%s-catalogue" % fzr.binary_id)

    # delete all the traced entries
    redis_inst.delete("%s-traced" % fzr.binary_id)

    # delete the finished entry
    redis_inst.delete("%s-finsihed" % fzr.binary_id)

    # delete the fuzz bitmaps
    redis_inst.delete("%s-bitmaps" % fzr.binary_id)
    
    # delete all symmap
    redis_inst.delete("%s-symmap" % fzr.binary_id)



#@app.task  
def fuzz(binary_path,input_from,afl_input_para,afl_engine,comapre_afl,inputs_sorted,strategy_id='1',time_limit=None,qemu=True,multi_afl=False,driller_engine=True):
    '''
    @param strategy_id: the id of strategy, 0,1,2,3,4,5,6,7 
    @param time_limit: the time to fuzz 
    '''
    #start the redis and enable afl
    password=config.PASSWD_SUDO
    base = os.path.dirname(__file__)
    while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
        base = os.path.join(base, "..")
    if os.path.abspath(base) == "/":
        raise Exception("could not find driller listener install directory")
    script_path=os.path.join(base, "bin", "driller", "start_for_driller.sh")
    if not os.path.exists(script_path):
        l.error("there is not start script")
        return
    os.system('echo %s | sudo -S sh %s' %(password, script_path) )
    
    binary=os.path.basename(binary_path)
    seeds=[]
    seed_dir = config.SEED 
    
    #根据CBs 判断, 如果tmp中有,说明已经跑过了
    try:
        #读取global json
        global_json=config.Global_json
        if os.path.exists(global_json):
            f=open(global_json,'rt')
            info_dict=json.load(f)#是一个字典
            f.close()
        else:
            l.error("no global json")
        
        control_json_path=os.path.join( info_dict["ControlDir"],"control.json")
        if os.path.exists(control_json_path):
            f=open(control_json_path,'r')
            control_dict=json.load(f)#是一个字典
            f.close()
            for name,value in control_dict.items():
                if name==binary:
                    if value["Continue"] is False:
                        return
    except Exception as e:
        pass
    
    try:
        CBs_json=os.path.join(os.path.dirname(binary_path),"CBs.json")
        f=open(CBs_json,'rt')
        CBs_dict=json.load(f)#是一个字典
        f.close()
        binary_num=len(CBs_dict["CBs"])
        if os.path.exists( os.path.join(config.FUZZER_WORK_DIR,binary)  ):
            l.info("%s has been in tmp, start the next" , binary)
            #查看是否所有的程序都跑完了 比较driller目录下的数量和目标程序的数量
            if len(os.listdir(config.FUZZER_WORK_DIR)) < binary_num:
                return
            else:
                #重跑机制?
                l.info("%s resume---------------------------",binary )
        #防止死机
    except Exception as e:
        pass
          
    l.info("beginning to fuzz \"%s\"", binary)
    for seed in os.listdir(seed_dir):  # 底下最好不要有其他目录
        if '.' in seed:
            continue
        with open(os.path.join(seed_dir, seed), 'rb') as f:  
            seeds.append(f.read())
            f.close()
    
    # TODO enable dictionary creation, this may require fixing parts of the fuzzer module
    fzr = fuzzer.Fuzzer(binary_path, 
                        config.FUZZER_WORK_DIR, 
                        config.FUZZER_INSTANCES,
                        seeds=seeds, 
                        create_dictionary=False,
                        afl_engine=afl_engine,
                        input_from=input_from,
                        afl_input_para=afl_input_para,
                        time_limit=time_limit, #second fuzz and symbolic execution time
                        comapre_afl=comapre_afl,
                        strategy_id=strategy_id,
                        multi_afl=multi_afl
                        )
    
    early_crash = False
    try:
        fzr.start() #
        # start a listening for inputs produced by driller 
        start_listener(fzr)
        
        #start a listenin for collecting crashes
        start_collecting_crash(fzr)  #考虑一下,如果没有json呢

        # clean all stale redis data
        clean_redis(fzr)

        # list of 'driller request' each is a celery async result object
        driller_jobs = list() # 添加的是 @app.task包装的函数
        
        time.sleep(2)#
        #record the start
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #db ddefault is 1
        if fzr.time_limit is None:
            redis_inst.publish("tasks", binary+' start'+' each time is '+' no limited') 
        else:
            redis_inst.publish("tasks", binary+' start'+' each time is '+str(fzr.time_limit/60)+' minites') 
            
        # not fzr.found_crash()  and
        while_num=0
        crash_num=0
        while   not fzr.timed_out(): 
            #crash_num=fzr.crashes()  #得到signal 11 和4 的数量 所有引擎的数量
            if driller_engine:
                if 'fuzzer-master' in fzr.stats and 'pending_favs' in fzr.stats['fuzzer-master']:  
                    if not int(fzr.stats['fuzzer-master']['pending_favs']) > 50000: #
                        l.info("[%s] driller being requested!", binary) 
                        driller_jobs.extend(request_drilling(fzr))  #
            print "start another while at %d"  %while_num
            while_num+=1           
            time.sleep(config.CRASH_CHECK_INTERVAL) #
        # make sure to kill the fuzzers when we're done
        #保存信息到log
        
        
        fzr.kill()
        gc.collect()
        
    #except Exception as e:
    except StopIteration as e:
#     except fuzzer.EarlyCrash:
        fzr.kill()
        gc.collect()
        #l.info("binary crashed on dummy testcase, moving on...")
        l.info("binary Exception %s",e)
        early_crash = True

#     # we found a crash!
#     if early_crash or fzr.found_crash():
#         l.info("found crash for \"%s\"", binary_path)
# 
#         # publish the crash  
#         redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #db ddefault is 1
#         redis_inst.publish("crashes", binary) 
#         
#         # revoke any driller jobs which are still working
#         for job in driller_jobs:
#             if job.status == 'PENDING':
#                 job.revoke(terminate=True)

    if early_crash or fzr.timed_out():
        # publish the time_out tasks
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #db ddefault is 1
        redis_inst.publish("tasks", binary+' time_out') 
        l.info("timed out while fuzzing \"%s\"", binary)
        
        #revoke any driller jobs which are still working
#         for job in driller_jobs:
#             if job.status == 'PENDING':
#                 job.revoke(terminate=True) ##??

    # TODO end drilling jobs working on the binary


    #return fzr.found_crash() or early_crash



