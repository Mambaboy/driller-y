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
from plumbum.cli.switches import switch

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
    return fuzzer_name + ",src:" + input_id

@app.task
def drill(binary_path, input_data, input_data_path, bitmap_hash, tag, input_from, afl_input_para,time_limit_for_pro):
    '''
    :@param time_limit_for_pro:针对每个目标程序的执行时间
    '''
    binary=os.path.basename(binary_path)
    redis_inst = redis.Redis(connection_pool=redis_pool) #
    fuzz_bitmap = redis_inst.hget(binary + '-bitmaps', bitmap_hash)  #get the bitmap   ##这是一个长传的字符,131072个字符.可以用[]读取,但是不能赋值
    if fuzz_bitmap is None:
        fuzz_bitmap="\xff" * 131072 #debug用
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
        add_exclude_sim_pro=["stat"]
    else:
        l.error("the input argv in driller is error")
    #add_env={"HOME": os.environ["HOME"]}   
    add_env=None
    #complete confifure --------------------------------------------------------  


    driller = Driller(binary_path, input_data, input_data_path, fuzz_bitmap, tag, redis=redis_inst,argv=yargv,
                      add_fs=add_fs,add_env=add_env,add_exclude_sim_pro=add_exclude_sim_pro,
                      time_limit_for_pro=time_limit_for_pro, sy_ex_time_limit=10*60
                      ) 
    #tag fuzzer-master,src:000108
    
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
#     while not os.path.exists(bitmap_f):
#         pass
#     ##end--------------------------------------------------------
#     l.info("fuzz_bitmap is generated, go on")
#           
#     bitmap_data = open(bitmap_f, "rb").read() #bitmap
#     bitmap_hash = hashlib.sha256(bitmap_data).hexdigest() #
#     redis_inst = redis.Redis(connection_pool=redis_pool) #
#     redis_inst.hset(fzr.binary_id + '-bitmaps', bitmap_hash, bitmap_data) # 构建hash对
    
    bitmap_hash=None # for debug
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
    inputs = input_filter(os.path.join(fzr.out_dir, "fuzzer-master"), inputs) # 删除已经跟踪的
    #------------------------------------------------------------------------
    
    
    # submit a driller job for each item in the queue  
    for input_file in inputs: 
        if fzr.timed_out():
            l.info("fuzzzer time out ")
            break #如果fuzzer停了,符号执行也停
        input_data_path = os.path.join(in_dir, input_file) #这里即使input_file是绝对路径也没有关系
        input_data = open(input_data_path, "rb").read()  # 
        # d_jobs.append(drill.delay(fzr.binary_id, input_data, bitmap_hash, get_fuzzer_id(input_data_path)))
        d_jobs.append(
                drill(
                fzr.binary_path,
                input_data, 
                input_data_path, 
                bitmap_hash, 
                get_fuzzer_id(input_data_path), 
                input_from=fzr.input_from, 
                afl_input_para=fzr.afl_input_para,
                time_limit_for_pro=fzr.time_limit)
                )  # 
        
    return d_jobs #当前的测试用例跑完了,退出看看time_out,没有的

def start_listener(fzr):
    '''
    start a listener for driller inputs
    '''

    driller_queue_dir = os.path.join(fzr.out_dir, "driller", "queue") #
    channel = "%s-generated" % fzr.binary_id  #

    # find the bin directory listen.py will be installed in
    base = os.path.dirname(__file__)

    while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
        base = os.path.join(base, "..")

    if os.path.abspath(base) == "/":
        raise Exception("could not find driller listener install directory")

    args = [os.path.join(base, "bin", "driller", "listen.py"), driller_queue_dir, channel]
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



@app.task  
def fuzz(binary_path,input_from,afl_input_para,afl_engine,comapre_afl,inputs_sorted,strategy_id):
    '''
    @param strategy_id: the id of strategy, 0,1,2,3,4,5,6,7 
    '''
    #     return
    binary=os.path.basename(binary_path)
    l.info("beginning to fuzz \"%s\"", binary)
    seeds=[]
    seed_dir = config.SEED
    for seed in os.listdir(seed_dir):  # 
        # copy seed to input catalory
        with open(os.path.join(seed_dir, seed), 'rb') as f:  
            seeds.append(f.read())
            f.close()
    ##end--------------------------------------------------------
    
    # TODO enable dictionary creation, this may require fixing parts of the fuzzer module
    #fzr = fuzzer.Fuzzer(binary_path, config.FUZZER_WORK_DIR, config.FUZZER_INSTANCES, seeds=seeds, create_dictionary=True)
    
    #no dictionary
    fzr = fuzzer.Fuzzer(binary_path, 
                        config.FUZZER_WORK_DIR, 
                        config.FUZZER_INSTANCES,
                        seeds=seeds, 
                        create_dictionary=False,
                        afl_engine=afl_engine,
                        input_from=input_from,
                        afl_input_para=afl_input_para,
                        time_limit=15*60, #second fuzz and symbolic execution time
                        comapre_afl=comapre_afl,
                        strategy_id=strategy_id
                        )
    
    early_crash = False
    try:
        fzr.start() #
        # start a listening for inputs produced by driller 
        start_listener(fzr)

        # clean all stale redis data
        clean_redis(fzr)

        # list of 'driller request' each is a celery async result object
        driller_jobs = list() # 添加的是 @app.task包装的函数
        
        time.sleep(2)#
        #record the start
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #db ddefault is 1
        redis_inst.publish("tasks", binary+' start'+' each time is '+str(fzr.time_limit/60)+' minites') 
        
        # start the fuzzer and poll for a crash, timeout, or driller assistance  
        #while not fzr.found_crash() and not fzr.timed_out():  # 
        while  not fzr.timed_out():  # 
            if 'fuzzer-master' in fzr.stats and 'pending_favs' in fzr.stats['fuzzer-master']:  
                if not int(fzr.stats['fuzzer-master']['pending_favs']) > 510000: #
                    l.info("[%s] driller being requested!", binary) 
                    driller_jobs.extend(request_drilling(fzr))  # 
            time.sleep(config.CRASH_CHECK_INTERVAL) #
        # make sure to kill the fuzzers when we're done
        fzr.kill()
        gc.collect()
        
    except Exception as e:
#     except fuzzer.EarlyCrash:
        l.info("binary crashed on dummy testcase, moving on...")
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

    return fzr.found_crash() or early_crash



