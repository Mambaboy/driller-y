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

from sys import argv
import simuvex
import shutil
import signal
import sys
import gc

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
    fuzz_bitmap = redis_inst.hget(binary + '-bitmaps', bitmap_hash)  #get the bitmap  
    if fuzz_bitmap is None:
        fuzz_bitmap="\xff" * 65535 #
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
    
    #-------------------------complete-------------------------------   
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
    while not os.path.exists(bitmap_f):
        pass
    ##end--------------------------------------------------------
    l.info("fuzz_bitmap is generated, go on")
     
    bitmap_data = open(bitmap_f, "rb").read() #bitmap
    bitmap_hash = hashlib.sha256(bitmap_data).hexdigest() #
     
    redis_inst = redis.Redis(connection_pool=redis_pool) #
    redis_inst.hset(fzr.binary_id + '-bitmaps', bitmap_hash, bitmap_data) #

    ##get inputs
    in_dir = os.path.join(fzr.out_dir, "fuzzer-master", "queue") #
    if fzr.inputs_sorted :
        inputs=fzr.get_inputs_by_distance("fuzzer-master") #绝对路径,有很多空字符串
        inputs.extend(filter(lambda d: not d.startswith('.') and os.path.basename(d) not in inputs, os.listdir(in_dir))); # 这个路径是
    else:
        ##get the inputs in turns
        inputs = filter(lambda d: not d.startswith('.'), os.listdir(in_dir))
    
    # filter inputs which have already been sent to driller
    inputs = input_filter(os.path.join(fzr.out_dir, "fuzzer-master"), inputs) # 删除已经跟踪的

    # submit a driller job for each item in the queue  
    for input_file in inputs: 
        if fzr.timed_out():
            l.info("fuzzzer time out ")
            break #如果fuzzer停了,符号执行也停
        input_data_path = os.path.join(in_dir, input_file) #这里即使input_file是绝对路径也没有关系
        input_data = open(input_data_path, "rb").read()  # 
        # d_jobs.append(drill.delay(fzr.binary_id, input_data, bitmap_hash, get_fuzzer_id(input_data_path)))
        d_jobs.append(drill(
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



@app.task  
def fuzz(binary_path,input_from,afl_input_para,afl_engine,comapre_afl,inputs_sorted):
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
    
    #
    # look for a pcap
#     pcap_path = os.path.join(config.PCAP_DIR, "%s.pcap" % binary)
#     if os.path.isfile(pcap_path):
#         l.info("found pcap for binary %s", binary)
#         seeds = pcap.process(pcap_path)
#     else:
#         l.warning("unable to find pcap file, will seed fuzzer with the default")

    
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
                        inputs_sorted=inputs_sorted)
    
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



