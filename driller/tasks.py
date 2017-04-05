#coding=utf-8
import fuzzer
import hashlib
import logging
import os
import subprocess
import time

from celery import Celery
import config
import redis

from driller import Driller
import pcap

l = logging.getLogger("driller.tasks")
#l.setLevel(logging.DEBUG)

backend_url = "redis://%s:%d" % (config.REDIS_HOST, config.REDIS_PORT) #
app = Celery('tasks', broker=config.BROKER_URL, backend=backend_url)
app.conf.CELERY_ROUTES = config.CELERY_ROUTES
app.conf['CELERY_ACKS_LATE'] = True
app.conf['CELERYD_PREFETCH_MULTIPLIER'] = 1

redis_pool = redis.ConnectionPool(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #一个链接池

def get_fuzzer_id(input_data_path): #get testcase-id in the queue catalog 删减一些名称
    # get the fuzzer id
    abs_path = os.path.abspath(input_data_path)
    if "sync/" not in abs_path or "id:" not in abs_path:
        l.warning("path %s, cant find fuzzer id", abs_path)
        return "None"
    fuzzer_name = abs_path.split("sync/")[-1].split("/")[0]
    input_id = abs_path.split("id:")[-1].split(",")[0]
    return fuzzer_name + ",src:" + input_id

@app.task
def drill(binary, input_data, bitmap_hash, tag):
    redis_inst = redis.Redis(connection_pool=redis_pool) #连接redis数据库
    #fuzz_bitmap = redis_inst.hget(binary + '-bitmaps', bitmap_hash) #get the bitmap  在request_drilling是上传的,也算是即时从文件中读取的
    fuzz_bitmap="\xff" * 65535
    binary_path = os.path.join(config.BINARY_DIR, binary) #目标程序路径
    #配置driller信息
    driller = Driller(binary_path, input_data, fuzz_bitmap, tag, redis=redis_inst) #tag是 类如 fuzzer-master,src:000108
    try:
        return driller.drill() #得到的路径保存在 driller._generated集合中
    except Exception as e:
        l.error("encountered %r exception when drilling into \"%s\"", e, binary) #遇见错误
        l.error("input was %r", input_data)

def input_filter(fuzzer_dir, inputs): #这个函数在task中,也没有考虑到非字符串的情况

    traced_cache = os.path.join(fuzzer_dir, "traced")

    traced_inputs = set()
    if os.path.isfile(traced_cache):
        with open(traced_cache, 'rb') as f:
            #这里可能可以改成hash的形式
            traced_inputs = set(f.read().split('\n')) #分隔符默认为所有的空字符 这里为什么要分割?

    new_inputs = filter(lambda i: i not in traced_inputs, inputs)

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

    d_jobs = [ ] #利用一个测试用例发现新路径的数量


    bitmap_f = os.path.join(fzr.out_dir, "fuzzer-master", "fuzz_bitmap") 
    
    ##add by yyy---------------------------------------------------
    ##to assure the file is exit
    l.info("waiting for fuzz_bitmap")
    while not os.path.exists(bitmap_f):
        pass
          
    ##end--------------------------------------------------------
    l.info("fuzz_bitmap is generated, go on")
    
    bitmap_data = open(bitmap_f, "rb").read() #bitmap文件
    bitmap_hash = hashlib.sha256(bitmap_data).hexdigest() #文件内容的hash

    redis_inst = redis.Redis(connection_pool=redis_pool) #一个链接实例
    redis_inst.hset(fzr.binary_id + '-bitmaps', bitmap_hash, bitmap_data) #发送bitmap, hset function 一个name对应一个dic来存储 , 发布到池子里

    
    in_dir = os.path.join(fzr.out_dir, "fuzzer-master", "queue") #AFL生成测试用例的目录
    
    # ignore hidden files
    inputs = filter(lambda d: not d.startswith('.'), os.listdir(in_dir))  #queue下的测试用例

    # filter inputs which have already been sent to driller
    
    inputs = input_filter(os.path.join(fzr.out_dir, "fuzzer-master"), inputs) #过滤已经传递给drill的测试用例 在输出目录下traced文件记录已经传递给driller的测试用例

    # submit a driller job for each item in the queue  对每个测试用例符号执行跑
    for input_file in inputs:
        input_data_path = os.path.join(in_dir, input_file) 
        input_data = open(input_data_path, "rb").read() #读取测试用例内容
        #d_jobs.append(drill.delay(fzr.binary_id, input_data, bitmap_hash, get_fuzzer_id(input_data_path)))
        d_jobs.append(drill(fzr.binary_id, input_data, bitmap_hash, get_fuzzer_id(input_data_path))) #这里只传bitmap_hash, 具体内容通过redis传
        #这里应该可以通过某一种机制,将结果告诉afl, 然后afl就可以用了
    return d_jobs

def start_listener(fzr):
    '''
    start a listener for driller inputs
    '''

    driller_queue_dir = os.path.join(fzr.out_dir, "driller", "queue") #用于保存符号执行生成测试用例的目录
    channel = "%s-generated" % fzr.binary_id  #监听测试用例的信道

    # find the bin directory listen.py will be installed in
    base = os.path.dirname(__file__)

    while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
        base = os.path.join(base, "..")

    if os.path.abspath(base) == "/":
        raise Exception("could not find driller listener install directory")

    args = [os.path.join(base, "bin", "driller", "listen.py"), driller_queue_dir, channel]
    p = subprocess.Popen(args) #启动listen.py  

    # add the proc to the fuzzer's list of processes
    fzr.procs.append(p) #添加进程对象

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

@app.task  #注意这个修饰符号, 表示被包装调用,可以传递参数
def fuzz(binary): #这里的参数只有程序名称,所以主函数的目标程序目录和config下的都要配置,且需要一致

    l.info("beginning to fuzz \"%s\"", binary)

    binary_path = os.path.join(config.BINARY_DIR, binary)
    
    ##add by yyy---------------------------------
    ## setup the seed testcase
    #seeds = ["fuzz"] # 初始测试用例
    seeds=[]
    seed_dir = config.SEED
    for seed in os.listdir(seed_dir):  # 遍历多个目标程序, 这里是程序名称
        # 复制seed到input目录
        with open(os.path.join(seed_dir, seed), 'rb') as f:  #b 表示一个二进制文件
            seeds.append(f.read())
            f.close()
    ##end--------------------------------------------------------
    
    ##annotation by yyy----------------------------------------------
    #配置种子测试用例 , 语料库
    # look for a pcap
#     pcap_path = os.path.join(config.PCAP_DIR, "%s.pcap" % binary)
#     if os.path.isfile(pcap_path):
#         l.info("found pcap for binary %s", binary)
#         seeds = pcap.process(pcap_path)
#     else:
#         l.warning("unable to find pcap file, will seed fuzzer with the default")
    #end---------------------------------------------------

    
    # TODO enable dictionary creation, this may require fixing parts of the fuzzer module
   ##annotation by yyy---------------------
   #fzr = fuzzer.Fuzzer(binary_path, config.FUZZER_WORK_DIR, config.FUZZER_INSTANCES, seeds=seeds, create_dictionary=True)
    ##end-----------------------
    
    ##add by yyy---------------------------------------------
    #这里暂时不用字典生成,这个字典生成是利用控制流图方面的
    fzr = fuzzer.Fuzzer(binary_path, config.FUZZER_WORK_DIR, config.FUZZER_INSTANCES, seeds=seeds, create_dictionary=False)
    ##end ----------------------------
    
    early_crash = False
    try:
        fzr.start() #启动afl

        # start a listening for inputs produced by driller 启动监听对象,将新的测试用例保存到driller目录中
        start_listener(fzr)

        # clean all stale redis data
        clean_redis(fzr)

        # list of 'driller request' each is a celery async result object
        driller_jobs = [ ] #记录每次调用driller后的结果

        # start the fuzzer and poll for a crash, timeout, or driller assistance  
        #while not fzr.found_crash() and not fzr.timed_out():  # 此时afl不会暂停, 继续跑
        while not fzr.timed_out():  # 此时afl不会暂停, 继续跑; 可以自定义退出条件
            # check to see if driller should be invoked
            
            if 'fuzzer-master' in fzr.stats and 'pending_favs' in fzr.stats['fuzzer-master']:  

                if not int(fzr.stats['fuzzer-master']['pending_favs']) > 510000:
                    l.info("[%s] driller being requested!", binary) 
                    driller_jobs.extend(request_drilling(fzr))  #调用符号执行, extend表示在list末尾添加多个值
                    
                    
                    
            time.sleep(config.CRASH_CHECK_INTERVAL) #间隔时间

        # make sure to kill the fuzzers when we're done
        fzr.kill()

    except fuzzer.EarlyCrash:
        l.info("binary crashed on dummy testcase, moving on...")
        early_crash = True

    # we found a crash!
    if early_crash or fzr.found_crash():
        l.info("found crash for \"%s\"", binary)

        # publish the crash  提供信息
        redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #db默认是1
        redis_inst.publish("crashes", binary) #发现crash,发布信息

        # revoke any driller jobs which are still working
        for job in driller_jobs:
            if job.status == 'PENDING':
                job.revoke(terminate=True)

    if fzr.timed_out():
        l.info("timed out while fuzzing \"%s\"", binary)

    # TODO end drilling jobs working on the binary

    return fzr.found_crash() or early_crash
