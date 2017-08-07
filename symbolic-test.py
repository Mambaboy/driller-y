#!/usr/bin/env python
#coding=utf-8
import os
import sys
import driller.tasks
import shutil
import redis
import subprocess
import time
import driller.config as config

back_pro=[]

def clean_redis(binary):
    redis_pool = redis.ConnectionPool(host=driller.config.REDIS_HOST, port=driller.config.REDIS_PORT, db=driller.config.REDIS_DB) 
    redis_inst = redis.Redis(connection_pool=redis_pool)
    # delete all catalogued inputs
    redis_inst.delete("%s-catalogue" % binary)
    # delete all the traced entries
    redis_inst.delete("%s-traced" % binary)
    # delete the finished entry
    redis_inst.delete("%s-finsihed" % binary)
    # delete the fuzz bitmaps
    redis_inst.delete("%s-bitmaps" % binary)
    # delete the symmap
    redis_inst.delete("%s-symmap" % binary)
    
def start_listener(workdir):
#     driller_queue_dir = os.path.join(workdir, "symbolic", "queue")
    driller_queue_dir = workdir
    binary_id=os.path.basename(workdir)
    channel = "%s-generated" % binary_id  #监听测试用例的信道
    base="/home/xiaosatianyu/workspace/git/driller-yyy/driller"
    args = [ os.path.join(base, "bin", "driller", "listen.py"),  driller_queue_dir,  channel ]
    p = subprocess.Popen(args) #启动listen.py   #要启动这个脚本成功,必须在driller的目录下
    back_pro.append(p)
    pass
def get_seed(seed_dir):
    inputs=[]
    if os.path.exists(seed_dir) :
        inputs=os.listdir(seed_dir)
        inputs.sort()
    else:
        l.error("there is no seed dir")
    return inputs

#开始符号执行    
def start_sym_test(binary_path):
    binary_id=os.path.basename(binary_path)
    
    #test-cases dir
#     seed_dir=os.path.join("/home/xiaosatianyu/Desktop/driller-desk",binary_id)
    seed_dir=os.path.join("/home/xiaosatianyu/Desktop/driller-desk","seed")
    
    #some special configuration
    bitmap_hash="hello"
    
    #input configuration
    #input_from="file" 
    #afl_input_para=["@@"]
    input_from="stdin"
    afl_input_para=[]
    
    #initial prepare 
    workdir=os.path.join("/tmp/symbolic",binary_id)
    if os.path.exists(workdir):
            shutil.rmtree(workdir) #删除工作目录, 此时尚未生成相关的目录,所以先删除一下没事
    clean_redis(binary_id)
    start_listener(workdir)      
    
        
    #开始符号执行
    #这里怎么管理轨迹呢?
    #每个input都要重新搞一个Driller类
    inputs=get_seed(seed_dir) #这里可以增加调度吗
    for input_file in inputs:
        input_data_path=os.path.join(seed_dir,input_file)
        input_data = open(input_data_path, "rb").read() #读取测试用例内容
        tag=input_file
        try:
            driller.tasks.drill(binary_path, 
                        input_data, 
                        input_data_path, 
                        bitmap_hash, 
                        tag, 
                        input_from, 
                        afl_input_para,
                        18*60)
        except Exception as e: 
            pass
    
    #关闭当前的listen
    for p in back_pro:
        p.terminate()
        p.wait()

#end start_sym_test

       
#单纯符号执行    
if __name__ == "__main__":
    binaries_dir=config.BINARY_DIR_CGC_TEST
    target_pros=os.listdir(binaries_dir)
    target_pros.sort()
    for pro in target_pros:
#         if os.path.exists(os.path.join("/tmp/driller",pro)):
#             #表示已经存在了
#             continue
        target_pro_path=os.path.join(binaries_dir,pro)
        print "deal with %s" % os.path.basename(target_pro_path)
        start_sym_test(target_pro_path)
        
    sys.exit()
