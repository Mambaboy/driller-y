#coding=utf-8

'''
直接在afl-fast上进行修改, 先不用在yyy上进行修改.,修改的时候加宏定义
1. Random Ordering(Random)随机排序,从AFL产生的测试用例中随机选择下一个测试用例(AFL输出测试用例,python实现随机乱序排列)(AFl不用,python随机乱序)
2. Branch Total (BT)轨迹长度优先,优选较长的测试用例,重复的轨迹重复记录(AFL所有测试用例集合的排序后轨迹长度,python实现读取)(AFL输出排序后的轨迹长度,python按照顺序选择)
2.1 Branch Total (BT)轨迹长度优先,优选较长的测试用例,不记录重复轨迹.(AFL输出排序后的轨迹长度,python按照顺序选择)
3. Branch Additional (BA)根据增加长度对测试用例进行排序?  (第一次,全部加入)筛选出每一轮新增加的,将这些新增加的和上次做过符号执行的测试用例集进行比较,
                    分别计算出这些新的测试用例和就测试用例集合之间的基本块插件,从高低排序.(python中建立一个集合,记录所有符号执行过(包括在线和离线部分)的轨迹集合,
                    计算新的测试用例和这些轨迹差之间的差值,然后从高往低排序,即优先处理高差值的测试用例
                    (实现方法,afl输出测试用例的轨迹,python中实现排序)
                    (python中用一个有序的容器记录轨迹会比较方便)
                    (AFL输出测试用例的轨迹(元组值),python中进行排序,利用数据库输出吧)
4. (FPF,可以叫做min-max),计算当前测试用例与所有其他测试用例之间的距离(汉明距离)(每次AFL生成新测试用例时时计算)(如果新生成一个测试用例,比如e,且ea的距离小于a的属性,
                        则更新a的属性),选取最小值作为距离属性,然后按照属性值从大往小取
5. 最短优先策略()重复记录和不重复记录两种(可以在AFl输出中排序,python负责筛选)
'''
import os
import random # 乱序模块
import redis
import config
import logging

l = logging.getLogger("driller.sort_strategy")

redis_pool = redis.ConnectionPool(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB) #
redis_inst = redis.Redis(connection_pool=redis_pool) 

##0 NO_SORT_0************************************************************************
#ok
def no_sort_0(in_dir, fzr):
    '''
    read from in_dir, and sort them in chaos
    '''
    inputs = filter(lambda d: not d.startswith('.'), os.listdir(in_dir))
    inputs.sort() #从小到大的顺序
    return inputs 
##0 end NO_SORT_0---------------------------------------------------------------------------



##1 Random_Sort_1************************************************************************
#ok
def random_sort_1(in_dir, fzr):
    '''
    read from in_dir, and sort them in chaos
    '''
    inputs = filter(lambda d: not d.startswith('.'), os.listdir(in_dir))
    random.shuffle(inputs)#乱序
    return inputs 
##end Random_Sort_1---------------------------------------------------------------------------


#2 BT_dup_Sort_2************************************************************************
def BT_dup_sort_2(in_dir, fzr):
    '''
    AFL sort the test cases by distance, keep the duplicate block
    '''
    inputs = []
    if os.path.isdir(fzr.out_dir):
            record_path = os.path.join(fzr.out_dir, "fuzzer-master", "afl_to_angr") 
            if os.path.isfile(record_path):
                with open(record_path, "rb") as f:
                    content = f.read()
                    lines = content.split("\n")[1:-1]
                    for line in lines:
                        inputs_line = line.split(";")
                        inputs_line[0] = os.path.basename(inputs_line[0].strip())
                        if inputs_line[0].strip() not in inputs  and  inputs_line[0] != "":
                            inputs.append(inputs_line[0].strip())
            else:
                fzr.strategy_id = '0'                
    
    ##加载剩下的测试用例
#     inputs.extend(filter(lambda d: not d.startswith('.') and os.path.basename(d) not in inputs, os.listdir(in_dir)));
    return inputs

#end 2 BT_dup_Sort_2------------------------------------------------------------------------------------

#3 BT_no_dup_sort_3************************************************************************
def BT_nodup_sort_3(in_dir, fzr):
    '''
    AFL sort the test cases by distance, duplicate block only count as one 
    '''
    inputs = []
    if os.path.isdir(fzr.out_dir):
            record_path = os.path.join(fzr.out_dir, "fuzzer-master", "afl_to_angr") 
            if os.path.isfile(record_path):
                with open(record_path, "rb") as f:
                    content = f.read()
                    lines = content.split("\n")[1:-1]
                    for line in lines:
                        inputs_line = line.split(";")
                        inputs_line[0] = os.path.basename(inputs_line[0].strip())
                        if inputs_line[0].strip() not in inputs  and  inputs_line[0] != "":
                            inputs.append(inputs_line[0].strip())
            else:
                fzr.strategy_id = '0'                

    ##加载剩下的测试用例
#     inputs.extend(filter(lambda d: not d.startswith('.') and os.path.basename(d) not in inputs, os.listdir(in_dir)));
    return inputs
#end 3 BT_no_dup_Sort_3--------------------------------------------------------------------------------------


#4 BA_sort_4 ************************************************************************
def BA_sort_4(in_dir, fzr):
    '''
    从afl中读取一个文件,该文件中记载了每个测试用例trace_mini的文件位置
    '''
    #debug
#     out_dir="/tmp/driller/CROMU_00057/sync"
#     in_dir = os.path.join(out_dir, "fuzzer-master", "queue")
#     binary_id='CROMU_00057'

#     trace_mini_path=os.path.join(out_dir,"fuzzer-master","queue_trace_mini")
    trace_mini_path=os.path.join(fzr.out_dir,"fuzzer-master","queue_trace_mini")
    
    trace_mini_inputs=os.listdir(trace_mini_path)
    
#     input_filter(os.path.join(out_dir, "fuzzer-master"),trace_mini_inputs)
    input_filter(os.path.join(fzr.out_dir, "fuzzer-master"),trace_mini_inputs)
    
    #还要过滤掉已经记录的程序,避免再打开关闭文件
    trace_mini_inputs.sort()
    
    #得到符号执行的轨迹
    ##比较每个测试用例和符号轨迹之间的距离,并按照距离排序
#     redis_inst.sadd(fzr.binary_id+'-symmap', 1)  
#     a=redis_inst.sismember(fzr.binary_id+'-symmap', 1)   #true
#     b=redis_inst.sismember(fzr.binary_id+'-symmap', '1')   #true
#     
#     redis_inst.sadd(fzr.binary_id+'-symmap', '2')   
#     a=redis_inst.sismember(fzr.binary_id+'-symmap', 2)   #true
#     b=redis_inst.sismember(fzr.binary_id+'-symmap', '2')  #true
    
    record=[]
    for trace_mini in trace_mini_inputs:
        if "total" in trace_mini: continue
        
#         target=os.path.join(out_dir,"fuzzer-master","queue_trace_mini",trace_mini)
        target=os.path.join(fzr.out_dir,"fuzzer-master","queue_trace_mini",trace_mini)
        
        if not os.path.exists(  target ) :
            l.error("the trace_mini is wrong")
        with open(target, "rb") as f:
            distance=0
            content = f.read()
            lines = content.split("\n")[1:-1] 
            for line in lines:
                line=line.strip() #注意去掉空格
                #查看对应的元素是否在符号执行轨迹里, 不在则加1 
#                 aa=redis_inst.smembers(binary_id+'-symmap')
#                 if redis_inst and not redis_inst.sismember(binary_id+'-symmap', line):  #line是str
                if redis_inst and not redis_inst.sismember(fzr.binary_id+'-symmap', line):  #line是str
                    distance+=1
                else:
                    pass #for debug  
                    distance+=0  
        record.append((trace_mini,distance))
        
    #根据与符号执行轨迹距离进行排序距离排序    
    sorted_record = sorted(record, key=lambda testcase : testcase[1], reverse=True) #key这里指定一个函数，即读取每个元素的某个域的值
    
    ##输出测试用例的排序
    inputs=[]
    for test_record in sorted_record:
        inputs.append(test_record[0])
    return inputs
    
#end 4 BA_Sort_4--------------------------------------------------------------------------------------

#5 Min_Max_Sort_5 ************************************************************************
def min_max_sort_5(in_dir, fzr):
    '''
    AFL calculate the new found testcase with all before testcases by hamming distance
    select the minimum as the attribution
    sort the testcases according by the attribution from large to small
    '''
    inputs = []
    if os.path.isdir(fzr.out_dir):
            record_path = os.path.join(fzr.out_dir, "fuzzer-master", "afl_to_angr") 
            if os.path.isfile(record_path):
                with open(record_path, "rb") as f:
                    content = f.read()
                    lines = content.split("\n")[1:-1]
                    for line in lines:
                        inputs_line = line.split(";")
                        inputs_line[0] = os.path.basename(inputs_line[0].strip())
                        inputs_line[1] = os.path.basename(inputs_line[1].strip())
                        if inputs_line[0].strip() not in inputs and not inputs_line[0] == "":
                            inputs.append(inputs_line[0].strip())
                        if inputs_line[1].strip() not in inputs and not inputs_line[1] == "":    
                            inputs.append(inputs_line[1].strip())
            else:
                fzr.inputs_sorted = False                
    
    ##加载剩下的测试用例
    #inputs.extend(filter(lambda d: not d.startswith('.') and os.path.basename(d) not in inputs, os.listdir(in_dir)));
    
    return inputs
#end 5 Min_Max_Sort_5--------------------------------------------------------------------------------------



#6 Short_first_Sort_6 ************************************************************************
def short_first_sort_6(in_dir, fzr):
    '''
    AFL sort the test cases by distance, duplicate block only count as one, the　short ones are converted to angr first 
    '''
    inputs = []
    if os.path.isdir(fzr.out_dir):
            record_path = os.path.join(fzr.out_dir, "fuzzer-master", "afl_to_angr") 
            if os.path.isfile(record_path):
                with open(record_path, "rb") as f:
                    content = f.read()
                    lines = content.split("\n")[1:-1]
                    for line in lines:
                        inputs_line = line.split(";")
                        inputs_line[0] = os.path.basename(inputs_line[0].strip())
                        if inputs_line[0].strip() not in inputs  and  inputs_line[0] != "":
                            inputs.append(inputs_line[0].strip())
            else:
                fzr.strategy_id = '0'                
                
    ##加载剩下的测试用例
#     inputs.extend(filter(lambda d: not d.startswith('.') and os.path.basename(d) not in inputs, os.listdir(in_dir)));
    
    return inputs
#end 5 Short_first_Sort_6--------------------------------------------------------------------------------------


#7  Short_by_hamming_7***********************************************************************************************
def hamming_sort_7(in_dir, fzr):
    '''
    按照hanmming距离排序，距离大的且轨迹长的优先．
    '''
    inputs = []
    if os.path.isdir(fzr.out_dir):
            record_path = os.path.join(fzr.out_dir, "fuzzer-master", "afl_to_angr") 
            if os.path.isfile(record_path):
                with open(record_path, "rb") as f:
                    content = f.read()
                    lines = content.split("\n")[1:-1]
                    for distance_power in lines:
                        inputs_line = distance_power.split(";")
                        inputs_line[0] = os.path.basename(inputs_line[0].strip())
                        inputs_line[1] = os.path.basename(inputs_line[1].strip())
                        if inputs_line[0].strip() not in inputs and not inputs_line[0] == "":
                            inputs.append(inputs_line[0].strip())
                        if inputs_line[1].strip() not in inputs and not inputs_line[1] == "":    
                            inputs.append(inputs_line[1].strip())
            else:
                fzr.inputs_sorted = False                
    ##加载剩下的测试用例
#     inputs.extend(filter(lambda d: not d.startswith('.') and os.path.basename(d) not in inputs, os.listdir(in_dir)));
    
    return inputs
#end 7 -------------------------------------------------------------------------------------------------------------


##general function ----------------------------------------------------------------------------------------------------
def input_filter(fuzzer_dir, inputs): #

    traced_cache = os.path.join(fuzzer_dir, "traced")

    traced_inputs = set()
    if os.path.isfile(traced_cache):
        with open(traced_cache, 'rb') as f:
            traced_inputs = set(f.read().split('\n')) 

    new_inputs = filter(lambda pro: pro not in traced_inputs, inputs)

    return new_inputs
