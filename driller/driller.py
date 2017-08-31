#coding=utf-8
import logging
from _ast import If
from audioop import add

l = logging.getLogger("driller.Driller")

import tracer
import angr
import os
import time
import signal
import resource
import cPickle as pickle
from itertools import islice, izip
import hashlib

import config #pylint:disable=relative-import
from sort_strategy import *

class DrillerEnvironmentError(Exception):
    pass

class DrillerMisfollowError(Exception):
    pass

class Driller(object):
    '''
    Driller object, symbolically follows an input looking for new state transitions
    '''

    def __init__(self, binary, input, input_data_path, fuzz_bitmap = "\xff" * 131072, tag=None, redis=None, hooks=None, argv=None,
                 add_fs=None,add_env=None,add_exclude_sim_pro={},time_limit_for_pro=None,sy_ex_time_limit=None): #pylint:disable=redefined-builtin
        '''
        :param binary: the binary to be traced
        :param input: input string to feed to the binary
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty)
        :param redis: redis.Redis instance for coordinating multiple Driller instances
        :param hooks: dictionary of addresses to simprocedures
        :param argv: Optionally specify argv params (pro,e,: ['./calc', 'parm1']) defaults to binary name with no params.
        :param fs: the Simfile to use
        :param add_env: the environment variable 
        :param add_exclude_sim_pro: the exclude simprocedure
        :param time_limit_for_pro: time limitation for drilling this binary
        :param sy_ex_time_limit: time limitation for once symbolic exploration
        '''

        self.binary      = binary
        # redis crash_target_dir identifier
        self.identifier  = os.path.basename(binary) #去除路径信息,得到程序名称
        self.input       = input
        self.input_data_path=input_data_path 
        self.fuzz_bitmap = fuzz_bitmap   #AFL bitmap 默认全时\xff
        self.tag         = tag  # fuzzer-master,src:000108 这样的,用于listen中生成测试用例的名称
        self.redis       = redis  #一个redis连接实例
        self.argv = argv or [binary] #带程序和参数的,或者直接不填;默认有程序
        ##yyy add
        self.add_fs=add_fs
        self.add_env=add_env
        self.add_exclude_sim_pro=add_exclude_sim_pro
        self.time_limit_for_pro =time_limit_for_pro
        self.sy_ex_time_limit   =sy_ex_time_limit
        self.start_time=time.time() # the start time of this drilling
        
        self.base = os.path.join(os.path.dirname(__file__), "..") #本模块所在目录的上一级, 即driller部分内

        # the simprocedures
        self._hooks = {} if hooks is None else hooks

        # set of encountered basic block transition 
        #记录当前测试用例的轨迹,以及符号执行过程中的轨迹 
        self._encounters = set()  #记录了测试用例的基本块跳转关系, 这个和bitmap好像是一样的吧? 元组值　每个元素是一个dict,表示跳跃
        
        # start time, set by drill method
        self.start_time       = time.time()

        # set of all the generated inputs
        self._generated       = set() #新建一个set集合 ,保存了符号执行发现的新的测试用例

        # set the memory limit specified in the config
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))

        l.info("[%s] drilling started on %s", self.identifier, time.ctime(self.start_time))

        self.fuzz_bitmap_size = len(self.fuzz_bitmap) # 和AFL中的这个数组大小一样,这里不一定是65536个字节
        
        # setup directories for the driller and perform sanity checks on the directory structure here
        if not self._sane(): #确定目标的可执行,读取执行权限
            l.error("[%s] environment or parameters are unfit for a driller run", self.identifier)
            raise DrillerEnvironmentError

### ENVIRONMENT CHECKS AND OBJECT SETUP

    def _sane(self):
        '''
        make sure the environment will allow us to run without any hitches(故障) 
        '''
        ret = True

        # check permissions on the binary to ensure it's executable
        if not os.access(self.binary, os.X_OK):
            l.error("passed binary file is not executable")
            ret = False

        return ret

### DRILLING

    def drill(self):
        '''
        perform the drilling, finding more code coverage based off our existing input base.
        '''
        l.info("start drill funtion")
        #sismember 函数, 检查value是否是name对应的集合内的元素, 即检查对应内容的测试用例是否被符号执行过
        if self.redis and self.redis.sismember(self.identifier + '-traced', self.input):  # self.identifier + '-traced'作为集合名,input作为元素.
            # don't re-trace the same input
            l.info("redis has not started or this input has be traced")
            return -1

        # Write out debug info if desired
        if l.level == logging.DEBUG and config.DEBUG_DIR:
            self._write_debug_info()
        elif l.level == logging.DEBUG and not config.DEBUG_DIR:
            l.warning("Debug directory is not set. Will not log fuzzing bitmap.")

        # update traced
        if self.redis:
            #sadd函数, 给第一个参数制定的集合添加元素, 后面的参数全是元素, 提交当前测试用例,用来标记已经符号执行过了
            self.redis.sadd(self.identifier + '-traced', self.input) #在redis中维护了一个数据结构,程序名称加'-traced'用来表示key
            
        #接下来生成新的测试用例, 此时的bitmap是固定的,这里没有返回值,但是应该也可以利用这些返回值的
        list(self._drill_input()) #  yield, 在原来的路径基础上,又多走了几步.
        #结果保存在 self._generated
        if self.redis: #如果服务器存在
            return len(self._generated)  # 0 利用这个初始测试用例没有办法发现新的路径
        else:
            return self._generated

    def drill_generator(self):
        '''
        A generator interface to the actual drilling.
        '''

        # set up alarm for timeouts
        if config.DRILL_TIMEOUT is not None:
            signal.alarm(config.DRILL_TIMEOUT)

        for pro in self._drill_input():
            yield pro

    def _drill_input(self):
        '''
        symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        state transitions.
        '''
        l.info("start _drill_input fucntion")
        # initialize the tracer
        t = tracer.Tracer(self.binary, self.input, hooks=self._hooks, argv=self.argv, 
                          add_fs=self.add_fs, add_env=self.add_env,add_exclude_sim_pro=self.add_exclude_sim_pro) #
        #这个trace是利用qemu跑一遍获得基本块链表,还没有符号执行
        
        self._set_concretizations(t) #具体化? 得到一些测试用例? 这个还不是很清楚,和unicorn有关 
        self._set_simproc_limits(t) #设置了一些libc库的上限
        
        # update encounters with known state transitions
        # islice(iterable, start, stop[, step]) ; islice(t.trace, 1, None)对一个list进行筛选, 去掉第一个基本块, stop是不达到的
        # izip可以生成两个迭代器之间的关系,生成dict形式的元素, izip的结果还是保持有序性的,多余的长度自动忽略
        #update后没有了有序性, 因为set是一个有序集合, 有固定排列顺序的
        self._encounters.update(izip(t.trace, islice(t.trace, 1, None))) #izip 把不同的迭代器元素聚合到一个迭代器 islice返回一个迭代器
        #---------------------------------------------------------------------------------------
        ##记录符号执行过的地址到在线数据库的self.binary+'-symmap',针对当前测试程序全部有效
        #sym_map=[]
        for  addrs in self._encounters:
            prev_loc = addrs[0] #上一个基本块的地址
            cur_loc = addrs[1] #当前基本块的地址
            self.add_to_sym_map(prev_loc,cur_loc) 
            #sym_map.append( self.add_to_sym_map(prev_loc,cur_loc) )
        #sym_map.sort()
        #测试符号执行轨迹的有用性
        #BA_sort_4(None,None) 
        #-----------------------------------------------------------------------------------------
         
        #l.debug("drilling into %r", self.input) 
        #l.debug("input is %r", self.input)
        l.info("drilling into %r",self.tag)
        
        #开始寻找下一个新的测试用例了
        # used for finding the right index in the fuzz_bitmap
        prev_loc = 0   #cgc的缓存要看一看
        branches = t.next_branch() # tracer.Tracer 下的函数, branches是 PathGroup类  get some missed state; 在这里 沿着原本的路径有一个active,沿着另一个有一个missed;即上一个地址处有一个分叉
        while len(branches.active) > 0 and t.bb_cnt < len(t.trace):  # Bool
            if  self.whole_driller_timed_out(): #the time limitation for this input
                l.info("next_branch time out ")
                break
            # check here to see if a crash has been found
            if self.redis and self.redis.sismember(self.identifier + "-finished", True):  #这里的crash由谁保存的?和AFL的crash冲突吗
                return  #表示当前路径是crash,不用继续了
            #mimic AFL's indexing scheme  模仿AFL中的插桩记录手法, 即将发现的新的branch,生成一个新的基本块跳转
            if len(branches.missed) > 0:  
                prev_addr = branches.missed[0].addr_trace[-1] # a bit ugly #上一个基本块的地址, 这个是history记录的
                prev_loc = prev_addr
                prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
                prev_loc &= self.fuzz_bitmap_size - 1
                prev_loc = prev_loc >> 1
                for path in branches.missed: 
                    cur_loc = path.addr #当前基本块的地址
                    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                    cur_loc &= self.fuzz_bitmap_size - 1
                    #hit为0表示，AFL没有执行过这块元组关系； hit为true，表示afl处理过这块元组关系
                    hit = bool(ord(self.fuzz_bitmap[cur_loc ^ prev_loc]) ^ 0xff)  #ord返回ascii码, AFL的fuzz_bitmap中0xff表示没有对应元组关系，默认0xff，表示没有，为0 表示出现过对应的元组关系
                    transition = (prev_addr, path.addr)
                    l.info("found %x -> %x transition", transition[0], transition[1])
                    #hit 表示AFL是否执行过这个基本块,0表示没有,1表示有
                    #self._has_encountered(transition) 表示angr是否执行过这个基本块, true表示有,false表示没有
                    #self._has_false(path) 表示这个基本块是否可以执行
                    if not hit and not self._has_encountered(transition) and not self._has_false(path):
#                         redis_inst.sismember(self.identifier+'-symmap',cur_loc ^ prev_loc) #表示测试其他测试用例时,符号执行过这个元组 调试
                        t.remove_preconstraints(path)  # 这个怎么去除预约束?
                        if path.state.satisfiable(): #表示约束可以满足吧
                            # a completely new state transitions, let's try to accelerate AFL
                            # by finding  a number of deeper inputs
                            l.info("found a completely new transition, exploring to some extent")#再前进一定的步数
                            
                            w = self._writeout(prev_addr, path, len(t.argv)) #输出新测试用例到redis数据库,w是一个tuple,一个是信息,第二个是生成的内容
                            if w is not None:
                                yield w  # 生成器, 返回的是一个tuple, 有关于新的测试用例
                            for pro in self._symbolic_explorer_stub(path): #找到一条新的路径之后,继续纯符号执行一定的步数至再产生累计1024个state
                                yield pro # 生成器
                        else:
                            l.debug("path to %#x was not satisfiable", transition[1])

                    else:
                        l.debug("%x -> %x has already been encountered,or not feasible", transition[0], transition[1])

            try:
                branches = t.next_branch()  # go on find the next branch 寻找到下一个分叉的两个选项 ,此时bb_cnt的数值延后
                #上一句之后,t.bb_cnt指向的是branches.active[0], t.bb_cnt可能是一下子增加很多
                if len(branches.active) >0:
                    #以下为调试
                    if  branches.active[0].state.addr in t.trace:
                        pass
                    if len(branches.missed) > 0: 
                        amissed=self._has_false(branches.missed[0])
                        aactive=self._has_false(branches.active[0])
                
            #except AttributeError: #debug
            except IndexError: #这个是哪里来的error
                branches.active = [ ] #清空 表示当前这条真实路径跑不下去了,开始下一个测试用例
    
### EXPLORER
    def _symbolic_explorer_stub(self, path):
        # create a new path group and step it forward up to 1024 accumulated active paths or steps
        #这里时间上会越来越慢
        steps = 0
        accumulated = 1
        start_time=time.time()
        p = angr.Project(self.binary) # 为了调用 p.factory 这里缺少了一些东西吧
        pg = p.factory.path_group(path, immutable=False, hierarchy=False) #这里这些参数的意义

        l.info("[%s] started symbolic exploration at %s", self.identifier, time.ctime())
        
#--------只跑一条路径 
#         while  accumulated < 100000:  #
#             def some_eq(pg):
#                 for pro in pg.active:
#                     if pro.state.scratch.guard.op=="__eq__" and not pro.state.addr in [134514675,134514660,134514690,134514705] or pro.state.addr in [134514810]:
#                         return True
#             pg.step(until=some_eq)
#             
#             
#             def remove_not_eq(path):
#                 if path.state.scratch.guard.op != "__eq__":
#                     return True
#             for pro in pg.active:
#                 if pro.state.scratch.guard.op=="__eq__":
#                     pg.drop(filter_func=remove_not_eq) #只保留等号约束的路径
#                     break;
                
            #path=successors[-1]
#             if len(successors) >1:
#                 pass
#                 for pro in successors:
#                     pass
#                     successors[pro].state.satisfiable() #这里的路径应该是全部可满足的
#                     successors[pro].state.scratch.guard #比较当前跳转的约束复杂 Bool
#                 path=successors[0]
#             steps += 1
            # dump all inputs
            #accumulated = steps * (len(pg.active) + len(pg.deadended)) #这里是一种探索方式的上限
            #l.info("symbolic exploration %d",accumulated)
#             if(new_path_num>old_path_num):  #found new path 
#                 for pro in xrange(new_path_num):
#                     try:
#                         if pg.active[pro].state.satisfiable(): #如果是可满足的
#                             w = self._writeout(pg.active[pro].addr_trace[-1], pg.active[pro])  # SimFile
#                             if w is not None:
#                                 yield w
#                                 #pass
#                     except IndexError: # if the path we're trying to dump wasn't actually satisfiable
#                         pass
#         l.info("[%s] symbolic exploration stopped at %s", self.identifier, time.ctime())
         
#---------每次发现新的基本块就求解                
#         old_path_num=len(pg.active)
#         new_path_num=len(pg.active)#保证还有存活的路径
#         while new_path_num and accumulated < 1024:  
#             pg.step() #这个是在线符号执行 运行这一步之后的pg.active也会更新,是每一个基本块都求解,还是只求解一次呢 在这个扩张的过程中会消失
#             steps += 1
#             old_path_num=new_path_num
#             new_path_num=len(pg.active)
#             # dump all inputs
#             accumulated = steps * (len(pg.active) + len(pg.deadended)) #这里是一种探索方式的上限
#             print "symbolic exploration accumulated %d" % accumulated
#             l.info("symbolic exploration %d",accumulated)
#             if(new_path_num>old_path_num):  #found new path 
#                 for pro in xrange(new_path_num):
#                     try:
#                         if pg.active[pro].state.satisfiable(): #如果是可满足的
#                             w = self._writeout(pg.active[pro].addr_trace[-1], pg.active[pro],len(self.argv))  # SimFile
#                             if w is not None:
#                                 yield w
#                     except IndexError: # if the path we're trying to dump wasn't actually satisfiable
#                         pass
#         l.info("[%s] symbolic exploration stopped at %s", self.identifier, time.ctime())
#            
#         pg.stash(from_stash='deadended', to_stash='active') #这个步骤的原因? 如果这边有新的,则不对了 修改了stashes
#         if len(pg.active)>new_path_num: 
#             for dumpable in pg.active: #dumpable是 path 类型的
#                 try:
#                     if dumpable.state.satisfiable(): #如果是可满足的
#                         w = self._writeout(dumpable.addr_trace[-1], dumpable, len(self.argv)) 
#                         if w is not None:
#                             yield w
#                 except IndexError: # if the path we're trying to dump wasn't actually satisfiable
#                     pass

#-----------原始的  , 发现新路径到终点,再生成    
        #计时
        while len(pg.active) and accumulated < config.SYM_STATE_MAX: #修改这里的逻辑,每次新发现一个state,就生成
            if  self.single_sy_ex_timed_out(start_time):
                l.info("single_sy_ex_timed_out time out ")
                break
            if self.whole_driller_timed_out(): ##单次的时间上限,或者总时间到了
                l.info("whole_driller_timed_out time out ")   
                break
            pg.step() #这个是在线符号执行
            steps += 1
            # dump all inputs
            accumulated = steps * (len(pg.active) + len(pg.deadended)) #这里是一种探索方式的上限
            l.info("symbolic exploration %d",accumulated)
            print "%s symbolic exploration accumulated %d,time is %d" % (os.path.basename(self.binary),accumulated, time.time()- start_time)
        l.info("[%s] symbolic exploration stopped at %s second", self.identifier, time.ctime())
  
        pg.stash(from_stash='deadended', to_stash='active') #为什么这么移动? deadended是结束路, 是因为预约束吗
        for dumpable in pg.active: #dumpable是 path 类型的
            try:
                if  dumpable.state.satisfiable(): #如果是可满足的
                    w = self._writeout(dumpable.addr_trace[-1], dumpable,1) 
                    if w is not None:
                        yield w
            except IndexError: # if the path we're trying to dump wasn't actually satisfiable
                pass

### UTILS

    @staticmethod
    def _set_simproc_limits(t):
        state = t.path_group.one_active.state
        state.libc.max_str_len = 1000000
        state.libc.max_strtol_len = 10
        state.libc.max_memcpy_size = 0x100000
        state.libc.max_symbolic_bytes = 100
        state.libc.max_buffer_size = 0x100000

    @staticmethod
    def _set_concretizations(t): 
        state = t.path_group.one_active.state
        flag_vars = set() #增加的是符号对象的名称
        for b in t.cgc_flag_bytes: #cgc的符号对象, tracer中搞了4096个字节的符号对象, b是 BV 类  update是添加到set中
            flag_vars.update(b.variables)  # b.variables is from Base class, 好像是符号对象的名称
        state.unicorn.always_concretize.update(flag_vars) # 添加符号变量的名称 添加到 Unicorn 的 always_concretize set中
        # let's put conservative thresholds for now
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def _has_encountered(self, transition): #判断参数指定的基本块跳跃关系,是否已经存在
        return transition in self._encounters

    @staticmethod
    def _has_false(path): #这里判断当前的跳转条件是否 为常量false 或者true  
        # check if the path is unsat even if we remove preconstraints
        claripy_false = path.state.se.false #这个只是 Bool 类型,是一个false常量   #cache_key是claripy的base模块下的函数
        if path.state.scratch.guard.cache_key == claripy_false.cache_key: #这个是什么意思? 在这里有问题 ASTCacheKey 类  这里实际上是 BV 类的比较
            return True      #表示当前路径的条件不满足                        #关键点在于研究 path.state.scratch.guard 是什么意思   
        # path.state.scratch.guard 也有可能是一个条件约束 比如 Bool: <Bool file_/dev/stdin_30_3_4105_8 .. file_/dev/stdin_30_2_4104_8 .. file_/dev/stdin_30_1_4103_8 .. file_/dev/stdin_30_0_4102_8 > 0x13>
        for c in path.state.se.constraints:  # path.state.se.constraints 这个应该是分离的约束  哪里来的  SimSolver
            if c.cache_key == claripy_false.cache_key:  #判断是否所有约束可满足
                return True
        return False  #false 表示当前路径的条件满足

    def _in_catalogue(self, length, prev_addr, next_addr): #这里判断方法不对,有可能是两个 afl只记录了两个基本块的跳跃关系,这里模仿了afl的记录方法,只记录的跳跃关系;  我觉得这里得多记录一些
        '''
        check if a generated input has already been generated earlier during the run or by another
        thread.

        :param length: length of the input
        :param prev_addr: the source address in the state transition
        :param next_addr: the destination address in the state transition
        :return: boolean describing whether or not the input generated is redundant
        '''
        key = '%x,%x,%x\n' % (length, prev_addr, next_addr) #这种key无法代表这一条路径??

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key) #这个返回值,判断对象是否存在
        else:
            # no redis means no coordination, so no catalogue
            return False

    def _add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key) #记录出现过的元组跳跃,还有对应测试用例的长度
        # no redis = no catalogue

    def _writeout(self, prev_addr, path, argv_num):   #怎么求解的?
#         t_pos = path.state.posix.files[0].pos # 找到文件偏移量 这个怎么是找的stdin输入
#         path.state.posix.files[0].seek(0) #这个怎么是stdin
#         # read up to the length
#         generated = path.state.posix.read_from(0, t_pos)# 将偏移之前的数值求解
#         generated = path.state.se.any_str(generated)
#         path.state.posix.files[0].seek(t_pos)
        if argv_num ==1: #没有其他符号文件
            fd=0
        else:
            fd=3
        
        t_pos = path.state.posix.files[fd].pos # 找到文件偏移量 这个怎么是找的stdin输入  #怎么有些时候没有 file[3]呢?
        path.state.posix.files[fd].seek(0) # 找到文件头,修改position
        # read up to the length
        generated = path.state.posix.read_from(fd, t_pos)# 将偏移之前的数值求解 没有读取所有的字节
        generated = path.state.se.any_str(generated) # BV 对象怎么保存约束的? 不一定有约束吧
        path.state.posix.files[fd].seek(t_pos) #回到文件偏移量
        key = (len(generated), prev_addr, path.addr)
        print ( "新发现 0X%x -> 0x%x" %( prev_addr, path.addr ))
         
        # checks here to see if the generation is worth writing to disk
        # if we generate too many inputs which are not really different we'll seriously slow down AFL
        
        if self._in_catalogue(*key):  #加 *号表示 一堆变量
            return
        else:
            self._encounters.add((prev_addr, path.addr)) #添加到了self._encounters 中
            self._add_to_catalogue(*key)
            #添加到整个符号执行的轨迹中
            self.add_to_sym_map(prev_addr,path.addr)

        l.info("[%s] dumping input for %x -> %x", self.identifier, prev_addr, path.addr)

        self._generated.add((key, generated)) #保存结果

        if self.redis:
            # publish it out in real-time so that inputs get there immediately
            crash_target_dir = self.identifier + '-generated'

            self.redis.publish(crash_target_dir, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag})) #将结果发送到服务器,然后会保存到disk
        else:
            l.info("generated: %s", generated.encode('hex'))

        return (key, generated)

    def _write_debug_info(self):
        m = hashlib.md5()
        m.update(self.input)
        f_name = os.path.join(config.DEBUG_DIR,
                              self.identifier + '_' + m.hexdigest() + '.py')
        with open(f_name, 'w+') as f:
            l.debug("Wrote debug log to %s", f_name)
            f.write("binary = %r\n" % self.binary +
                    "started = '%s'\n" % time.ctime(self.start_time) +
                    "input = %r\n" % self.input +
                    "fuzz_bitmap = %r" % self.fuzz_bitmap)

    def whole_driller_timed_out(self): 
        '''
        configure to end drilling of this input
        针对该目标程序的时间上限判断
        '''
        if self.time_limit_for_pro is None:
            return False  # 默认是false,表示不会退出
        return time.time() - self.start_time > self.time_limit_for_pro #表示要退出了
    
    def single_sy_ex_timed_out(self,this_start_time): 
        '''
        configure to end drilling of this symbolice exploration
        每条路径符号执行的时间上限判断
        '''
        if self.sy_ex_time_limit is None:
            return False  # 默认是false
        return time.time() - this_start_time > self.sy_ex_time_limit
    
    #将元组关系加入到符号执行轨迹中,在数据库中
    def add_to_sym_map(self, prev_loc, cur_loc):
        prev_loc = (prev_loc >> 4) ^ (prev_loc << 8)
        prev_loc &= self.fuzz_bitmap_size - 1
        prev_loc = prev_loc >> 1
        # 当前基本块的地址
        cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
        cur_loc &= self.fuzz_bitmap_size - 1
        # 记录符号执行的轨迹
        self.redis.sadd(self.identifier+'-symmap', str(cur_loc ^ prev_loc)) #若已经存在，则被忽略
        aa=redis_inst.smembers(self.identifier+'-symmap')
        return cur_loc ^ prev_loc #返回轨迹点
