#!/usr/bin/env python
# coding=utf-8
# 监听到数据然后上传之类的, 保存到/tmp/driller/bmp2tiff/sync/driller/queue目录下

import os
import sys
import redis
import logging
import cPickle as pickle
import driller.config as config

''' 
listen for new inputs produced by driller

:param queue_dir: directory to places new inputs
:param channel: redis channel on which the new inputs will be arriving
'''

queue_dir = sys.argv[1] 
channel = sys.argv[2]

l = logging.getLogger("driller.listen")

l.debug("subscring to redis channel %s" % channel)
l.debug("new inputs will be placed into %s" % queue_dir)

try:
    os.makedirs(queue_dir)  
except OSError:
    l.warning("could not create output directory '%s'" % queue_dir)

redis_inst = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, db=config.REDIS_DB)  # 一个链接实例 , db默认为0
p = redis_inst.pubsub()  # p is some type in redis 事件处理器  发布订阅模式

p.subscribe(channel)  # i shoud learn some apis of redis  订阅channel频道

input_cnt = 0 

for msg in p.listen():  # 监听收到的信息,这里是服务端
    if msg['type'] == 'message':
        real_msg = pickle.loads(msg['data'])  # 从数据库传来m 监听到了新的测试用例生成
        out_filename = "driller-%d-%x-%x" % real_msg['meta']
        out_filename += "_%s" % real_msg['tag']
        l.debug("dumping new input to %s" % out_filename)
        afl_name = "id:%06d,src:%s" % (input_cnt, out_filename)
        out_file = os.path.join(queue_dir, afl_name)  

        with open(out_file, 'wb') as ofp:
            ofp.write(real_msg['data'])  # write testcase to the catalog ,输出符号执行的测试用例后,怎么给afl使用?

        input_cnt += 1

