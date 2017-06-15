#coding=utf-8
### Redis Options
import driller
REDIS_HOST='127.0.0.1'
REDIS_PORT=6379
REDIS_DB=None  #redis中默认为0

### Celery Options
BROKER_URL= 'redis://127.0.0.1:6379'

CELERY_ROUTES = None

### Environment Options

# directory contain driller-qemu versions, relative to the directoy node.py is invoked in
QEMU_DIR=None

# directory containing the binaries, used by the driller node to find binaries
BINARY_DIR_UNIX='/home/xiaosatianyu/Desktop/driller/binary-unix/unix/stdin'
BINARY_DIR_CGC='/home/xiaosatianyu/Desktop/driller/binary-cgc'
# directory containing the pcap corpus
PCAP_DIR=None  #语料库

### Driller options
# how long to drill before giving up in seconds
DRILL_TIMEOUT=None

MEM_LIMIT=None

# where to write a debug file that contains useful debugging information like
# AFL's fuzzing bitmap, input used, binary path, time started.
# Uses following naming convention:
#   <binary_basename>_<input_str_md5>.py
DEBUG_DIR = None

### Fuzzer options

# how often to check for crashes in seconds
CRASH_CHECK_INTERVAL=60 #间隔多久判断一次是否需要符号执行

# how long to fuzz before giving up in seconds
FUZZ_TIMEOUT=60  #这个好像没有用到

# how long before we kill a dictionary creation process
DICTIONARY_TIMEOUT=None

# how many fuzzers should be spun up when a fuzzing job is received
FUZZER_INSTANCES=1

# where the fuzzer should place it's results on the filesystem
FUZZER_WORK_DIR="/tmp/driller"

##add by yyy----------------------------------
#the seed directory
SEED='/home/xiaosatianyu/Desktop/driller/seed'


