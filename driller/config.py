#coding=utf-8
### Redis Options
import driller
from celery.backends.base import Backend
from pygments.lexers.templates import RhtmlLexer
REDIS_HOST='127.0.0.1'
REDIS_PORT=6379
REDIS_DB='5'  #数据库
REDIS_BACKEND_DB='6'  #结果数据库

### Celery Options
BROKER_URL= 'redis://127.0.0.1:6379/'+REDIS_DB
Backend_URL= 'redis://127.0.0.1:6379/'+REDIS_BACKEND_DB

CELERY_ROUTES = None

### Environment Options

# directory contain driller-qemu versions, relative to the directoy node.py is invoked in
QEMU_DIR=None

# directory containing the binaries, used by the driller node to find binaries
BINARY_DIR_UNIX='/home/xiaosatianyu/Desktop/driller-desk/binary-unix'
BINARY_DIR_CGC='/home/xiaosatianyu/Desktop/driller-desk/binary-cgc'
BINARY_DIR_CGC2='/home/xiaosatianyu/Desktop/driller-desk/binary-cgc2'
BINARY_DIR_CGC_TEST='/home/xiaosatianyu/Desktop/driller-desk/binary-cgc-test'
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
CRASH_CHECK_INTERVAL=5 #间隔多久判断一次是否需要符号执行

# how long to fuzz before giving up in seconds
FUZZ_TIMEOUT=1  #这个好像没有用到

# how long before we kill a dictionary creation process
DICTIONARY_TIMEOUT=None

# how many fuzzers should be spun up when a fuzzing job is received
FUZZER_INSTANCES=1

# where the fuzzer should place it's results on the filesystem
FUZZER_WORK_DIR="/tmp/driller"

##add by yyy-------------------------------------------------------
#the seed directory
SEED='/home/xiaosatianyu/Desktop/driller-desk/seed'
AFL_FAST='/home/xiaosatianyu/workspace/git/aflfast/afl-fuzz'
AFL_YYY='/home/xiaosatianyu/workspace/git/afl-yyy/afl-fuzz'
AFL='/home/xiaosatianyu/workspace/git/afl/afl-fuzz'
#AFL_Shellfish_unix='/home/xiaosatianyu/workspace/git/driller-yyy/shellphish-afl/bin/afl-unix/afl-fuzz'
AFL_Shellfish_unix='/home/xiaosatianyu/workspace/git/afl/afl-fuzz'
FUZZ_LIMIT=5*60
SYM_STATE_MAX=1024

CRASH_DIR="/home/xiaosatianyu/Desktop/driller-desk/CRASH"
PASSWD_SUDO='1'
AFL_START_SCRIPT='/home/xiaosatianyu/workspace/git/driller-yyy/driller/bin/driller/start_for_driller.sh'

###
# for RHT
collect_qemu="/home/xiaosatianyu/workspace/git/driller-yyy/shellphish-qemu/shellphish_qemu/bin"
Global_json="/home/xiaosatianyu/Desktop/driller-desk/CRASH/CCGCGlobalConfig.json"
traffic_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/bin/driller/collect_traffic.py"
