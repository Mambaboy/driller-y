#coding=utf-8

import subprocess
import os
import shutil
import time


out_put_dir="/home/xiaosatianyu/Desktop/driller-desk/picture"

if os.path.exists(out_put_dir):
    shutil.rmtree(out_put_dir)
os.mkdir(out_put_dir)

pros_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"

sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/make_pic_8strategy.sh"
# sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/make_pic-no-sort.sh"

pros=[]
for pro in os.listdir(pros_dir):
    if '#' not in pro:
        pros.append(pro) #移除重复的   这里有浅拷贝和深拷贝的问题 for in 是对 下标操作的
pros.sort()

for pro in pros:
    if pro+'#0'  in os.listdir("/tmp/driller"):
        ret=os.system('sh '+sh_path+' '+out_put_dir+' '+pro)  #successful
        
print "end"
                
                
