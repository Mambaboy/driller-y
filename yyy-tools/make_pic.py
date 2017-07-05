#coding=utf-8

import subprocess
import os
import shutil


out_put_dir="/home/xiaosatianyu/Desktop/driller-desk/picture"
pros_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"
pros=os.listdir(pros_dir)
sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/make_pic.sh"
#sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/1.sh"

for i in pros:
    if i in os.listdir("/tmp/driller"):
        work_dir=os.path.join(out_put_dir,i)
        if os.path.exists(work_dir):
            shutil.rmtree(work_dir)
        os.makedirs(work_dir)    
        
        ret=os.system('sh '+sh_path+' '+out_put_dir+' '+i)  #successful

        print ret
