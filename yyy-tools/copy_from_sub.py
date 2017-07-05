#coding=utf-8

import os
import subprocess
import shutil

source_dir="/home/xiaosatianyu/infomation/git-2/CGC/DECREE/cgc-vm/samples/examples"
target_dir="/home/xiaosatianyu/Desktop/driller/binary-cgc"

path=os.listdir(source_dir)
fail_sub=[]
for i in path:
    sub_target_dir=os.path.join(source_dir,i)
    if os.path.exists(sub_target_dir):
        if "bin" in os.listdir(sub_target_dir):
            sub_target_dir=os.path.join(sub_target_dir,"bin")
            for j in os.listdir(sub_target_dir):
                if "patched" not in j:
                    target_di_pro=os.path.join(sub_target_dir,j)
                    shutil.copy(target_di_pro, target_dir)

         

