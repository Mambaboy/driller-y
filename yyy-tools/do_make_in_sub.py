#coding=utf-8

import subprocess
import os

#target_dir="/home/xiaosatianyu/infomation/git-2/CGC/DECREE/cgc-vm/samples/examples"

base = os.path.dirname(__file__)
target_dir=os.path.join(base,"samples/examples")
print target_dir

b=0
path=os.listdir(target_dir)
unenable_make=[]
unenable_make_clean=[]
for i in path:
    sub_target_dir=os.path.join(target_dir,i)
    if os.path.exists(sub_target_dir):
        if "Makefile" in os.listdir(sub_target_dir):

            if subprocess.call(['make', 'clean'], shell=True,cwd=sub_target_dir) != 0:
            #if subprocess.call(['make', 'clean'],cwd=sub_target_dir) != 0:
                unenable_make_clean.append(i)

            if subprocess.call(['make', '-j2'], shell=True, cwd=sub_target_dir) != 0:
            #if subprocess.Popen(['make', '-j2'], shell=True, cwd=sub_target_dir) != 0:  #无阻塞 需要wait
            #if subprocess.call(['make', '-j2'], cwd=sub_target_dir) != 0:
                unenable_make.append(i)
                #subprocess.call(['make', 'clean'], shell=True , cwd=sub_target_dir)
# 	b+=1	
# 	if b > 2:
# 		break

print "unenable_make list %s" %unenable_make
print "unenable_make_clean list %s:" % unenable_make_clean
