#coding=utf-8

import subprocess
import os
import shutil
import time


out_put_dir="/home/xiaosatianyu/Desktop/driller-desk/picture"
pros_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"
# pros_dir2="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc2"
pros=[]
# pros2=os.listdir(pros_dir2)
sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/make_pic.sh"
# sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/make_pic-no-sort.sh"

pros.sort()
for pro in os.listdir(pros_dir):
    if '#' not in pro:
        pros.append(pro)

        
for pro in pros:
#     if pro in os.listdir("/tmp/driller"):
#         work_dir=os.path.join(out_put_dir,pro)
#         if os.path.exists(work_dir):
#             shutil.rmtree(work_dir)
#         os.makedirs(work_dir)    
        ret=os.system('sh '+sh_path+' '+out_put_dir+' '+pro)  #successful
                
            
# pros2.sort()
# for pro in pros2:
#     if '-fast' in pro:
#         pros2.remove(pro)
# #         print pro
#          
# for pro in pros2:
#     if pro in os.listdir("/tmp/driller"):
# #         work_dir=os.path.join(out_put_dir,pro)
# #         if os.path.exists(work_dir):
# #             shutil.rmtree(work_dir)
# #         os.makedirs(work_dir)    
#         ret=os.system('sh '+sh_path+' '+out_put_dir+' '+pro)  #successful

print "end"
                
                
