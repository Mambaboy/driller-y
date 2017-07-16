#coding=utf-8

import subprocess
import os
import shutil
import time


out_put_dir="/home/xiaosatianyu/Desktop/driller-desk/picture"
pros_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"
pros=os.listdir(pros_dir)
sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/make_pic.sh"
#sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/make_pic-no-sort.sh"
#sh_path="/home/xiaosatianyu/workspace/git/driller-yyy/driller/yyy-tools/1.sh"
t5_dir=os.path.join(out_put_dir,"5minites")
t10_dir=os.path.join(out_put_dir,"10minites")
t15_dir=os.path.join(out_put_dir,"15minites")
t30_dir=os.path.join(out_put_dir,"30minites")
t40_dir=os.path.join(out_put_dir,"40minites")
t50_dir=os.path.join(out_put_dir,"50minites")
t60_dir=os.path.join(out_put_dir,"60minites")

if os.path.exists(t5_dir):
    shutil.rmtree(t5_dir)
os.makedirs(t5_dir)   
if os.path.exists(t10_dir):
    shutil.rmtree(t10_dir)
os.makedirs(t10_dir)    
if os.path.exists(t15_dir):
    shutil.rmtree(t15_dir)
os.makedirs(t15_dir)   
# if os.path.exists(t30_dir):
#     shutil.rmtree(t30_dir)
# os.makedirs(t30_dir)   
# if os.path.exists(t40_dir):
#     shutil.rmtree(t40_dir)
# os.makedirs(t40_dir)  
# if os.path.exists(t50_dir):
#     shutil.rmtree(t50_dir)
# os.makedirs(t50_dir)  
# if os.path.exists(t60_dir):
#     shutil.rmtree(t60_dir)
# os.makedirs(t60_dir) 

pros.sort()
for pro in pros:
    if '-sort' in pro:
        pros.remove(pro)
#         print pro
        
for pro in pros:
    start_time=time.time()
    num=0;
    print "wait "
    while   num<3:
        if (time.time()-start_time==5*60 
            or time.time()-start_time==10*60  
            or time.time()-start_time==14*60  
#           or  time.time()-start_time==30*60 
#           or  time.time()-start_time==40*60 
#           or   time.time()-start_time==50*60 
#           or  time.time()-start_time==60*60
            ):
            num+=1
            
            if pro in os.listdir("/tmp/driller"):
                work_dir=os.path.join(out_put_dir,pro)
                if os.path.exists(work_dir):
                    shutil.rmtree(work_dir)
                os.makedirs(work_dir)    
                ret=os.system('sh '+sh_path+' '+out_put_dir+' '+pro)  #successful
                time.sleep(5)
            
            if num==1:
                print "5 minite"
                if os.path.exists(os.path.join(t5_dir,pro)):
                        shutil.rmtree(os.path.join(t5_dir,pro))
                shutil.copytree(work_dir, os.path.join(t5_dir,pro))     
            elif num==2:
                print "10 minite"
                if os.path.exists(os.path.join(t10_dir,pro)):
                        shutil.rmtree(os.path.join(t10_dir,pro))
                shutil.copytree(work_dir, os.path.join(t10_dir,pro)) 
            elif num==3:
                print "15 minite"
                if os.path.exists(os.path.join(t15_dir,pro)):
                        shutil.rmtree(os.path.join(t15_dir,pro))
                shutil.copytree(work_dir, os.path.join(t15_dir,pro))
#             elif num==4:
#                 print "30 minite"
#                 if os.path.exists(os.path.join(t30_dir,pro)):
#                         shutil.rmtree(os.path.join(t30_dir,pro))
#                 shutil.copytree(work_dir, os.path.join(t30_dir,pro))
#             elif num==5:
#                 print "40 minite"
#                 if os.path.exists(os.path.join(t40_dir,pro)):
#                         shutil.rmtree(os.path.join(t40_dir,pro))
#                 shutil.copytree(work_dir, os.path.join(t40_dir,pro))
#             elif num==6:
#                 print "50 minite"
#                 if os.path.exists(os.path.join(t50_dir,pro)):
#                         shutil.rmtree(os.path.join(t50_dir,pro))
#                 shutil.copytree(work_dir, os.path.join(t50_dir,pro))
#             elif num==7:
#                 print "60 minite"
#                 if os.path.exists(os.path.join(t60_dir,pro)):
#                         shutil.rmtree(os.path.join(t60_dir,pro))
#                 shutil.copytree(work_dir, os.path.join(t60_dir,pro))        
                
print "end"
