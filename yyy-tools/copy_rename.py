#coding=utf-8
import shutil
import os
import stat

srt_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"
dst_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"
all_str=['#0','#1','#2','#3','#4','#5','#6','#7']
pros=os.listdir(srt_dir)
pros.sort()
for pro in pros: 
    if '#' in pro:
        continue 
    pro_path=os.path.join(srt_dir,pro) 
    for tail_name in all_str: 
        new_name=pro+tail_name
        newpro_path=os.path.join(srt_dir,new_name)  
        if os.path.exists(newpro_path)  :
            os.remove(newpro_path)
        shutil.copy(pro_path,newpro_path) 
print "end"

