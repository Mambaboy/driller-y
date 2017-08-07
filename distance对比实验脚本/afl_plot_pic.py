#!/usr/bin/env python
#coding=utf-8
import numpy as np
import matplotlib.pyplot as plt
from pylab import *
import matplotlib
import os
import shutil
import logging
from reportlab.lib.styles import LineStyle
l = logging.getLogger("make_pic")


def get_plotdata(plot_dir):
    x0=[]
    x1=[]
    x2=[]
    x3=[]
    x4=[]
    x5=[]
    x6=[]
    x7=[]
    x8=[]
    x9=[]
    x10=[]
    with open(plot_dir) as f:
        lines = f.read()
        line=lines.split('\n')[1:-1]
        for row in line:
            if int(row.split(',')[0]) > 60*14:
                break
            x0.append( row.split(',')[0])
            x1.append( row.split(',')[1])
            x2.append( row.split(',')[2])
            x3.append( row.split(',')[3])
            x4.append( row.split(',')[4])
            x5.append( row.split(',')[5])
            x6.append( row.split(',')[6])
            x7.append( row.split(',')[7])
            x8.append( row.split(',')[8])
            x9.append( row.split(',')[9])
            x10.append( row.split(',')[10])
            
    x0 = np.array( x0 ) #unix_time
    x1 = np.array( x1 ) #cycles_done
    x2 = np.array( x2 ) #cur_path
    x3 = np.array( x3 ) #paths_total
    x4 = np.array( x4 ) #pending_total
    x5 = np.array( x5 ) #pending_favs
    x6 = np.array( x6 ) #map_size
    x7 = np.array( x7 ) #unique_crashes
    x8 = np.array( x8 ) #unique_hangs
    x9 = np.array( x9 ) #max_depth
    x10 = np.array( x10 ) #execs_per_sec    
        
            
#     x0 = np.array([ row.split(',')[0]  for row in line ]) #unix_time
#     x1 = np.array([ row.split(',')[1]  for row in line ]) #cycles_done
#     x2 = np.array([ row.split(',')[2]  for row in line ]) #cur_path
#     x3 = np.array([ row.split(',')[3]  for row in line ]) #paths_total
#     x4 = np.array([ row.split(',')[4]  for row in line ]) #pending_total
#     x5 = np.array([ row.split(',')[5]  for row in line ]) #pending_favs
#     x6 = np.array([ row.split(',')[6]  for row in line ]) #map_size
#     x7 = np.array([ row.split(',')[7]  for row in line ]) #unique_crashes
#     x8 = np.array([ row.split(',')[8]  for row in line ]) #unique_hangs
#     x9 = np.array([ row.split(',')[9]  for row in line ]) #max_depth
#     x10 = np.array([ row.split(',')[10]  for row in line ]) #execs_per_sec
    
    return [x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10]    
    

out_put_dir="/home/xiaosatianyu/Desktop/driller-desk/picture"
data_dir="/tmp/driller"
pros_dir="/home/xiaosatianyu/Desktop/driller-desk/binary-cgc"


#picture output dir
if os.path.exists(out_put_dir):
    shutil.rmtree(out_put_dir)
os.mkdir(out_put_dir)
    
#driller data input dir
if not os.path.exists(out_put_dir):
    print "error,there is no input data"
    l.error("input_from is error")
      

#the list of cgc program
pros=[]
for pro in os.listdir(pros_dir):
    if '#' not in pro:
        pros.append(pro)
pros.sort()

pro=0   
for pro in pros:
    #save_file_path
    save_file_path=os.path.join(out_put_dir,pro)

    # driller-yyy-nosort-afl #1
    driller=os.path.join(data_dir,pro+'#1','sync/fuzzer-master','plot_data')
    afl_yyy=os.path.join(data_dir,pro+'#1','sole/fuzzer-master','plot_data')
    
    # driller-yyy-sort-noafl #2
    driller_sort=os.path.join(data_dir,pro+'#2','sync/fuzzer-master','plot_data')
    
    # driller-fast-nosort-afl #3
    driller_fast_nosort=os.path.join(data_dir,pro+'#3','sync/fuzzer-master','plot_data')
    afl_fast=os.path.join(data_dir,pro+'#3','sole/fuzzer-master','plot_data')
    
    # driller-fast-sort-noafl #4
    fas=os.path.join(data_dir,pro+'#4','sync/fuzzer-master','plot_data')

    #get the plot_data
    if not os.path.exists(driller):
        continue
    
    driller_plot=get_plotdata(driller)
    afl_yyy_plot=get_plotdata(afl_yyy)
    driller_sort_plot=get_plotdata(driller_sort)
    driller_fast_nosort_plot=get_plotdata(driller_fast_nosort)
    afl_fast_plot=get_plotdata(afl_fast)
    fas_plot=get_plotdata(fas)

    ##make the picture
    if pro%2==0:
        plt.figure()#新建一个图片
        tag=211
    else:
        tag=212    
    
    #plt.ylabel("number of paths")
    a1=plt.subplot(tag)
    a1.plot(afl_yyy_plot[0],afl_yyy_plot[3],color='m',label='AFL',ls='-.',lw=4) #marker="s" linestyle=':'
    a1.plot(driller_plot[0],driller_plot[3],color='r',label='Driller',ls='--',lw=4) #,marker="^"
    a1.plot(afl_fast_plot[0],afl_fast_plot[3],color='b',label='DO-fuzzer',ls=':',lw=4) #,marker="v"
    a1.plot(fas_plot[0],fas_plot[3],color='g',label='FAS',lw=3) #,marker="8"
    a1.set_title(pro,fontsize=15)
    
    
#     plt.plot(afl_yyy_plot[0],afl_yyy_plot[3],color='m',label='AFL',ls='-.',lw=4) #marker="s" linestyle=':'
#     plt.plot(driller_plot[0],driller_plot[3],color='r',label='Driller',ls='--',lw=4) #,marker="^"
#     plt.plot(afl_fast_plot[0],afl_fast_plot[3],color='b',label='DO-fuzzer',ls=':',lw=4) #,marker="v"
#     plt.plot(fas_plot[0],fas_plot[3],color='g',label='FAS',lw=3) #,marker="8"
    
    plt.legend(loc='upper left',fontsize=13,shadow=True,framealpha=True,borderpad=False,labelspacing=False)
    if pro%2==1:
        #lt.ylabel("number of paths")
        plt.xlabel("Second")
        plt.savefig(save_file_path+'.pdf',format="pdf",edgecolor=None,transparent=True,borderpad=False,borderaxespad=False) #facecolor=None,
        plt.close()
    pro+=1
print "end"
