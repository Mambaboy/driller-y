
out_put_dir=$1 #工作目录
target=$2 #目标程序
#workdir="/home/xiaosatianyu/Desktop/driller-desk/record/driller4"
workdir="/tmp/driller"


NO_SORT_0=$target'#0'
Random_Sort_1=$target'#1'
BT_dup_Sort_2=$target'#2'
BT_no_dup_Sort_3=$target'#3'
BA_Sort_4=$target'#4'
Min_Max_Sort_5=$target'#5'
Short_first_Sort_6=$target'#6'
Short_by_hamming_7=$target'#7'

GNUPLOT=`which gnuplot 2>/dev/null`

if [ "$GNUPLOT" = "" ]; then

  echo "[-] Error: can't find 'gnuplot' in your \$PATH." 1>&2
  exit 1

fi

echo "[*] Generating plots..."

#cd $out_put_dir/$target
cd $out_put_dir


(
cat <<_EOF_
set terminal png truecolor enhanced size 1000,350 font "Times New Roman,16" #butt 
set output './$target.png' 

#设置x轴
set xdata time 		#设置x轴为时间
set timefmt '%s'    #时间输入格式设置为seconds since the Unix epoch (1970-01-01, 00:00 UTC)
#set format x "%y\n %b %d\n%H:%M" #x轴时间格式
set format x   "%H:%M" #时间格式
#set xrange [0:600]


set grid xtics linetype 0 linecolor rgb '#e0e0e0'
set xtics font  "Times New Roman,16" 
set autoscale xfixmin
set autoscale xfixmax
set xlabel "Time(Hours)" font "Times New Roman,16" 


#设置y轴
#set ytics 80 font  "Times New Roman,16" 
#set grid ytics linetype 0 linecolor rgb '#e0e0e0'
#set ylabel "Number of paths"

#set tics font  "100000" 
#set tics textcolor rgb '#000000'
#unset mxtics
#unset mytics


#设置边
set border #linecolor rgb '#50c0f0'
set grid 

#设置图例
#set key inside  bottom Right font "DejaVu Sans,18" 
#set label "ddd" at 0.5,0.5
#set title "the number of test-cases with different paths"
set key outside rmargin   "DejaVu Sans,15" 

  
plot '/$workdir/$NO_SORT_0/sync/fuzzer-master/plot_data' using 1:4 with lines title 'NO\_SORT\_0' linewidth 4 linetype 3, \\
	 '/$workdir/$Random_Sort_1/sync/fuzzer-master/plot_data' using 1:4 with lines title 'Random\_Sort\_1'    linewidth 4 linetype 4 ,\\
	 '/$workdir/$BT_dup_Sort_2/sync/fuzzer-master/plot_data' using 1:4 with lines title 'BT_dup\_Sort\_2'    linewidth 4 linetype 5 ,\\
	 '/$workdir/$BT_no_dup_Sort_3/sync/fuzzer-master/plot_data' using 1:4 with lines title 'BT\_no\_dup\_Sort\_3' linewidth 4 linetype 6, \\
	 '/$workdir/$BA_Sort_4/sync/fuzzer-master/plot_data' using 1:4 with lines title 'BA\_Sort\_4' linewidth 4 linetype 7, \\
	 '/$workdir/$Min_Max_Sort_5/sync/fuzzer-master/plot_data' using 1:4 with lines title 'Min\_Max\_Sort_5' linewidth 4 linetype 8, \\
	 '/$workdir/$Short_first_Sort_6/sync/fuzzer-master/plot_data' using 1:4 with lines title 'Short\_first\_Sort_6' linewidth 4 linetype 9, \\
	 '/$workdir/$Short_by_hamming_7/sync/fuzzer-master/plot_data' using 1:4 with lines title 'Short\_by\_hamming\_7' linewidth 4 linetype 10, \\
	 
	  

######end the high_freq.png


_EOF_

) | gnuplot 



#(
#cat <<_EOF_
#set terminal png truecolor enhanced size 1000,350 font "Times New Roman,16" #butt 

#set output './crash发现速度.png' 


##设置x轴
#set xdata time 		#设置x轴为时间
#set timefmt '%s'    #时间输入格式设置为seconds since the Unix epoch (1970-01-01, 00:00 UTC)
##set format x "%b %d\n%H:%M" #x轴时间格式
#set format x "%H:%M" #时间格式
#set xlabel "Time(Hours)" font "Times New Roman,16" 
#unset mxtics
##set grid xtics linetype 0 linecolor rgb '#e0e0e0'
#set autoscale xfixmin
#set autoscale xfixmax


##设置y轴
##set ytics 25
##set tics font 'small'
##set ylabel "Number of crashes"
#unset mytics
##set grid ytics linetype 0 linecolor rgb '#e0e0e0'


##设置边
#set border #linecolor rgb '#50c0f0'
##set tics textcolor rgb '#000000'
#set grid 

##设置图例
##set key inside  bottom Right font "DejaVu Sans,18" 
#set key inside   Right font "DejaVu Sans,15" 

##设置label
##set label "ddd" at 0.5,0.5


##设置题目
##set title "the number of unique crashes"


#plot  '/tmp/driller/$target/sync/fuzzer-master/plot_data'   using 1:8 with lines title 'driller-afl-yyy'   linewidth 4 linetype 3, \\
	  #'/tmp/driller/$target/sole/fuzzer-master/plot_data' using 1:8 with lines title 'afl'       linewidth 4 linetype 4 ,\\
	  #'/tmp/driller/$target_fast/sync/fuzzer-master/plot_data' using 1:8 with lines title 'driller-afl-fast'   linewidth 4 linetype 5 ,\\
	  

#_EOF_

#) | gnuplot 

echo "[+] All done - enjoy your charts!"

exit 0
