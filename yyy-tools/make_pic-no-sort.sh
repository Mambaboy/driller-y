
out_put_dir=$1 #工作目录
target=$2 #目标程序


GNUPLOT=`which gnuplot 2>/dev/null`

if [ "$GNUPLOT" = "" ]; then

  echo "[-] Error: can't find 'gnuplot' in your \$PATH." 1>&2
  exit 1

fi

echo "[*] Generating plots..."



cd $out_put_dir/$target


(
cat <<_EOF_
set terminal png truecolor enhanced size 1000,350 font "Times New Roman,16" #butt 
set output './路径发现速度.png' 

#设置x轴
set xdata time 		#设置x轴为时间
set timefmt '%s'    #时间输入格式设置为seconds since the Unix epoch (1970-01-01, 00:00 UTC)
#set format x "%b %d\n%H:%M" #x轴时间格式
set format x   "%H:%M" #时间格式
#set grid xtics linetype 0 linecolor rgb '#e0e0e0'
#set xtics font  "Times New Roman,16" 
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
set key inside  bottom Right font "DejaVu Sans,18" 
#set label "ddd" at 0.5,0.5
#set title "the number of test-cases with different paths"

  
plot '/tmp/driller/$target/sync/fuzzer-master/plot_data'   using 1:4 with lines title 'driller-afl-no-sort'   linewidth 4 linetype 3, \\
	 '/tmp/driller/$target/sole/fuzzer-master/plot_data' using 1:4 with lines title 'afl'       linewidth 4 linetype 4 ,\\
	 
	  

######end the high_freq.png


_EOF_

) | gnuplot 



(
cat <<_EOF_
set terminal png truecolor enhanced size 1000,350 font "Times New Roman,16" #butt 

set output './crash发现速度.png' 


#设置x轴
set xdata time 		#设置x轴为时间
set timefmt '%s'    #时间输入格式设置为seconds since the Unix epoch (1970-01-01, 00:00 UTC)
#set format x "%b %d\n%H:%M" #x轴时间格式
set format x "%H:%M" #时间格式
set xlabel "Time(Hours)" font "Times New Roman,16" 
unset mxtics
#set grid xtics linetype 0 linecolor rgb '#e0e0e0'
set autoscale xfixmin
set autoscale xfixmax


#设置y轴
#set ytics 25
#set tics font 'small'
#set ylabel "Number of crashes"
unset mytics
#set grid ytics linetype 0 linecolor rgb '#e0e0e0'


#设置边
set border #linecolor rgb '#50c0f0'
#set tics textcolor rgb '#000000'
set grid 

#设置图例
#set key inside  bottom Right font "DejaVu Sans,18" 
set key inside   Right font "DejaVu Sans,15" 

#设置label
#set label "ddd" at 0.5,0.5


#设置题目
#set title "the number of unique crashes"


plot  '/tmp/driller/$target/sync/fuzzer-master/plot_data'   using 1:8 with lines title 'driller-afl-no-sort'   linewidth 4 linetype 3, \\
	  '/tmp/driller/$target/sole/fuzzer-master/plot_data' using 1:8 with lines title 'afl'       linewidth 4 linetype 4 ,\\
	 
	  

_EOF_

) | gnuplot 

echo "[+] All done - enjoy your charts!"

exit 0
