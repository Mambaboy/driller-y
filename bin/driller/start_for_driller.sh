#不用在driller环境下

#if [ "$1" == "stop" ]; then	
	#redis-cli -h 127.0.0.1 -p 6379 shutdown #重启
	#echo 'stop'
#else
	redis-cli -h 127.0.0.1 -p 6379 shutdown #重启
	redis-server /home/xiaosatianyu/workspace/git/driller-yyy/redis-stable/redis.conf
	echo 'start'
#fi


echo core >/proc/sys/kernel/core_pattern
echo $?
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
echo 1 > /proc/sys/kernel/sched_child_runs_first

