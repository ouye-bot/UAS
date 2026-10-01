cd /home/ouye
setsid ~/ardupilot/build/sitl/bin/arducopter -S -w --model + -I0 > /tmp/sitl0.log 2>&1 < /dev/null &
sleep 8
ps aux | grep -v grep | grep arducopter | wc -l
head -5 /tmp/sitl0.log
