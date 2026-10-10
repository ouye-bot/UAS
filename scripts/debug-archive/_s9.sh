cd /home/ouye
nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitl9.log 2>&1 < /dev/null &
sleep 8
pgrep -c arducopter
