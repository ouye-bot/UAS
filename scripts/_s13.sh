cd /home/ouye
setsid nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitlC.log 2>&1 < /dev/null &
sleep 6
pgrep -c arducopter
exit 0
