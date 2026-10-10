pkill -f arducopter; sleep 1
setsid ~/ardupilot/build/sitl/bin/arducopter -S -w --model + -I0 --out 127.0.0.1:14550 --out 127.0.0.1:14551 > /tmp/sitl0.log 2>&1 < /dev/null &
sleep 10
tail -4 /tmp/sitl0.log
exit 0
