cd /home/ouye
nohup ~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/sitl2.log 2>&1 < /dev/null &
sleep 10
tail -3 /tmp/sitl2.log
ss -tln | grep 577
exit 0
