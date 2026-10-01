pkill -f arducopter; sleep 1
cd /home/ouye
setsid ~/ardupilot/build/sitl/bin/arducopter -w --model + -I0 --serial0 tcpclient:127.0.0.1:5760 > /tmp/sitl0.log 2>&1 < /dev/null &
sleep 3
# SITL 默认(serial0=tcp server:5760)。改用 mavproxy 风格: 起默认配置, bridge 直连 5760 TCP。
setsid ~/ardupilot/build/sitl/bin/arducopter -w --model + -I0 > /tmp/sitl1.log 2>&1 < /dev/null &
sleep 10
tail -3 /tmp/sitl1.log
ss -tln 2>/dev/null | grep 5760
exit 0
