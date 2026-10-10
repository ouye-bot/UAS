cd ~
nohup ~/ardupilot/build/sitl/bin/arducopter -S -w --model + --speedup 1 -I0 > /tmp/sitl0.log 2>&1 &
echo SITL_LAUNCHED
