cd /home/ouye
~/ardupilot/build/sitl/bin/arducopter -w --model + -I1 > /tmp/fg.log 2>&1
echo "EXIT=$?" >> /tmp/fg.log
exit 0
