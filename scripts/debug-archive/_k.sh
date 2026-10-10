pkill -9 -f arducopter; sleep 2
pgrep -c arducopter || echo ALL_DEAD
exit 0
