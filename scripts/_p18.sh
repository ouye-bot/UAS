dmesg | grep -iE "kill|oom|ardu" | tail -3; journalctl -k 2>/dev/null | tail -3; exit 0
