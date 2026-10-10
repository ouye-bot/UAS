ps aux | grep -v grep | grep arducopter | head -2; ss -ulnp 2>/dev/null | grep 14550 | head -1; exit 0
