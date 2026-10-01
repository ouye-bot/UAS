ss -tlnp 2>/dev/null | head -8; ps aux | grep -v grep | grep arducopter | awk "{print \$2, \$11, \$12, \$13}" | head -3; exit 0
