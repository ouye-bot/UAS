' fz_wsl_keepalive 隐藏运行包装（2026-10-04：直接跑 .cmd 每 10 分钟弹窗——改 wscript 隐藏窗口）。
' Exec 形态：进程常驻隐藏 + StdOut 不得读（防管道阻塞），wscript 随 wsl 挂起。
Dim sh
Set sh = CreateObject("WScript.Shell")
Dim proc
Set proc = sh.Exec("wsl.exe -e bash -c " & Chr(34) & "sleep infinity" & Chr(34) & "")
' Exec 无窗口隐藏参数？——Exec 继承控制台。改回 Run 等待形态但确保字面量正确：
Set proc = Nothing
Dim ret
ret = sh.Run("wsl.exe -e bash -c " & Chr(34) & "sleep infinity" & Chr(34), 0, True)
