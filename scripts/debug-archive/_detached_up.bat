@echo off
rem 无人值守演示环境启动器（AI/后台场景：脱离调用方会话树——Task Scheduler 宿主）。
rem 真人终端请直接跑 scripts\demo_up.py（独立控制台窗口可见）。
set "UAS=%~dp0.."
set "PY=%UAS%\backend\.venv\Scripts\python.exe"
if not exist "%UAS%\logs" mkdir "%UAS%\logs"
cd /d "%UAS%"
"%PY%" scripts\demo_up.py > "%UAS%\logs\demo_up_detached.log" 2>&1
