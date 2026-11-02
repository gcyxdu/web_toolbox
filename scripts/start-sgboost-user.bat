@echo off
cd /d C:\SGBoost
echo 连接 CSP 做推理。若提示 Connection refused，说明模型服务还没起来，等训练日志结束后再运行。
"D:\PyCharm\PyCharm 2026.2.1\jbr\bin\java.exe" -cp C:\SGBoost\SGBoost.jar user.user
pause
