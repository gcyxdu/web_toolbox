@echo off
cd /d "d:\联合成果展示\portal"
echo 入口页: http://127.0.0.1:8090/
python -m http.server 8090
