#!/bin/bash
echo "正在下载最新的 geoip.dat 和 geosite.dat ..."
wget -O geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
wget -O geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
echo "下载完成！文件列表："
ls -lh geoip.dat geosite.dat
