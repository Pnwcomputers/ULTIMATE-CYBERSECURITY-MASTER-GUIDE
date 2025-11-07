#!/bin/bash

clear

#start streaming
cd /./home/kali/CyberSecurity_Lab/mjpg-streamer
./mjpg_streamer -i "./input_uvc.so -r 320x240 -f 30 -q 95" -o "./output_http.so -w ./www -c admin:kali"
