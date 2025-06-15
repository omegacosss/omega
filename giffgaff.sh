#!/bin/bash

# 你的Telegram机器人API令牌和聊天ID
API_TOKEN="7993163707:AAGzq2j7wDWhB664n-Ho4VCwGkNLlXdbn0U"
CHAT_ID="7562806496"
MESSAGE="giffgaff该续期啦！！!"

# 向Telegram发送消息
curl -s -X POST https://api.telegram.org/bot$API_TOKEN/sendMessage -d chat_id=$CHAT_ID -d text="$MESSAGE"