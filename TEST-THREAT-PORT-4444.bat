@echo off
title Log Sentinel harmless port 4444 test
echo.
echo This is a HARMLESS Log Sentinel test.
echo It starts Python's built-in web server on 127.0.0.1:4444.
echo Log Sentinel should flag this as: High - Suspicious listening port 4444.
echo.
echo Keep this window open, then click Scan now in Log Sentinel.
echo Press Ctrl+C in this window to stop the test.
echo.
py -3 -m http.server 4444 --bind 127.0.0.1
