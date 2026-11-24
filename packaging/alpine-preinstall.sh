#!/bin/sh
getent group selvedge-push >/dev/null 2>&1 || addgroup -S selvedge-push
getent passwd selvedge-push >/dev/null 2>&1 || adduser -S -D -H -h /nonexistent -s /sbin/nologin -G selvedge-push selvedge-push
