#!/bin/sh
# RPM passes $1=0 on uninstall (1 on upgrade); DEB passes "remove".
if [ "$1" = "0" ] || [ "$1" = "remove" ]; then
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop selvedge-push.service >/dev/null 2>&1 || true
		systemctl disable selvedge-push.service >/dev/null 2>&1 || true
	fi
fi
