#!/bin/sh
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	# RPM passes $1=1 on upgrade (0 on uninstall).
	if [ "$1" = "1" ]; then
		systemctl try-restart selvedge-push.service >/dev/null 2>&1 || true
	fi
fi
