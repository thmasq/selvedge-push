#!/bin/sh
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if [ "$1" = "1" ] || [ "$1" = "upgrade" ]; then
		systemctl try-restart selvedge-push.service >/dev/null 2>&1 || true
	fi
fi
