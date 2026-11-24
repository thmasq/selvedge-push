#!/bin/sh
if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	# DEB passes "configure" and $2=<old-version> on upgrade.
	if [ "$1" = "configure" ] && [ -n "$2" ]; then
		systemctl try-restart selvedge-push.service >/dev/null 2>&1 || true
	fi
fi
