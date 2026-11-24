#!/bin/sh
if command -v rc-service >/dev/null 2>&1; then
	if rc-service selvedge-push status >/dev/null 2>&1; then
		rc-service selvedge-push restart >/dev/null 2>&1 || true
	fi
fi
