#!/bin/sh
if command -v rc-service >/dev/null 2>&1; then
	rc-service selvedge-push stop >/dev/null 2>&1 || true
fi
if command -v rc-update >/dev/null 2>&1; then
	rc-update del selvedge-push default >/dev/null 2>&1 || true
fi
