#!/bin/sh
#
# dpi-for-everyone: double-click uninstaller for macOS. Finder runs
# .command files in Terminal.app automatically. Asks for your password
# once (sudo) and runs uninstall.sh from this same folder. To also
# remove settings and logs, run uninstall.sh --purge directly instead.
set -u
cd "$(dirname "$0")" || { echo "uninstall.command: could not cd to its own folder" >&2; exit 1; }
echo "dpi-for-everyone uninstaller"
echo "This needs administrator (sudo) access to remove the service."
echo
if sudo ./uninstall.sh; then status=0; else status=$?; fi
echo
if [ $status -eq 0 ]; then
	echo "Done. You can close this window."
else
	echo "Uninstall did not finish successfully (exit $status). See the output above."
fi
printf 'Press Return to close this window...'
read -r _ || true
