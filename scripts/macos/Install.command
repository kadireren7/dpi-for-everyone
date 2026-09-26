#!/bin/sh
#
# dpi-for-everyone: double-click installer for macOS. Finder runs
# .command files in Terminal.app automatically. Asks for your password
# once (sudo) and runs install.sh from this same folder. For
# manual/scripted installs, run install.sh directly instead.
set -u
cd "$(dirname "$0")" || { echo "install.command: could not cd to its own folder" >&2; exit 1; }
echo "dpi-for-everyone installer"
echo "This needs administrator (sudo) access to install a system service."
echo
if sudo ./install.sh; then status=0; else status=$?; fi
echo
if [ $status -eq 0 ]; then
	echo "Done. You can close this window."
else
	echo "Install did not finish successfully (exit $status). See the output above."
fi
printf 'Press Return to close this window...'
read -r _ || true
