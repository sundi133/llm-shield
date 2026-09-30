#!/bin/sh
# Removes the agent, its trust entries and its device key. Run as root
# (Jamf and Kandji can run it as a script).
BASE="/Library/Application Support/Votal/DeviceAgent"
/bin/launchctl bootout system/ai.votal.device-agent 2>/dev/null || true
"$BASE/bin/votal-device-agent" uninstall-hooks 2>/dev/null || true
rm -f /Library/LaunchDaemons/ai.votal.device-agent.plist
rm -rf "$BASE"
/usr/sbin/pkgutil --forget ai.votal.device-agent >/dev/null 2>&1 || true
echo "Votal device agent removed. Remove its MDM profiles to clear the proxy setting."
