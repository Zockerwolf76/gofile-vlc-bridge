#!/system/bin/sh
MODDIR=${0%/*}
# Wait until Android boot is complete so the background service starts reliably.
while [ "$(getprop sys.boot_completed)" != "1" ]; do sleep 2; done
chmod 755 "$MODDIR/bin/gofile-bridge"
"$MODDIR/bin/gofile-bridge" >>"$MODDIR/bridge.log" 2>&1 &
