# Obelisk activity VM HTTP proxy

This static guest process terminates HTTP and HTTPS inside the activity VM and
exchanges request and response files with the Obelisk host through a writable
WASI directory exposed to Linux over virtio-9p.

The activity VM appliance installs the proxy at
`/usr/local/libexec/obelisk/obelisk-activity-vm-http-proxy`. It also provides a
guest-local DNS responder which resolves names to the proxy's HTTP and HTTPS
loopback listeners. This transparently covers static and dynamic executables
without relying on an ABI-specific `LD_PRELOAD` shim.
