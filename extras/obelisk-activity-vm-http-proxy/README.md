# Obelisk activity VM HTTP proxy

This static guest process terminates HTTP and HTTPS inside the activity VM and
exchanges request and response files with the Obelisk host through a writable
WASI directory exposed to Linux over virtio-9p.

The activity VM appliance installs the proxy at
`/usr/local/libexec/obelisk/obelisk-activity-vm-http-proxy`. Obelisk may replace
it at runtime by preopening an executable named
`obelisk-activity-vm-http-proxy.override` in `/obelisk-activity-vm-tools`.

The socket interception shim remains a runtime-provided artifact because it
must be ABI-compatible with the Nix executable being launched.
