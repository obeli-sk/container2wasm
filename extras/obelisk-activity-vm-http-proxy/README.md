# Obelisk activity VM HTTP proxy

This static guest process terminates HTTP and HTTPS inside the activity VM and
exchanges request and response files with the Obelisk host through a writable
WASI directory exposed to Linux over virtio-9p.

The activity VM appliance installs the proxy at
`/usr/local/libexec/obelisk/obelisk-activity-vm-http-proxy`. It also provides a
guest-local DNS responder which resolves names to the proxy's HTTP and HTTPS
loopback listeners. This transparently covers static and dynamic executables
without relying on an ABI-specific `LD_PRELOAD` shim.

`obelisk-host` is reserved as the guest spelling of the Obelisk host. The proxy
rewrites it to `localhost` before forwarding the request through the bridge, so
existing HTTP policy remains portable across VM, exec, WASM, and JS activities:

```toml
[[activity_vm.allowed_host]]
pattern = "http://localhost:5005"
```

```sh
curl http://obelisk-host:5005/v1/executions
```

Guest `localhost` remains guest-local. The alias rewrite applies only to the
exact `obelisk-host` authority, optionally followed by a port.

The appliance also listens for plain HTTP on `obelisk-host:5005`, Obelisk's
default API port. This permits the direct curl form above without `--connect-to`.
