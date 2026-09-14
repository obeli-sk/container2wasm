# QEMU Wasmtime JIT experiment

The experiment pins the QEMU backend fork and commit in the container2wasm
Dockerfile:

```console
$ make c2w
$ ./out/c2w \
    --target-stage qemu-wasmtime-jit-amd64 \
    --build-arg QEMU_WASMTIME_JIT=true \
    'alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc' \
    /tmp/qemu-wasmtime-jit/
```

The current target validates and exports the outer QEMU module built by the
existing Emscripten toolchain. It is not yet the final WASI appliance: the
module still has Emscripten runtime imports in addition to the new
`qemu_jit` imports. The production target needs a WASI-compatible QEMU runtime
or a Wasmtime host layer that supplies those runtime imports.

Use these appliance parameters for the first Linux and Nix benchmark:

```text
TARGETARCH=amd64
VM_CORE_NUMS=1
VM_MEMORY_SIZE_MB=1024
QEMU_MIGRATION=true
LOAD_MODE=single
OPTIMIZATION_MODE=wizer
QEMU_WASMTIME_JIT=true
EXTERNAL_DISK_PATH=/external/store.squashfs
```

`EXTERNAL_DISK_PATH` is the interface to reuse from the concurrent SquashFS
work. In this base revision it is wired only to the Bochs WASI configuration,
so the QEMU WASI target must also translate it into a read-only QEMU disk
argument after that work is merged. Keep it unset for the Alpine-only smoke
test, then point it at the guest path mapped to the Nix store image for the
file benchmark.
