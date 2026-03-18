# Disk Layout Specification

## Overview

The QNX hypervisor manages a single storage device (eMMC or NVMe) partitioned
to support A/B banking for the hypervisor itself and up to two guest OS images.
All images are verified by the hypervisor before use. Guest OS partitions are
presented read-only to VMs.

## Partition Table (GPT)

| #  | Label          | Size    | Type    | Description                              |
|----|----------------|---------|---------|------------------------------------------|
| 1  | `boot`         | 64 MB   | raw     | QNX IPL + first-stage loader (not banked)|
| 2  | `hyp-a`        | 512 MB  | raw     | QNX hypervisor image, bank A             |
| 3  | `hyp-b`        | 512 MB  | raw     | QNX hypervisor image, bank B             |
| 4  | `os1-a`        | 2 GB    | ext4    | OS1 image (kernel + rootfs), bank A      |
| 5  | `os1-b`        | 2 GB    | ext4    | OS1 image (kernel + rootfs), bank B      |
| 6  | `os2-a`        | 2 GB    | ext4    | OS2 image (kernel + rootfs), bank A      |
| 7  | `os2-b`        | 2 GB    | ext4    | OS2 image (kernel + rootfs), bank B      |
| 8  | `nv`           | 32 MB   | raw     | NV data store (bank manager managed)     |
| 9  | `data`         | 2 GB    | ext4    | Persistent data (keys, config, app state)|
| 10 | `containers`   | varies  | ext4    | Container image store (Podman/Docker)    |
| 11 | `swap`         | >= RAM  | raw     | Linux VM hibernate (resume=)             |

### Notes

- **boot**: Contains the IPL (Initial Program Loader) and first-stage bootloader.
  Not A/B banked. Updated rarely, locked down. The bootloader reads NV Boot State
  to determine which hypervisor bank to load.

- **hyp-a/b**: Full QNX hypervisor image. The bootloader verifies the SHA-256 hash
  (from NV FW Meta) before executing. Read-only at runtime.

- **os1-a/b, os2-a/b**: Complete guest OS stacks (kernel + rootfs + modules).
  Presented to VMs as read-only block devices. The hypervisor verifies SHA-256
  before mapping to the VM.

- **nv**: Single raw partition managed internally by the bank manager. Contains
  boot state, factory data, per-bank metadata, and application data. See
  [nv-store-format.md](nv-store-format.md) for internal layout.

- **data**: Not banked. Persists across OS updates. Contains HSM wrapped keys,
  runtime configuration, application state. Mounted read-write by the guest VM.

- **containers**: Not banked. Stores container images pulled at runtime. Base
  containers may be baked into the OS image; this partition holds runtime layers.
  Size depends on workload.

- **swap**: Not banked. Used for Linux VM hibernate (S4). Must be at least as
  large as VM RAM allocation. Kernel cmdline: `resume=/dev/vdX`.

## Partition Discovery

Partitions are identified by **GPT partition label** (not device enumeration
order) to avoid sensitivity to device probe ordering. The bank manager uses
labels to find the NV partition and image partitions.

## Sizing

The sizes above assume a 16 GB device. For larger devices, expand `containers`
and `data`. For constrained devices (8 GB), reduce OS image sizes or drop OS2.

The three A/B bank sets (hyp + os1 + os2) consume ~9 GB. NV + data + containers
+ swap consume the remainder.
