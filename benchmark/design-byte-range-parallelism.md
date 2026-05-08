# Design: Byte-Range Parallelism and Filesystem-Aware Transfers

## Motivation

Benchmark results (sftp-parallel-results.csv vs sftp-results.csv, May 2026) show that
parallel streams give large gains for multi-file workloads at high RTT (5–12x for small
files, 4–7x for medium files) but only modest gains for large files (1.2–1.9x). Two
related limitations drive this:

1. **Single-file transfers get zero parallel benefit.** With the current whole-file work
   unit model, one worker owns a file start-to-finish. A single 50 GB file transferred
   with -j8 uses exactly one stream.

2. **The TCP window bottleneck is still present for large files.** Multiple independent
   streams collectively maintain a higher aggregate congestion window than a single
   stream, giving ~1.86x at 100ms RTT for 500 MiB files. Byte-range splitting would
   apply the same TCP window benefit to any file regardless of file count.

The fix is byte-range parallelism: split a single large file into N ranges and assign
one range per worker, exactly as GridFTP does with Extended Block Mode.

## Protocol Feasibility

SFTP v3 (supported by all servers) supports offset-based I/O natively:
- `SSH_FXP_READ(handle, offset, length)` — download range
- `SSH_FXP_WRITE(handle, offset, data)` — upload range

No protocol extensions are needed for the actual data transfer. Multiple workers can
each hold an independent open handle to the same file and read/write their assigned
byte range.

## The Filesystem Alignment Problem

Naive byte-range splitting without knowledge of the target filesystem can hurt
performance on distributed/parallel filesystems common at HPC sites:

**Lustre**: Files are striped across OSTs (object storage targets). Writes that do not
align to the stripe boundary cause partial-stripe writes: the OST must read-modify-write
rather than doing a clean overwrite. This is expensive and can be worse than a single
stream. Additionally, each worker opening the same file acquires a Lustre LDLM extent
lock for its region — clean stripe-aligned ranges avoid lock contention.

**GPFS/Spectrum Scale**: Similar stripe/block alignment requirements. Concurrent writes
are safe (GPFS distributed locking is granular) but unaligned writes incur overhead.

**NFS**: Concurrent offset writes are safe (NFSv4 byte-range locking) but the NFS
server typically serializes conflicting writes, so gains are limited.

**Local filesystems (ext4, xfs, tmpfs)**: No alignment constraints. The kernel handles
concurrent pwrite() at different offsets cleanly.

## GridFTP Reference Implementation

GridFTP handles this via:

1. **Extended Block Mode (MODE E)**: Each data block carries an explicit offset+length
   header, making parallel byte-range transfer a first-class protocol feature.

2. **Lustre DSI plugin** (`globus_gridftp_server_lustre`): Calls `llapi_file_get_stripe()`
   before initiating the transfer, then aligns parallel stream boundaries to Lustre
   stripe boundaries. With N OSTs and stripe size S, it uses N streams each writing
   stripe-aligned ranges of size S.

3. **Cluster/striped mode**: Co-locates a GridFTP server process with each storage node.
   Each server instance handles only data physically local to its OST, sidestepping
   alignment entirely.

Our approach uses the DSI concept (server-side filesystem query, communicated to the
client via an SFTP extension) without requiring co-located server processes.

## Design

### New SFTP Extension: `hpn-fs-info@hpnssh.org`

Server advertises this in the `SSH_FXP_VERSION` extensions list. Client sends:

```
SSH_FXP_EXTENDED
  request-id       uint32
  "hpn-fs-info@hpnssh.org"   string
  path             string     # path being transferred to/from
```

Server responds:

```
SSH_FXP_EXTENDED_REPLY
  request-id       uint32
  fs_type          string     # "lustre", "gpfs", "xfs", "ext4", "nfs", "unknown", ...
  stripe_size      uint64     # bytes per stripe; 0 if not applicable
  stripe_count     uint32     # number of stripes/OSTs; 0 if not applicable
  block_size       uint64     # optimal I/O block size from statvfs (always present)
```

### Server-Side Detection (sftp-server.c)

Layered detection, each layer falling back to the next:

1. `statfs()` on the path → `f_type` magic number identifies filesystem type.
   Relevant constants from `<linux/magic.h>`:
   - `LUSTRE_SUPER_MAGIC` / `LL_SUPER_MAGIC`
   - `GPFS_SUPER_MAGIC`
   - `EXT4_SUPER_MAGIC` (0xEF53)
   - `XFS_SUPER_MAGIC` (0x58465342)
   - `NFS_SUPER_MAGIC` (0x6969)

2. For Lustre stripe geometry:
   - Primary: `llapi_file_get_stripe()` from `<lustre/lustreapi.h>` if compiled
     with `--with-lustre`
   - Fallback: invoke `lfs getstripe --yaml <path>` as subprocess and parse output
     (newer Lustre ≥ 2.12 outputs clean YAML; older versions use a parseable text
     format)

3. For GPFS stripe geometry:
   - Primary: `gpfs_fcntl()` from GPFS API if compiled with `--with-gpfs`
   - Fallback: invoke `mmlsattr -L <path>` as subprocess

4. If no stripe info available: return `block_size` from `statvfs.f_bsize`, zeros
   for stripe fields. Client treats this as "split however you like."

Build-time: `--with-lustre` and `--with-gpfs` are optional. Without them the extension
still works, returning type + block_size but not stripe geometry.

### Client-Side Range Splitting (sftp-parallel.c)

Before submitting work units for a large file transfer:

```
query hpn-fs-info for destination path
if extension not supported by server:
    fall back to equal-size ranges aligned to block_size
if stripe_size > 0:
    align range boundaries to stripe_size
    cap num_streams at stripe_count (more streams than OSTs gains nothing)
    num_ranges = min(num_streams, stripe_count)
    range_size = stripe_size  (or multiple thereof for large files)
else:
    num_ranges = num_streams
    range_size = ceil(file_size / num_ranges), aligned to block_size
```

For uploads, pre-create the remote file at the correct size before workers start:
- Single `SSH_FXP_OPEN` with `O_WRONLY|O_CREAT|O_TRUNC` from the orchestrator
- Immediately `SSH_FXP_SETSTAT` to set the final size (pre-allocates space on Lustre,
  avoids fragmented OST allocation)
- Workers then open with `O_WRONLY` only (no truncate) and write their range

### New Work Unit Types

Extend `sftp_op` in sftp-parallel.h:

```c
SFTP_OP_UPLOAD_RANGE    /* src_path, dst_path, offset, length */
SFTP_OP_DOWNLOAD_RANGE  /* src_path, dst_path, offset, length */
```

`sftp_work_unit` gains two new fields: `off_t range_offset`, `off_t range_length`.

These slot into the existing `execute_unit()` dispatch. Retry logic re-queues only the
failed byte range, not the whole file — cleaner than whole-file retry for large files.

### Threshold: When to Split vs. Whole-File

Byte-range splitting has overhead (extra open handles, pre-creation step, range
coordination). Not worth it for small files. Suggested threshold:

```c
#define RANGE_SPLIT_MIN_SIZE  (64 * 1024 * 1024)   /* 64 MiB */
```

Files below this threshold use the existing whole-file work units. Files at or above
use range splitting. The threshold should be tunable via config.

## Implementation Scope

| Component         | New code (approx) | Notes                                      |
|-------------------|-------------------|--------------------------------------------|
| sftp-server.c     | ~150 lines        | Extension handler, statfs, optional Lustre/GPFS query |
| sftp-client.c     | ~250 lines        | `sftp_upload_range()`, `sftp_download_range()` |
| sftp-parallel.c   | ~150 lines        | Range-split orchestration, pre-create step |
| sftp-parallel.h   | ~20 lines         | New op types, new work unit fields         |
| configure.ac      | ~50 lines         | `--with-lustre`, `--with-gpfs` detection   |

Total: ~620 lines, not counting tests.

## Dependencies on Earlier Work

- Requires Phase 2 complete (worker fault isolation) so a failed range worker doesn't
  kill the whole process
- Builds on existing parallel worker pool, workqueue, and retry machinery
- Follows the extension pattern established by `hpn-check-file@hpnssh.org`

## Expected Gains

Based on benchmark data:
- Single large file transfers: currently 0x benefit from -j N → should approach the
  same ~1.9x (at 100ms RTT) seen for multi-file large transfers
- Multi-file large transfers: small additional gain (alignment removes partial-stripe
  overhead on Lustre; main gains are already captured by file-level parallelism)
- HPC Lustre workloads specifically: potential for super-linear gains if stripe-aligned
  splitting allows each stream to hit a different OST with no lock contention

## Open Questions

1. Should range splitting be automatic (triggered by file size threshold) or require
   an explicit flag? Auto is more user-friendly; explicit gives operators control on
   shared systems.
2. For Lustre: if `lfs getstripe` is not available and `--with-lustre` was not compiled
   in, should we attempt a fixed alignment heuristic (e.g. 1 MiB, a common default
   stripe size) or refuse to split?
3. The `--with-gpfs` fallback (`mmlsattr`) requires GPFS admin tools to be in PATH on
   the server. Is that a safe assumption at GPFS sites?
