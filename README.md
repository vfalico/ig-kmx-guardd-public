# ig-kmx-guardd

`ig-kmx-guardd` is a privileged, node-local activation service for narrowly
scoped agent policies. It loads a digest-pinned
[Inspektor Gadget](https://github.com/vfalico/inspektor-gadget-public) image,
binds the policy to one exact cgroup-v2 workload, and returns signed evidence
only after the gadget and kernel attachment are verified.

This repository contains:

- the Python guard daemon and its Unix `SOCK_SEQPACKET` protocol;
- a BPF LSM gadget for exact executable and write-open rules;
- a fail-safe guardian that freezes the target cgroup when required control
  processes disappear;
- signed, hash-chained activation receipts; and
- packaging and contract tests.

The companion architecture and deployment guide is in
[`vfalico/agentpolicy-guardd-integration-public`](https://github.com/vfalico/agentpolicy-guardd-integration-public).

## Current scope

The gadget can enforce exact executable and write-open rules for one cgroup-v2
workload. The portable Kaimahi-to-Orka contract currently authors exact-path
write denial only. Direct executable rules are available at the guardd/gadget
boundary but are not silently derived from portable write rules.

Network enforcement is not part of this release. Non-empty network rules are
rejected before activation. The project does not claim general read
confinement, rename/unlink coverage, inherited-descriptor mediation, or process
termination.

## Trust boundary

guardd is the sole privileged Inspektor Gadget actuator. Its caller supplies an
already-open cgroup directory file descriptor over Unix `SCM_RIGHTS`; a caller
path string is never authorization. Requests are deterministic CBOR inside a
protobuf frame and are authorized with COSE Sign1/Ed25519. Activation receipts
bind the policy, gadget, session, cgroup, guardian, and observed kernel
attachments.

The release gate is fail closed:

1. the workload process starts stopped;
2. the caller moves it into an exact child cgroup;
3. guardd validates the request and cgroup identity;
4. guardd loads the pinned gadget and provisions the policy;
5. guardd verifies worker, map, cgroup, and attachment evidence;
6. the fail-safe guardian acknowledges readiness; and
7. only then may the caller verify the signed receipt and release execution.

Kernel decisions are made synchronously by BPF LSM hooks. Event records are
evidence after the decision, not the enforcement mechanism.

## Requirements

- Linux with cgroup v2 and BPF LSM enabled;
- Python 3.11 or newer;
- OpenSSL 3;
- `bpftool`;
- an owner-controlled Inspektor Gadget build from
  `vfalico/inspektor-gadget-public`; and
- root privileges for installation and BPF/cgroup operation.

The service unit bounds capabilities and filesystem access, but guardd remains
a privileged security component. Review the configuration and deployment
paths before using it outside an isolated test node.

## Build

Clone the integration branches and the pinned owner Inspektor Gadget source:

```bash
branch=agentpolicy-kmx-orka-ig-guardd-current
git clone --branch "$branch" \
  https://github.com/vfalico/ig-kmx-guardd-public.git
git clone https://github.com/vfalico/inspektor-gadget-public.git
git -C inspektor-gadget-public checkout \
  b6dce71343f02269051fdea4e0d463d72c1d5310
```

Use the companion integration repository's `release-manifest.json` to verify
the exact guardd implementation and publication identity. The manifest avoids
an impossible self-reference from this README while keeping the clone
reproducible.

Create an isolated Python environment and run the host tests:

```bash
cd ig-kmx-guardd-public
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

Build the gadget against the owner-controlled IG checkout by following
[`gadget/README.md`](gadget/README.md). That workflow keeps canonical Go module
paths and uses a local workspace or temporary vendor tree to select the owner
fork. Do not commit `go.work`, a temporary `replace`, or `vendor/`.

## Configure and install

1. Build and verify the gadget OCI archive.
2. Build the owner-fork `ig` executable.
3. Generate separate Ed25519 key pairs for request authorization and receipt
   signing.
4. Install the Python package into the fixed service virtual environment:

   ```bash
   sudo python3 -m venv /opt/ig-kmx-guardd/venv
   sudo /opt/ig-kmx-guardd/venv/bin/python -m pip install --upgrade pip
   sudo /opt/ig-kmx-guardd/venv/bin/python -m pip install .
   ```

5. Install the service unit.
6. Copy [`packaging/config.example.json`](packaging/config.example.json) to
   `/etc/ig-kmx-guardd/config.json` and replace every example identity, path,
   and digest.
7. Install the authorization public key for guardd, the matching private key
   for Orka, the receipt private key for guardd, and the matching public key for
   Orka.
8. Verify the configured IG executable and OCI archive SHA-256 values before
   starting the service.

The example `allowed_uids` value is `0`, matching the Orka supervisor
container's Unix peer UID in this integration. If the supervisor security
context changes, update the allowlist to the exact observed UID. Peer UID
matching does not replace COSE authorization.

The launcher rejects unknown configuration fields, non-absolute paths,
insecure key files, malformed digests, inconsistent key pairs, and incomplete
identity configuration. The packaged service expects:

```text
/etc/ig-kmx-guardd/config.json
/etc/ig-kmx-guardd/kmx-authorization-public.pem
/etc/ig-kmx-guardd/receipt-private.pem
/etc/ig-kmx-guardd/receipt-public.pem
/run/ig-kmx-guardd/guardd.sock
/var/lib/ig-kmx-guardd/state.db
```

Validate configuration in an isolated environment before enabling the unit:

```bash
sudo install -D -m 0644 packaging/ig-kmx-guardd.service \
  /etc/systemd/system/ig-kmx-guardd.service
sudo systemctl daemon-reload
sudo systemctl start ig-kmx-guardd.service
sudo systemctl status --no-pager ig-kmx-guardd.service
```

## Test strategy

The repository tests cover protocol encoding, signatures, replay rejection,
strict policy validation, cgroup descriptor handling, activation lifecycle,
guardian readiness, crash recovery, evidence bounds, and transport behavior.
The gadget tests cover policy compilation and deterministic map keys.

A complete manual acceptance test must additionally verify on a disposable
Linux node that:

- provider execution remains held before a valid guardian-bound receipt;
- a configured exact write is denied while a neighboring path remains allowed;
- the expected gadget and BPF program identities appear in the signed receipt;
- worker, event-consumer, guardd, and guardian-control failures freeze the
  target cgroup before retirement;
- controller and daemon restart reconcile durable state; and
- cleanup leaves no test cgroups, gadget processes, or BPF programs.

See the companion integration guide for the end-to-end Orka and Kaimahi flow.

## License

The guardd service is licensed under Apache-2.0. The gadget carries the
license terms declared in [`gadget/LICENSE`](gadget/LICENSE) and its OCI
metadata.
