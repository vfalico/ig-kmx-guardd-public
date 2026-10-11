# AgentPolicy gadget

The standalone AgentPolicy gadget enforces exact executable and write-open
rules for one cgroup-v2 workload with BPF LSM. It accepts one strict
`agentpolicy.gadget/v1alpha1` JSON document, compiles it in WASM, populates
bounded maps, and commits the policy atomically before reporting `READY`.

Network enforcement is not part of this release. Any non-empty
`denyNetworks` policy is rejected before activation, and guardd independently
requires the network map to remain empty.

## Build against the owner IG fork

Clone `vfalico/inspektor-gadget-public` beside this repository. The IG module
keeps its canonical path, so a local Go workspace selects the owner-fork
checkout without changing imports:

```bash
go work init ./ig-kmx-guardd-public/gadget ./inspektor-gadget-public
go work edit \
  -replace=github.com/inspektor-gadget/inspektor-gadget@v0.0.0=./inspektor-gadget-public
cd ig-kmx-guardd-public/gadget
go test ./...
go vet ./...
GOWORK=off go mod edit \
  -replace=github.com/inspektor-gadget/inspektor-gadget@v0.0.0=../../inspektor-gadget-public
GOWORK=off go mod tidy
GOWORK=off go mod vendor
../../inspektor-gadget-public/ig image build \
  --builder-image-pull=missing \
  --update-metadata \
  --validate-metadata \
  -t ghcr.io/vfalico/ig-kmx-guardd-public/agentpolicy:0.4.1 .
rm -rf vendor
git restore gadget.yaml go.mod go.sum
git diff --exit-code
```

The host tests use the machine-local `go.work`. The containerized IG image
builder cannot see that parent workspace, so the next three commands create a
temporary vendor tree from the same owner-fork checkout. Do not commit
`go.work`, the temporary `replace`, or `vendor/`. Build the `ig` executable
normally from the owner fork before running the image command. The explicit
owner-controlled OCI name prevents IG's short-name default from attributing the
artifact to the upstream `inspektor-gadget` package namespace.

## Policy boundary

Required top-level keys are `apiVersion`, `kind`, `metadata`, and `spec`.
Unknown and duplicate keys are rejected. `metadata.name` and a lowercase
`sha256:` digest are required. `spec.failureMode` is `closed` or `open`.
Rule IDs and canonical absolute paths are unique.

Limits:

- document: 256 KiB;
- path: 255 bytes;
- executable rules: 64; and
- write rules: 128.

The WASM map population completes before `policy_state` becomes active. Kernel
events include the operation, decision, reason, rule ID, cgroup ID, process and
user identity, policy generation, errno, and resolved object path.

guardd loads this gadget directly through the pinned owner-fork `ig` executable.
There is no adapter image, init container, or bundled second copy of IG.
