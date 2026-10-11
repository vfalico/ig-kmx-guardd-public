// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Veaceslav Falico */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <gadget/buffer.h>
#include <gadget/macros.h>

#define AP_INITIALIZING 0
#define AP_ACTIVE 1
#define AP_FAILED 2
#define AP_MAX_PATH 256
#define AP_OP_EXEC 1
#define AP_OP_WRITE_OPEN 2
#define AP_OP_WRITE 3
#define AP_OP_CONNECT 4
#define AP_DECISION_ALLOW 1
#define AP_DECISION_DENY 2
#define AP_REASON_RULE 1
#define AP_REASON_FAIL_CLOSED 2
#define AP_REASON_QUARANTINE 3
#define AP_ACTION_NONE 0
#define AP_ACTION_EPERM 1
#define MAY_WRITE 2
#define O_ACCMODE 3
#define O_WRONLY 1
#define O_RDWR 2
#define AF_INET 2
#define IPPROTO_TCP 6

/* These are rewritten by vanilla IG before load, so startup protection is active
 * before the packaged WASM parses and commits the policy maps. */
const volatile __u64 target_cgroup_id = 0;
const volatile bool fail_closed = true;
GADGET_PARAM(target_cgroup_id);
GADGET_PARAM(fail_closed);

struct path_key { char path[AP_MAX_PATH]; };
struct net_key { __u8 address[4]; __u16 port_be; __u16 pad; };
struct inode_key { __u64 ino; __u32 dev; __u32 pad; };
struct path_scratch { struct path_key raw; struct path_key key; };
struct rule_value { __u32 rule_id; __u32 quarantine; };
struct write_rule_value { __u32 rule_id; __u32 quarantine; char path[AP_MAX_PATH]; };
struct policy_state { __u32 state; __u32 quarantined; __u32 generation; __u32 failure_closed; };
struct event {
    __u64 timestamp_raw;
    __u64 cgroup_id;
    __u64 pid_tgid;
    __u32 uid_gid;
    __u32 operation;
    __u32 decision;
    __u32 reason;
    __u32 action;
    __u32 rule_id;
    __s32 kernel_errno;
    __u32 policy_generation;
    __u8 address[4];
    __u16 port_be;
    __u16 pad;
    char comm[16];
    char object[AP_MAX_PATH];
};

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct policy_state); } policy_state SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct path_scratch); } path_scratch SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64); __type(key, struct path_key); __type(value, struct rule_value); } exec_rules SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 128); __type(key, __u64); __type(value, struct write_rule_value); } write_rules SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256); __type(key, struct net_key); __type(value, struct rule_value); } network_rules SEC(".maps");
/* Populated only after a sleepable file_open path match; bounded cache makes
 * file_permission enforcement non-sleepable and TOCTOU-resistant by inode. */
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 256); __type(key, struct inode_key); __type(value, struct rule_value); } denied_inodes SEC(".maps");
GADGET_TRACER_MAP(events, 8 * 1024 * 1024);
GADGET_TRACER(agentpolicy, events, event);

static __always_inline struct policy_state *state(void) { __u32 k = 0; return bpf_map_lookup_elem(&policy_state, &k); }
static __always_inline bool is_target(void) { return target_cgroup_id && bpf_get_current_cgroup_id() == target_cgroup_id; }
static __always_inline int emit_deny(void *ctx, __u32 op, __u32 reason, __u32 rule_id, const char *path, struct net_key *net, struct policy_state *st)
{
    struct event *e = gadget_reserve_buf(&events, sizeof(*e));
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->timestamp_raw = bpf_ktime_get_boot_ns(); e->cgroup_id = bpf_get_current_cgroup_id();
        e->pid_tgid = bpf_get_current_pid_tgid(); e->uid_gid = (__u32)bpf_get_current_uid_gid();
        e->operation = op; e->decision = AP_DECISION_DENY; e->reason = reason;
        e->action = AP_ACTION_EPERM; e->kernel_errno = -1; e->rule_id = rule_id;
        if (st) e->policy_generation = st->generation;
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        if (path) __builtin_memcpy(e->object, path, sizeof(e->object));
        if (net) { __builtin_memcpy(e->address, net->address, 4); e->port_be = net->port_be; }
        gadget_submit_buf(ctx, &events, e, sizeof(*e));
    }
    return -1; /* -EPERM */
}
static __always_inline int startup_gate(void *ctx, __u32 op, struct policy_state *st)
{
    if ((!st || st->state != AP_ACTIVE) && fail_closed)
        return emit_deny(ctx, op, AP_REASON_FAIL_CLOSED, 0, 0, 0, st);
    return 0;
}
static __always_inline struct path_key *resolve_path(struct path *p)
{
    __u32 zero = 0; struct path_scratch *sc = bpf_map_lookup_elem(&path_scratch, &zero); long n;
    if (!sc) return 0;
    __builtin_memset(&sc->raw, 0, sizeof(sc->raw));
    n = bpf_d_path(p, sc->raw.path, sizeof(sc->raw.path));
    if (n <= 0 || n > AP_MAX_PATH) return 0;
    /* bpf_d_path copies the path to the start but may leave its internal
     * end-of-buffer copy behind. Hash-map keys require deterministic padding. */
#pragma unroll
    for (int i = 0; i < AP_MAX_PATH; i++) {
        if (i >= n) sc->raw.path[i] = 0;
    }
    return &sc->raw;
}

SEC("lsm.s/bprm_check_security")
int BPF_PROG(agentpolicy_exec, struct linux_binprm *bprm, int ret)
{
    struct policy_state *st; struct path_key *key; struct rule_value *rule;
    if (ret) return ret; if (!is_target()) return 0;
    st = state(); if (startup_gate(ctx, AP_OP_EXEC, st)) return -1; if (!st || st->state != AP_ACTIVE) return 0;
    if (!bprm->file) return st->failure_closed ? emit_deny(ctx, AP_OP_EXEC, AP_REASON_FAIL_CLOSED, 0, 0, 0, st) : 0;
    /* bprm->filename is caller-controlled and preserves a symlink spelling.
     * Resolve the opened executable file instead, so policy is evaluated on
     * the same kernel object/path that will actually be executed. */
    key = resolve_path(&bprm->file->f_path);
    if (!key)
        return st->failure_closed ? emit_deny(ctx, AP_OP_EXEC, AP_REASON_FAIL_CLOSED, 0, 0, 0, st) : 0;
    rule = bpf_map_lookup_elem(&exec_rules, key);
    return rule ? emit_deny(ctx, AP_OP_EXEC, AP_REASON_RULE, rule->rule_id, key->path, 0, st) : 0;
}
static __always_inline bool same_path(const char *a, const char *b)
{
#pragma unroll
    for (int i = 0; i < AP_MAX_PATH; i++) {
        if (a[i] != b[i]) return false;
        if (!a[i]) return true;
    }
    return true;
}

static __always_inline __u64 hash_path(const char *p)
{
    __u64 h = 14695981039346656037ULL;
#pragma unroll
    for (int i = 0; i < AP_MAX_PATH; i++) {
        unsigned char c = p[i];
        if (!c) break;
        h ^= c; h *= 1099511628211ULL;
    }
    return h;
}
SEC("lsm.s/file_open")
int BPF_PROG(agentpolicy_open, struct file *file, int ret)
{
    struct policy_state *st; struct path_key *key; struct write_rule_value *rule; __u64 hash; int flags;
    if (ret) return ret; if (!is_target()) return 0;
    flags = BPF_CORE_READ(file, f_flags); if ((flags & O_ACCMODE) != O_WRONLY && (flags & O_ACCMODE) != O_RDWR) return 0;
    st = state(); if (startup_gate(ctx, AP_OP_WRITE_OPEN, st)) return -1; if (!st || st->state != AP_ACTIVE) return 0;
    key = resolve_path(&file->f_path);
    if (!key) return (st->failure_closed) ? emit_deny(ctx, AP_OP_WRITE_OPEN, AP_REASON_FAIL_CLOSED, 0, 0, 0, st) : 0;
    hash = hash_path(key->path);
    rule = bpf_map_lookup_elem(&write_rules, &hash);
    if (rule && same_path(key->path, rule->path)) {
        struct inode *inode = BPF_CORE_READ(file, f_inode); struct inode_key ik = {};
        if (inode) { ik.ino = BPF_CORE_READ(inode, i_ino); ik.dev = BPF_CORE_READ(inode, i_sb, s_dev); bpf_map_update_elem(&denied_inodes, &ik, rule, BPF_ANY); }
        return emit_deny(ctx, AP_OP_WRITE_OPEN, AP_REASON_RULE, rule->rule_id, key->path, 0, st);
    }
    return 0;
}
SEC("lsm/file_permission")
int BPF_PROG(agentpolicy_permission, struct file *file, int mask, int ret)
{
    struct policy_state *st; struct inode *inode; struct inode_key ik = {}; struct rule_value *rule;
    if (ret) return ret; if (!is_target() || !(mask & MAY_WRITE)) return 0;
    st = state(); if (startup_gate(ctx, AP_OP_WRITE, st)) return -1; if (!st || st->state != AP_ACTIVE) return 0;
    inode = BPF_CORE_READ(file, f_inode); if (!inode) return st->failure_closed ? emit_deny(ctx, AP_OP_WRITE, AP_REASON_FAIL_CLOSED, 0, 0, 0, st) : 0;
    ik.ino = BPF_CORE_READ(inode, i_ino); ik.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    rule = bpf_map_lookup_elem(&denied_inodes, &ik);
    return rule ? emit_deny(ctx, AP_OP_WRITE, AP_REASON_RULE, rule->rule_id, 0, 0, st) : 0;
}
SEC("lsm.s/socket_connect")
int BPF_PROG(agentpolicy_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    struct policy_state *st; struct sockaddr_in sa = {}; struct net_key key = {}; struct rule_value *rule; __u16 family; __u16 type;
    if (ret) return ret; if (!is_target()) return 0;
    st = state(); if (startup_gate(ctx, AP_OP_CONNECT, st)) return -1; if (!st || st->state != AP_ACTIVE) return 0;
    if (st->quarantined) return emit_deny(ctx, AP_OP_CONNECT, AP_REASON_QUARANTINE, 0, 0, 0, st);
    if (addrlen < (int)sizeof(sa)) return st->failure_closed ? emit_deny(ctx, AP_OP_CONNECT, AP_REASON_FAIL_CLOSED, 0, 0, 0, st) : 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family); if (family != AF_INET) return 0;
    type = BPF_CORE_READ(sock, type); if (type != 1) return 0;
    bpf_probe_read_kernel(&sa, sizeof(sa), address); __builtin_memcpy(key.address, &sa.sin_addr.s_addr, 4); key.port_be = sa.sin_port;
    rule = bpf_map_lookup_elem(&network_rules, &key);
    if (!rule) return 0; if (rule->quarantine) st->quarantined = 1;
    return emit_deny(ctx, AP_OP_CONNECT, AP_REASON_RULE, rule->rule_id, 0, &key, st);
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
