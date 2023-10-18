// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "vmlinux.h"
#include "pid.h"
#include "utils.h"
#include "bpf_dbg.h"
#include "ringbuf.h"
#include "http_trace.h"
#include "gc.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_STW_GC_MARK_TERM     1
#define GO_STW_GC_SWEEP_TERM    2

// For Go we track 2 things seperately:
// 1) the pair of stop-the-world pauses during GC mark
// 2) the entire GC start through finish of concurrent GC mark phase.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // key: pid
    __type(value, gc_event);
    __uint(max_entries, MAX_ONGOING_GC_ENTRIES);
} ongoing_go_gc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // key: pid
    __type(value, gc_event);
    __uint(max_entries, MAX_ONGOING_GC_ENTRIES);
} ongoing_go_stw_gc SEC(".maps");

static inline u16 go_reason_to_gc_action(u8 reason) {
    switch (reason) {
    case GO_STW_GC_MARK_TERM:  // End of mark phase
        return (u16)GC_STW_MARK_TERM;
    case GO_STW_GC_SWEEP_TERM: // Start of mark phase
        return (u16)GC_STW_SWEEP_TERM;
    default:
        return (u16)GC_UNKNOWN;
    }
}

SEC("uprobe/runtime_stopTheWorldWithSema")
int uprobe_runtime_stop_the_world_with_sema(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();
    u8 go_reason_arg = (u8)(u64)ctx->ax; // TODO: Fix headers to allow pid.h and vmlinux to define ax vs. rax for GO_PARAM1
    bpf_dbg_printk("== uprobe/runtime_startTheWorldWithSema reason=%u", go_reason_arg);
    u16 gc_action = go_reason_to_gc_action(go_reason_arg);
    record_gc_start(&ongoing_go_stw_gc, now, gc_action, GC_LANG_GO);
    return 0;
}

SEC("uprobe/runtime_startTheWorldWithSema")
int uprobe_runtime_start_the_world_with_sema(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();
    bpf_dbg_printk("== uprobe/runtime_startTheWorldWithSema ==");
    record_gc_end_event(&ongoing_go_stw_gc, now);
    return 0;
}

SEC("uprobe/runtime_gcBgMarkStartWorkers")
int uprobe_runtime_gcBgMarkStartWorkers(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();
    bpf_dbg_printk("=== uprobe/runtime_gcBgMarkStartWorkers ===");
    record_gc_start(&ongoing_go_gc, now, GC_MARK, GC_LANG_GO);
    return 0;
}

SEC("uprobe/runtime_freeStackSpans")
int uprobe_runtime_freeStackSpans(struct pt_regs *ctx) {
    u64 now = bpf_ktime_get_ns();
    bpf_dbg_printk("=== uprobe/runtime_freeStackSpans ===");
    record_gc_end_event(&ongoing_go_gc, now);
    return 0;
}
