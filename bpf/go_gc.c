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

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_GO_PIDS  100
typedef struct go_gc_t {
    u64 world_stop_monotime_ns;
    u8  reason;
} go_gc;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // key: pid
    __type(value, go_gc);
    __uint(max_entries, MAX_GO_PIDS);
} ongoing_GC SEC(".maps");


static inline bool reason_is_GC(u8 reason) {
    switch (reason) {
    case 1: // 	stwGCMarkTerm  // "GC mark termination"
    case 2: // 	stwGCSweepTerm // "GC sweep termination"
        return true;
    default:
        // Some other stop the world reason that we're not instrumenting here.
        return false;
    }
}

SEC("uprobe/runtime_stopTheWorldWithSema")
int uprobe_runtime_stop_the_world_with_sema(struct pt_regs *ctx) {
    go_gc gc = { .world_stop_monotime_ns = bpf_ktime_get_ns() };
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_dbg_printk("=== uprobe_runtime_stop_the_world_with_sema pid=%u, gid=%u", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);
    u32 pid = valid_pid(pid_tgid);
    if (pid) {
        gc.reason = (u8)(u64)ctx->ax; // TODO: Fix headers to allow pid.h and vmlinux to define ax vs. rax
        if (0 != bpf_map_update_elem(&ongoing_GC, &pid, &gc, BPF_NOEXIST)) {
            bpf_dbg_printk("Couldn't update ongoing GC map");
        }
    }
    return 0;
}

static inline void submit_gc_event(go_gc *gc, u32 pid, u64 world_start_time) {
    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return;
    }
    //trace->type = EVENT_GO_GC_EVENT;
    trace->id = (u64)pid;
    // Event is duration that GC stopped the world.  So event _start_ time is world _stop_ time:
    trace->start_monotime_ns = gc->world_stop_monotime_ns;
    trace->end_monotime_ns = world_start_time;
}

SEC("uprobe/runtime_startTheWorldWithSema")
int uprobe_runtime_start_the_world_with_sema(struct pt_regs *ctx) {
    u64 world_start_time = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_dbg_printk("=== uprobe_runtime_start_the_world_with_sema === pid=%u, gid=%u", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);
    u32 pid = valid_pid(pid_tgid);
    if (pid) {
        go_gc *gc = bpf_map_lookup_elem(&ongoing_GC, &pid); 
        if (gc != NULL) {
            u64 elapsed = world_start_time - gc->world_stop_monotime_ns;
            if (reason_is_GC(gc->reason)) {
                bpf_printk("World was stopped by GC for: %luus", elapsed/1000); // TODO: REMOVE ME
                submit_gc_event(gc, pid, world_start_time);
            } else {
                bpf_printk("WORLD STOPPED FOR SOMETHING ELSE: %luus", elapsed/1000);    // TODO: REMOVE ME
            }
            bpf_map_delete_elem(&ongoing_GC, &pid);
        }
    }
    return 0;
}
