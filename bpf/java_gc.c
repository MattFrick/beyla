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

#define MAX_JAVA_PIDS  100
typedef struct java_gc_t {
    u64 gc_begin_monotime_ns;
} java_gc;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // key: pointer to the request goroutine
    __type(value, java_gc);
    __uint(max_entries, MAX_JAVA_PIDS);
} ongoing_java_GC SEC(".maps");

SEC("uprobe/mem__pool__gc__begin")
int uprobe_MemPoolGcBegin(struct pt_regs *ctx) {
    java_gc gc = { .gc_begin_monotime_ns = bpf_ktime_get_ns() };
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_dbg_printk("=== uprobe/MemPoolGcBegin pid=%u, gid=%u", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);
    u32 pid = valid_pid(pid_tgid);
    if (pid) {
        if (0 != bpf_map_update_elem(&ongoing_java_GC, &pid, &gc, BPF_NOEXIST)) {
            bpf_dbg_printk("Couldn't update ongoing GC map");
        }
    }
    return 0;
}

static inline void submit_gc_event(java_gc *gc, u64 gc_end_monotime_ns, u32 pid) {
    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return;
    }
    trace->type = EVENT_JAVA_GC;
    trace->id = (u64)pid;
    trace->start_monotime_ns = gc->gc_begin_monotime_ns;
    trace->end_monotime_ns = gc_end_monotime_ns;
    bpf_ringbuf_submit(trace, get_flags());
}

SEC("uprobe/mem__pool__gc__end")
int uprobe_MemPoolGcEnd(struct pt_regs *ctx) {
    u64 gc_end_monotime_ns = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_dbg_printk("=== uprobe/MemPoolGcEnd === pid=%u, tgid=%u", pid_tgid >> 32, pid_tgid & 0xFFFFFFFF);
    u32 pid = valid_pid(pid_tgid);
    if (pid) {
        java_gc *gc = bpf_map_lookup_elem(&ongoing_java_GC, &pid); 
        if (gc != NULL) {
            submit_gc_event(gc, gc_end_monotime_ns, pid);
            bpf_map_delete_elem(&ongoing_java_GC, &pid);
        }
    } else {
        // Remove potential for stale entries if pid were to become invalid:
        bpf_map_delete_elem(&ongoing_java_GC, &pid);
    }
    return 0;
}
