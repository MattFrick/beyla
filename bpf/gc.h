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

#ifndef __GC_H__
#define __GC_H__

#define MAX_ONGOING_GC_ENTRIES 100

typedef enum gc_lang_t {
    GC_LANG_UNKNOWN,
    GC_LANG_GO,
    GC_LANG_JAVA,
} gc_lang;

typedef enum gc_action_t {
    GC_UNKNOWN,
    GC_MARK,
    GC_SWEEP,
    GC_STW_MARK_TERM,
    GC_STW_SWEEP_TERM,
} gc_action;

typedef struct gc_event_t {
    u64       start_monotime_ns;
    gc_action action;
    gc_lang   lang;
} gc_event;

static inline void record_gc_start(void *map, u64 start_monotime_ns, gc_action action, gc_lang lang) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = valid_pid(pid_tgid);
    if (pid) {
        gc_event gc = { .start_monotime_ns = start_monotime_ns,
                        .action = action,
                        .lang = lang };
        if (0 != bpf_map_update_elem(map, &pid, &gc, BPF_NOEXIST)) {
            bpf_dbg_printk("Couldn't update ongoing GC map");
        }
    }
}

static inline void submit_gc_event(gc_event *gc, u64 end_monotime_ns, u32 pid) {
    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return;
    }
    trace->type = EVENT_GO_GC;  // TODO: Generic GC type
    trace->id = (u64)pid;
    trace->status = (u16)gc->action;
    trace->start_monotime_ns = gc->start_monotime_ns;
    trace->end_monotime_ns = end_monotime_ns;
    bpf_ringbuf_submit(trace, get_flags());
}

static inline void record_gc_end_event(void *map, u64 end_monotime_ns) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = valid_pid(pid_tgid);
    if (pid) {
        gc_event *gc = bpf_map_lookup_elem(map, &pid);
        if (gc != NULL) {
            if (gc->action != GC_UNKNOWN) {
                submit_gc_event(gc, end_monotime_ns, pid);
            }
            bpf_map_delete_elem(map, &pid);
        }
    }
}

#endif // __GC_H__