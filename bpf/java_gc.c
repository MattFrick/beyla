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

#include "utils.h"
#include "bpf_dbg.h"
#include "ringbuf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#if 0
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, func_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_GC SEC(".maps");
#endif

SEC("uprobe/mem__pool__gc__begin")
int uprobe_MemPoolGcBegin(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/MemPoolGcBegin === ");// TODO: Change back to _dbg
    return 0;
}

SEC("uprobe/mem__pool__gc__end")
int uprobe_MemPoolGcEnd(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/MemPoolGcEnd === "); // TODO: Change back to _dbg
    return 0;
}
