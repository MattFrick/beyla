#ifndef __GC_H__
#define __GC_H__

typedef enum gc_action_t {
    GC_UNKNOWN,
    GC_MARK,
    GC_SWEEP,
    GC_STW_MARK_TERM,
    GC_STW_SWEEP_TERM,
} gc_action;

typedef struct gc_event_t {
    u64       gc_start_monotime_us;
    gc_action action;
} gc_event;
#endif // __GC_H__