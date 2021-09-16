#!/usr/bin/python

from bcc import BPF
from time import strftime

# linux stats

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

enum event_type {
    EVENT_ARG,
    EVENT_RET,    
};

struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    enum event_type type;
};

BPF_HASH(birth, u32, u64);
BPF_PERF_OUTPUT(events);

int schedule_out(struct pt_regs *ctx){
    bpf_trace_printk("start");
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u64 ts = bpf_ktime_get_ns();
    birth.update(&pid, &ts);
    
    data.type = EVENT_ARG;
    data.pid = pid;

    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0; 
}

int do_ret_schedule_out(struct pt_regs *ctx){
   
    struct data_t data = {}; 
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    u64 *tsp, delta;
    tsp = birth.lookup(&pid);
    if(tsp == 0){
        return 0;    
    }

    delta = (bpf_ktime_get_ns() - *tsp);
    birth.delete(&pid);
    if(bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0){
        data.pid = pid;
        data.delta = delta;
    }

    bpf_trace_printk("pid : %d delta : %d comm : %s\\n", pid, delta, data.comm);

    data.type = EVENT_RET;
    events.perf_submit(ctx, &data, sizeof(data)); 
    return 0; 
}

"""

class EventType(object):
    EVENT_ARG = 0
    EVENT_RET = 1

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    if event.type==EventType.EVENT_RET:
        print("%-6d %-16s %d" % (event.pid, event.comm, event.delta))
        


# initialize BPF
b = BPF(text=bpf_text)
b["events"].open_perf_buffer(print_event)
b.attach_kprobe(event="io_schedule", fn_name="schedule_out")
b.attach_kretprobe(event="io_schedule", fn_name="do_ret_schedule_out")


# header
print("%-6s %-16s %-8s" % ("PID", "COMM", "TIME"))


while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
