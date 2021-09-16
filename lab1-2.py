#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import strftime
import argparse

# linux stats
loadavg = "/proc/loadavg"

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/oom.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/path.h>

struct data_t {
    long fault_cnt;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
};

BPF_HASH(fault_cnt, char*, long);
BPF_PERF_OUTPUT(events);

int invoke_page_fault(struct pt_regs *ctx){
    struct data_t data = {};
    
    struct task_struct *task;
    long cnt;
    long *ret;
    
    task = (struct task_struct *)bpf_get_current_task();
   
    const char * filename = task->fs->pwd.dentry->d_name.name;
    
    if(bpf_get_current_comm(&data.comm, sizeof(data.comm))==0){
        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), (void *)filename);    
    } 
    
    ret = fault_cnt.lookup(&data.fname);

    if(ret==NULL){
        cnt = 1;
        data.fault_cnt = 1;
        fault_cnt.update(&data.fname, &cnt);
    }
    else{
        
        cnt = *ret+1;
        fault_cnt.update(&data.fname, &cnt);
        data.fault_cnt = cnt;
        
    }

    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0; 
}

"""

#header

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-32s %ld" % (event.fname, event.fault_cnt));

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="handle_mm_fault", fn_name="invoke_page_fault")
print("%-32s %s" % ("FILE", "PAGE_FAULT_COUNT"));

b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
