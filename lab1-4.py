#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
import re
import argparse

# define BPF program
bpf_text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>
#include <linux/sched.h>
// for saving the timestamp and __data_len of each request

struct data_t {
    u64 rwflag;
    u64 sector;
    u64 len;
    char name[TASK_COMM_LEN];
    char disk_name[DISK_NAME_LEN];
};

BPF_PERF_OUTPUT(events);

void trace_rw(struct pt_regs *ctx, struct request *req){
    struct data_t data = {};

#ifdef REQ_WRITE                                                         
    data.rwflag = !!(req->cmd_flags & REQ_WRITE);                        
#elif defined(REQ_OP_SHIFT)                                              
    data.rwflag = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);  
#else                                                                    
    data.rwflag = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);    
#endif                                                                   

    data.len = req->__data_len;
    data.sector = req->__sector;
    
    bpf_probe_read_kernel(&data.disk_name, sizeof(data.disk_name), req->rq_disk->disk_name);
     
    events.perf_submit(ctx, &data, sizeof(data));
}

"""

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="blk_start_request", fn_name="trace_rw")

# header
print("%-20s %-5s %-7s %-20s %-7s" % ("Random/Sequential", "COMM", "DISK", "SECTOR", "BYTES"), end="")

rwflg = ""
breq = {"rwflag" : 0, "len" : 0, "sector" : 0}

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)

    ran_seq = 'Random'
    if (breq['rwflag']==0 and breq['len']==0 and breq['sector']==0)==0:
        n_sec = breq['sector'] + (breq['len']/512)
        if breq['rwflag']==event.rwflag:
            if n_sec == event.sector:
                ran_seq = 'Sequential'
            
     
    breq['rwflag']=event.rwflag
    breq['len']=event.len
    breq['sector']=event.sector
    
    if event.rwflag == 1:
        rwflg = "Write"
    else:
        rwflg = "Read"

    print("%-20s %-5s %-7s %-20s %-7s" % (ran_seq, rwflg, event.disk_name.decode('utf-8', 'replace'), event.sector, event.len))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
