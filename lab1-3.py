#!/usr/bin/python

from bcc import BPF
from time import strftime
import os
import subprocess
# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    long cnt;
    u64 delta;
    u64 RW;
    char type;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
};

BPF_HASH(read_cnt, char *, long);
BPF_HASH(write_cnt, char *);

BPF_PERF_OUTPUT(events);

void read_monitor(struct pt_regs *ctx, struct file* file){
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.RW = 0;

    u64 type = file->f_inode->i_mode;

    type = type >> 12;
    type = type << 12;
    switch(type){
        case S_IFREG:
            data.type = '-';
            break;
        case S_IFDIR:
            data.type = 'd';
            break;
        case S_IFCHR:
            data.type = 'c';
            break;
        case S_IFBLK:
            data.type = 'b';
            break;
        case S_IFLNK:
            data.type = 'l';
            break;
        case S_IFIFO:
            data.type = 'p';
            break;
        case S_IFSOCK:
            data.type = 's';
            break;
        default:
            data.type = '?';
            break;
    }

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    u64 cnt;
    long* ret;
    ret = read_cnt.lookup(&data.comm);

    if(ret==NULL){
        cnt = 1;
        read_cnt.update(&data.comm, &cnt);
    }
    else{
        cnt = *ret+1;
        read_cnt.update(&data.comm, &cnt);
    }
    data.cnt = cnt;
  
    events.perf_submit(ctx, &data, sizeof(data));
    
}

void write_monitor(struct pt_regs *ctx, struct file* file){
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.RW = 1;

    u64 type = file->f_inode->i_mode;

    type = type >> 12;
    type = type << 12;
    switch(type){
        case S_IFREG:
            data.type = '-';
            break;
        case S_IFDIR:
            data.type = 'd';
            break;
        case S_IFCHR:
            data.type = 'c';
            break;
        case S_IFBLK:
            data.type = 'b';
            break;
        case S_IFLNK:
            data.type = 'l';
            break;
        case S_IFIFO:
            data.type = 'p';
            break;
        case S_IFSOCK:
            data.type = 's';
            break;
        default:
            data.type = '?';
            break;
    }
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    u64 cnt;
    long* ret;
    ret = read_cnt.lookup(&data.comm);

    if(ret==NULL){
        cnt = 1;
        read_cnt.update(&data.comm, &cnt);
    }
    else{
        cnt = *ret+1;
        read_cnt.update(&data.comm, &cnt);
    }
    data.cnt = cnt;
  
    events.perf_submit(ctx, &data, sizeof(data));
}

"""

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
#    file_type = subprocess.check_output(['file', event.comm])
#    file_type = file_type.split(':')[1]
   # print(file_type)
    if event.RW==0 and event.cnt%10==0:
        print("%-10s %-6d %-20s %-30s %ld" % ("Read", event.pid, event.comm, event.type, event.cnt));
    elif event.RW==1 and event.cnt%10==0:
        print("%-10s %-6d %-20s %-30s %ld" % ("Write", event.pid, event.comm, event.type, event.cnt));


# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="vfs_read", fn_name="read_monitor")
b.attach_kprobe(event="vfs_readv", fn_name="read_monitor")
b.attach_kprobe(event="vfs_write", fn_name="write_monitor")
b.attach_kprobe(event="vfs_writev", fn_name="write_monitor")
print("%-10s %-6s %-20s %-30s %s" % ("Read/Write", "PID", "COMM", "FILE TYPE", "COUNT"))


b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
