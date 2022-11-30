#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
import argparse
import os
import re

# run in project examples directory with:
# sudo ./hello_world.py"
# see trace_fields.py for a longer example

from bcc import BPF, ArgString

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--name", type=str, help="archive mode")
args = parser.parse_args()
bpf_text = """
#include <linux/sched.h> 
#include <uapi/linux/bpf.h> 

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

static inline bool filter_comm() {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    char comparand[COMM_LENGTH] = "COMM";
    for (int i = 0; i < COMM_LENGTH; ++i)
        if (comm[i] != comparand[i])
        return false;
    return true;
}

int do_ret_sys_execve(struct pt_regs *ctx)
{   
    if(filter_comm()==0) {
    return 0;
    }
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("%d",data.pid);    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    bpf_send_signal(19);
    return 0;
}


"""
name = args.name
bpf_text = re.sub(r'\bCOMM_LENGTH\b', str(len(name)-1), bpf_text)
bpf_text = re.sub(r'\bCOMM\b', name
                  , bpf_text)
b = BPF(text=bpf_text);
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")


def attach_debug(cpu, data, size):
    event = b["events"].event(data)
    b.detach_kretprobe(event=execve_fnname)
    os.system('gdb -p ' + str(event.pid))


b["events"].open_perf_buffer(attach_debug)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
