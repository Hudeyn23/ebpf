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
    char filename[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

static inline bool filter_filename(char *filename) {
    char comparand[COMM_LENGTH] = "COMM";
    for (int i = 0; i < COMM_LENGTH; ++i) {
        if (filename[i] != comparand[i])
        return false;
    }
    return true;
}

int syscall__execve(struct pt_regs *ctx,
    const char __user *filename,
    const char __user *const __user *__argv,
    const char __user *const __user *__envp)
{
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_probe_read_user_str(&data.filename,sizeof(data.filename),(void *) filename);
    if(filter_filename(data.filename) == 0){
        return 0;
    }
    events.perf_submit((struct pt_regs *)ctx, &data, sizeof(data));
    bpf_send_signal(19);
}


"""

name = args.name
bpf_text = re.sub(r'\bCOMM_LENGTH\b', str(len(name) - 1), bpf_text)
bpf_text = re.sub(r'\bCOMM\b', name
                  , bpf_text)
b = BPF(text=bpf_text);
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")


def attach_debug(cpu, data, size):
    event = b["events"].event(data)
    os.system('gdb -p ' + str(event.pid))


b["events"].open_perf_buffer(attach_debug)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
