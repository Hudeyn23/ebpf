import argparse
import os
import copy
import re

from bcc import BPF
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

int prctl(struct pt_regs *ctx,int option, unsigned long arg2, unsigned long arg3,
                 unsigned long arg4, unsigned long arg5)
{   
    if(filter_comm()==0) {
    return 0;
    }
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    bpf_send_signal(19);
    return 0;
}

"""
isCaught = False
pid = -1
def attach_debug(cpu, data, size):
    global pid
    global isCaught
    event = b["events"].event(data)
    pid = copy.copy(str(event.pid))
    isCaught = True



def attach_comm(comm,p):
    global bpf_text
    global b
    bpf_text = re.sub(r'\bCOMM_LENGTH\b', str(len(comm)), bpf_text)
    bpf_text = re.sub(r'\bCOMM\b', comm
                      , bpf_text)
    b = BPF(text=bpf_text);
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")
    prctl_fnname = b.get_syscall_fnname("prctl")
    b.attach_kretprobe(event=prctl_fnname, fn_name="prctl")
    b["events"].open_perf_buffer(attach_debug)
    while not isCaught:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
    if(p == None):
        os.system("gdb -p " + pid)
    else:
        os.system("gdb -p " + pid + " -x" + p)

    return pid


