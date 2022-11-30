# see trace_fields.py for a longer example
import argparse
import re

from bcc import BPF, printb
import os

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

static inline bool filter_comm() {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    char comparand[COMM_LENGTH] = "COMM";
    for (int i = 0; i < COMM_LENGTH; ++i)
        if (comm[i] != comparand[i])
        return false;
    return true;
}

BPF_PERF_OUTPUT(events);

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
name = args.name
bpf_text = re.sub(r'\bCOMM_LENGTH\b', str(len(name)-1), bpf_text)
bpf_text = re.sub(r'\bCOMM\b', name
                  , bpf_text)
b = BPF(text=bpf_text);
execve_fnname = b.get_syscall_fnname("prctl")

b.attach_kretprobe(event=execve_fnname, fn_name="prctl")
def print_event(cpu, data, size):
    event = b["events"].event(data)
    os.system('gdb -p ' + str(event.pid))


b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
