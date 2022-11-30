import argparse
import re

from bcc import BPF, printb
import os

parser = argparse.ArgumentParser()
parser.add_argument("-n", "--name", type=str, help="archive mode")
args = parser.parse_args()
bpf_text = """
#include <linux/sched.h> 
#include <linux/mm_types.h> 
#include <uapi/linux/bpf.h> 
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char cmdline[100];
};

BPF_PERF_OUTPUT(events);

static inline bool filter_cmdline(char* cmdline) {
    char comparand[COMM_LENGTH] = "COMM";
    for (int i = 0; i<COMM_LENGTH; ++i) {
        if (cmdline[i] != comparand[i]){
         return false;
        }
    }    
    return true;
}

int catch_cmdline(struct pt_regs* args)
{

    struct data_t data = {};
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *m = t->mm;
    unsigned long arg_start = m->arg_start;
    unsigned long arg_end = m->arg_end;
    bpf_probe_read_user_str(&data.cmdline,sizeof(data.cmdline),(void *) arg_start);
    if(filter_cmdline(data.cmdline)==0) {
        return 0;
    }
    data.pid = bpf_get_current_pid_tgid();
    bpf_send_signal(19);
    events.perf_submit((struct pt_regs *)args, &data, sizeof(data));
}


"""
name = args.name
bpf_text = re.sub(r'\bCOMM_LENGTH\b', str(len(name) - 1), bpf_text)
bpf_text = re.sub(r'\bCOMM\b', name
                  , bpf_text)
b = BPF(text=bpf_text)
b.attach_raw_tracepoint(tp="sys_enter",fn_name="catch_cmdline")


def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%s" % event.cmdline)
    b.detach_raw_tracepoint(tp="sys_enter")
    os.system('gdb -p ' + str(event.pid))


b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
