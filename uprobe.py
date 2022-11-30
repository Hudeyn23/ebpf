
from __future__ import print_function
from bcc import BPF, printb

b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h> 
#include <uapi/linux/bpf.h> 
#include <linux/mm_types.h> 
struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char argv[100];
};
BPF_PERF_OUTPUT(events);
int catch_setproctitle(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *m = t->mm;
    unsigned long arg_start = m->arg_start;
    unsigned long arg_end = m->arg_end;
    bpf_probe_read_user_str(&data.argv,sizeof(data.argv),(void *) arg_start);
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};

""")
libpath = b.find_library('/usr/sbin/nginx')
b.attach_uretprobe(name=libpath, sym="ngx_setproctitle", fn_name="catch_setproctitle")
def print_event(cpu, data, size):
    event = b["events"].event(data)
    printb(b"%d %-16s %-16s" % (event.pid , event.comm,event.argv))


b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()