import ctypes
import os
import re

from bcc import BPF

bpf_text = """
#include <linux/sched.h> 
#include <linux/mm_types.h> 
#include <uapi/linux/bpf.h> 
#include <uapi/linux/limits.h>
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char cmdline[400];
};

BPF_PERF_OUTPUT(events);

static inline int filter_comm() {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    char comparand[] = "COMM";
    for (int i = 0; i < COMM_LENGTH; ++i)
        if (comm[i] != comparand[i])
        return 0;
    return 1;
}

static int filter_cmdline(char cmdline[400]) {
    char array[] = "CMDLINE";
    int firstIdx = 0;
    for (int i = 0; i<400; ++i) {
    int k = i;
    for (int j = 0;j<CMDLINE_LENGTH;j++){
        if(k>=400){
        return 0;
        }
        if (cmdline[k] != array[j]){
          break;
        }
        if(j == (CMDLINE_LENGTH-1)){
            return 1;
        }
        k++;

    }
    }    
    return 0;
}




int catch_cmdline(struct pt_regs* args)
{
    if(filter_comm()==0) {
    return 0;
    }
    struct data_t data;
    memset(&data, 0, sizeof(data));
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct mm_struct *m = t->mm;
    long arg_start = m->arg_start;
    long arg_end = m->arg_end;
    long size = 100;
    long totalRead = 0;
    for(int i = 1;i<5;i++){
    if(size<=0){
        return 0;
    } 
    long read = bpf_probe_read_user_str((void *) (&data.cmdline[0]+totalRead) ,size,(void *) arg_start + totalRead);
    if(read<0){
    return 0;
    }
    totalRead = totalRead + read;
    if(arg_start + totalRead >= arg_end){
        break;
    }
    data.cmdline[totalRead - 1] = ' ';
    size = size - read;
    }
    if(filter_cmdline(&data.cmdline[0])==0) {
        return 0;
    } 
    bpf_send_signal(19);
    data.pid = bpf_get_current_pid_tgid();
    events.perf_submit((struct pt_regs *)args, &data, sizeof(data));
    return 0;
}


"""

isCaught = False
pid = -1


def attach_debug(cpu, data, size):
    global pid
    global isCaught
    event = b["events"].event(data)
    print(event.cmdline)
    isCaught = True
    pid = str(event.pid)


def attach_cmdline(comm_name, cmdline,p):
    global bpf_text
    global b

    bpf_text = re.sub(r'\bCMDLINE_LENGTH\b', str(len(cmdline)), bpf_text)
    bpf_text = re.sub(r'\bCMDLINE\b', cmdline
                      , bpf_text)
    bpf_text = re.sub(r'\bCOMM_LENGTH\b', str(len(comm_name)), bpf_text)
    bpf_text = re.sub(r'\bCOMM\b', comm_name
                      , bpf_text)
    b = BPF(text=bpf_text)
    b.attach_raw_tracepoint(tp="sys_exit", fn_name="catch_cmdline")

    b["events"].open_perf_buffer(attach_debug)
    while not isCaught:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()
    b.cleanup()
    if (p == None):
        os.system("gdb -p " + pid)
    else:
        os.system("gdb -p " + pid + " -x " + p)
