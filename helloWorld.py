from bcc import BPF 

 

prog = """ 

int hello(void *ctx){ 

bpf_trace_printk("Hello world\\n"); 

return 0; 

} 

""" 

 

b=BPF(text=prog) 

b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello") 



 

print("Tracing new processes... Press Ctrl-C to end") 

print("%-18s %-30s %-12s %s" % ("TIME(s)", "COMMAND", "PROCESS ID", "MESSAGE")) 

 

while 1: 

    try: 

        (task, pid, cpu, flags, ts, msg) = b.trace_fields() 

        print("%-18.9f %-30s, %-12d %s" % (ts,task,pid,msg)) 

    except ValueError: 

        continue 

    except KeyboardInterrupt: 

        break
