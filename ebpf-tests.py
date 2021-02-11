#!/usr/bin/python3.8

from bcc import BPF

bpf_text = """

//BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    
	//currsock.update(&pid, &sk);
    
    return 0;
}

/*
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    //currsock.delete(&pid);

    return 0;
}
*/
"""

b = BPF(text=bpf_text)

#def inet_ntoa(addr):
#	dq = b''
#	for i in range(0, 4):
#		dq = dq + str(addr & 0xff).encode()
#		if i != 3:
#			dq = dq + b'.'
#		addr = addr >> 8
#	return dq

while 1:
	try:
		(task, pid, cpu, flags, ts, msg) = b.trace_fields()
	except ValueError:
		continue
	except KeyboardInterrupt:
		exit()

