#!/usr/bin/python3
from bcc import BPF

# Runs in the kernel. Written in C code
program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

#Runs in the user namespace
b = BPF(text=program) # This compile the C code before can be executed.
syscall = b.get_syscall_fnname("execve")  # We attach the eBPF program to this event.
b.attach_kprobe(event=syscall, fn_name="hello") # We attach the hello function to the syscall

b.trace_print()
