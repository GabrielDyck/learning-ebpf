#!/usr/bin/python3  
from bcc import BPF
import ctypes as ct

program = r"""
BPF_PROG_ARRAY(syscall, 300);   // BCC provides a BPF_PROG_ARRAY macro for easily defining maps of type
                                // BPF_MAP_TYPE_PROG_ARRAY. I have called the map syscall and allowed for 300 entries.

// int hello(struct bpf_raw_tracepoint_args *ctx) { // the context is passed from the sys_enter syscall 
// we are going to replace hello function using a direct way of raw_trace_point attachment
// Further info in:: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracepoints
RAW_TRACEPOINT_PROBE(sys_enter) { 
    int opcode = ctx->args[1];  
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d", opcode); // If the  tailcall succeed, this is not reachable.
    return 0;
}

int hello_exec(void *ctx) {     // this function will be loaded into the syscall program array map,
                                // to be executed as a tail call when the opcode indicates its an execcve() syscall. 
                                // its just going to generate a line of trace to tell the user a new program is being executed.
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {  // this function will be loaded into the syscall program array map
    int opcode = ctx->args[1];
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

int ignore_opcode(void *ctx) { // another tail call program, but it's a detail to ignore some syscalls.
    return 0;
}
"""

b = BPF(text=program) # Compiles the program code
#Remove this function because we are using a direct way to attach sys_enter syscall to a RAW_TRACE_POINT
#b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello") # attach the hello func to the sys_enter raw tracepoint syscall.
                                                            # It gets it whenever any syuscall is made.

# Pay attention to BPF.RAW_TRACEPOINT and attach_raw_tracepoint. The use
ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)    # We attach these tail call functions file to the map and it returns function file descriptors
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)         # We attach these tail call functions file to the map and it returns function file descriptors
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)       # We attach these tail call functions file to the map and it returns function file descriptors

# We create a syscall map.
prog_array = b.get_table("syscall")
# The map doesnt have to be fully populated for every
# possible opcode; if there is no entry for a particular opcode, it simply means no tail call wil be executed.
# Also, it's perfectly fine to have multiple entries that point to the same eBPF program.
# In this case I want the hello_timer() tail call to be executed for any of a set of timer-related syscall.
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# Ignore some syscalls that come up a lot
prog_array[ct.c_int(0)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(1)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(7)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(13)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(14)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(21)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(22)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(25)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(29)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(56)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(57)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(63)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(64)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(66)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(72)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(73)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(79)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(98)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(101)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(115)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(131)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(134)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(135)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(139)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(172)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(233)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(271)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(280)] = ct.c_int(ignore_fn.fd)
prog_array[ct.c_int(291)] = ct.c_int(ignore_fn.fd)

b.trace_print()
