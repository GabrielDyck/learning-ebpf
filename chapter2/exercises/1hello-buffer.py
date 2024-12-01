#!/usr/bin/python3  
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output); // create a map(output) that will be used to pass messages from the kernel to user space.
 
struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[12];
};
 
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
 
   data.pid = bpf_get_current_pid_tgid() >> 32;// bpf helper function to get the pid of process that tirggered this ebpf 
                                                // program to run. PID is in the first 32 bits.
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; // bpf helper function to get the user id who 
                                                      // has executed the program.
   
   bpf_get_current_comm(&data.command, sizeof(data.command)); // bpf helper programm to get the name of the program which
                                                              // has triggered the epgb program.
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); // copies the message to tdata structure
 
   output.perf_submit(ctx, &data, sizeof(data)); // this put the data in to the BPF_PERF_OUTPUT map
 
   return 0;
}
"""

b = BPF(text=program)  # compile the program
syscall = b.get_syscall_fnname("execve") # get the syscall name
b.attach_kprobe(event=syscall, fn_name="hello") # attach the program to the syscall
 
def print_event(cpu, data, size): # ebpf callback function
   data = b["output"].event(data) # gets data coming from the ebpf triggered programs.
   msg=f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}"
   if data.pid % 2 == 0:
      print(f"Even {msg}")  # prints the data
   else:
      print(f"Odd  {msg}") # prints the data
 
b["output"].open_perf_buffer(print_event) #  opens the perf ring buffer. Takes print_event as an argument to define
                                          # that this is the callback function to be used whenever there is data to read form the buffer.
while True:
   b.perf_buffer_poll() # Polling the perf ring buffer indefinitely. If there is an data available print_event will get called.
