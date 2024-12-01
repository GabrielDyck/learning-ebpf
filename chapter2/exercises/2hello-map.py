#!/usr/bin/python3  
from bcc import BPF
from time import sleep

#  BPF_HASH is a BCC macro that defines a hash table map.
#  bpf_get_current_uid_gid() is a helper function used to obtain the userID that is runnning the process
#       that triggered this kprove event. The user ID is held in the lowest 32bits of the 64-bit value
#       that gets returned( the top 32-bits hold the group ID, but that part is masked out.

program = r"""
BPF_HASH(counter_table);

int hello(void *ctx) {
   u64 uid;
   u64 counter = 0;
   u64 *p;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&uid, &counter);
   return 0;
}
"""


b = BPF(text=program) # Compiles the 'C'(syntax sugar).
syscall = b.get_syscall_fnname("execve") # Get the syscall Identifier
b.attach_kprobe(event=syscall, fn_name="hello") # Attach the hello function to the syscall.

# attach the BPF function to others syscalls also
openat = b.get_syscall_fnname("openat") # Get the syscall Identifier
write = b.get_syscall_fnname("write") # Get the syscall Identifier
b.attach_kprobe(event=openat, fn_name="hello")
b.attach_kprobe(event=write, fn_name="hello")



# Attach to a tracepoint that gets hit for all syscalls 
# b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(2)
    s = ""
    # Pay attention that, we are using counter_table hashmap from the bpf program
    # BPF program is executed in kernel space an this piece of code is running in the user namespace.
    # This is how data is shared.
    for k,v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
