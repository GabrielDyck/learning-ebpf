# Chapter 3 - Anatomy of an eBPF Program

Make sure you have installed libbpf and its header files as described in the
main [README file](../README.md).

You should then be able to build the example code as an object file by running
`make` in this directory. See Chapter 3 of the book for instructions on what to
do with this object file.



## BPF Architecture Details:

* https://origin.kernel.org/doc/html/latest/bpf/
* https://docs.cilium.io/en/stable/reference-guides/bpf/index.html


## XDP
* https://www.datadoghq.com/blog/xdp-intro/
XDP (eXpress Data Path) is an eBPF-based high-performance data path used to send and receive network packets at high rates

## eBPF OPCodes
* https://oreil.ly/nLbLp



## Steps to use eBPF programs without bcc framework

1. Compile C Program to C Object File(tool: clang)
2. Load the program into the Kernel(tool: bpftool(requires sudo), and also programmatically)
    * Ex: bpftool prog load hello.bpf.o **/sys/fs/bpf/hello**
    * Inspect the program:
      * bpftool list
      * bpftool prog show id 540
      * bpftool prog show name hello
      * bpftool prog show tag d34b...
      * bpftool prog show pinned /sys/fs/ebpf/hello
      * Obs: name , tag can be shared. But ID, pinned path are unique.
    * Inspect the translated Code:
      * bpftool prog dump xlated name hello
    * Inspect  Jit Compiled Code:
      * bpftool prog dump jited name hello
    * Inspect maps
      * bpftool map list
      * bpftool map dump name hello.bss
      * bpftool map dump id 165
3. Attach the eBPF program to an event
   * bpftool net attach xdp id 540 dev eth0
   * How to watch network attached eBPF programs using bpftool
     * bpftool net list
     * we can also use `ip link` 
4. Watch the printed events 
   * cat /sys/kernel/debug//tracing/tracepipe
   * bpftool prog tracelog
5. Detaching a program (although it is still loaded in the kernel)
   * bpftool net detach xdp dev eth0
   * bpftool net list( to see if its detached)
   * bpftool prog show name hello(to see that is still loaded in the kernel)
6. Unloading the program(from the Kernel)
   * rm /sys/fs/bpf/hello
   * bpftol prog show name hello( to see if is loaded. No output  because is no longer loaded in the kernel)