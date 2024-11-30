# Chapter 2

You'll need [BCC](https://github.com/iovisor/bcc) installed for the examples in this directory.

* `hello.py` - simple example that emits trace messages triggered by a kprobe
* `hello-map.py` - introduce the concept of a BPF map
* `hello-buffer.py` - use a ring buffer to convey information to user space
* `hello-tail.py` - simple demo of eBPF tail calls


Learned Facts:
* Linux has 300 syscalls at the time when I'm reading this.
* BPF Stack is limited up to 512 bytes.
* BCC framework does not suppot subprograms. If you like to use them, you should use inlined functions or use tail call.
* We can call BPF helper functions to get data from the execution context. This is truly powerful.



