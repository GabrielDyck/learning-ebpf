# Chapter 4 - The bpf() System Call

In this chapter I'll walk you through the system calls invoked by these example
programs `hello-buffer-config.py` and `hello-ring-buffer-config.py`.

## Exercises

Example solution to using `bpftool` to update the `config` map:

```
bpftool map update name config key 0x2 0 0 0 value hex 48 65 6c 6c 6f 20 32 0 0 0 0 0
```

[BPF function](https://man7.org/linux/man-pages/man2/bpf.2.html)

## The bpf() System Call
```shell
sudo strace -e bpf  ./hello-buffer-config.py
```

1. Loading BTF Data: to make ebpf program portable across different kernel versions. It returns the BTF Data filedescriptor.
```text
   bpf(BPF_BTF_LOAD, {btf="\237\353\1\0\30\0\0\0\0\0\0\0\364\5\0\0\364\5\0\0#\v\0\0\1\0\0\0\0\0\0\10"..., btf_log_buf=NULL, btf_size=4399, btf_log_size=0, btf_log_level=0}, 128) = 3
```
2. Creating Maps: create the output and the configmap with their according type. It returns each map filedescriptor
```text
    bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_PERF_EVENT_ARRAY, key_size=4, value_size=4, max_entries=24, map_flags=0, inner_map_fd=0, map_name="output", map_ifindex=0, btf_fd=0, btf_key_type_id=0, btf_value_type_id=0, btf_vmlinux_value_type_id=0, map_extra=0}, 128) = 4
    bpf(BPF_MAP_CREATE, {map_type=BPF_MAP_TYPE_HASH, key_size=4, value_size=12, max_entries=10240, map_flags=0, inner_map_fd=0, map_name="config", map_ifindex=0, btf_fd=3, btf_key_type_id=1, btf_value_type_id=4, btf_vmlinux_value_type_id=0, map_extra=0}, 128) = 5
```

3. Loading a Program: load the ebpf program into the kernel
```text
    bpf(BPF_PROG_LOAD, {prog_type=BPF_PROG_TYPE_KPROBE, insn_cnt=44, insns=0x7f33990ffbf8, license="GPL", log_level=0, log_size=0, log_buf=NULL, kern_version=KERNEL_VERSION(5, 15, 167), prog_flags=0, prog_n
    ame="hello", prog_ifindex=0, expected_attach_type=BPF_CGROUP_INET_INGRESS, prog_btf_fd=3, func_info_rec_size=8, func_info=0x55aa78b4bf80, func_info_cnt=1, line_info_rec_size=16, line_info=0x55aa78e0c260, line_info_cnt=21, attach_btf_id=0, attach_prog_fd=0, fd_array=NULL}, 128) = 6
```
4. Modifying a Map from User Space
```text
    bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x7f338e5d1a10, value=0x7f33989d2a90, flags=BPF_ANY}, 128) = 0
    bpf(BPF_MAP_UPDATE_ELEM, {map_fd=5, key=0x7f338e5d1a10, value=0x7f33989d2a90, flags=BPF_ANY}, 128) = 0
    bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7f338e5d1a10, value=0x7f33989d2a90, flags=BPF_ANY}, 128) = 0
    bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7f338e5d1a10, value=0x7f33989d2a90, flags=BPF_ANY}, 128) = 0
    bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, key=0x7f338e5d1a10, value=0x7f33989d2a90, flags=BPF_ANY}, 128) = 0
```
   * View map's content using bpftool
      ```shell
        bpftool map dump name config    
      ```
5. BPF Program and Map References: The user space process that made the syscall owns this file descriptiorn; when the process exits, the file descriptor gets released, and the reference count to the program is decremented. When there are no refereces left to a BPF program, the kernel removes the program.
   An additional refernce is created when we pin a program into the filesystem.
``` bpftool prog load hello.bpf.o /sys/fs/bpf/hello```
This pinned files are created in a seudo-filesystem held in memory. This allows to maintain the bpf program loaded when bpftool exits.
The reference conunter also gets incremented when a BPF program is atttached to a hook that will trigger it. The behavior of these counts depends on the BPF program type.
eBPF maps also has reference conunters, and they get cleaned up hwen their reference coun drops to zero.
 Maps can also be pinned to the filesystem and the user space program can gain access to the map by knoiwiung the path to the map.
6. BPF Links: 
proveide a layer of abstraction bewtween an eBPF program and the event it's attached to. A BPF link itself can be pinned to the filesystem, which creates an additional reference to the program..