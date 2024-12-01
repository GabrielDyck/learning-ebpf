#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int counter = 0;

SEC("xdp")  // The macro SEC() defines a section called xdp that you'll be able to see in the compiled object file.
            // But for now you can simply think of it as defining that it's express data path(XDP) type of ebpf program.
int hello(struct xdp_md *ctx) {
    bpf_printk("Hello World %d", counter); // bpf_trace_printk() is the BCC version of this function. In summary, it's the same func.
    counter++; 
    return XDP_PASS;
}

// We net to define the license string, this is a crucial requrement foir eBPF programs.
char LICENSE[] SEC("license") = "Dual BSD/GPL";
