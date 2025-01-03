#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Extract the syscall opcode from the tracepoint arguments.
// Compiler for efficiency(optimization)_ will inline this function into the code. WIth this __attribute((noinline)) we dont allow
// that operation.
static __attribute((noinline)) int get_opcode(struct bpf_raw_tracepoint_args *ctx) {
    return ctx->args[1];
}

SEC("raw_tp/")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = get_opcode(ctx);
    bpf_printk("Syscall: %d", opcode);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
