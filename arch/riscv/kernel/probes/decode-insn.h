/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _RISCV_KERNEL_KPROBES_DECODE_INSN_H
#define _RISCV_KERNEL_KPROBES_DECODE_INSN_H

#include <asm/sections.h>
#include <asm/kprobes.h>

enum probe_insn {
	INSN_REJECTED,
	INSN_GOOD_NO_SLOT,
};

/*
 * Compressed instruction format:
 * xxxxxxxxxxxxxxaa where aa != 11
 */
#define is_compressed_insn(insn) ((insn & 0x3) != 0x3)

#ifdef CONFIG_KPROBES
enum probe_insn
riscv_probe_decode_insn(struct kprobe *p);
#endif
#endif /* _RISCV_KERNEL_KPROBES_DECODE_INSN_H */
