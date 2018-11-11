/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Based on arch/arm64/include/asm/probes.h
 *
 * Copyright (C) 2013 Linaro Limited
 */
#ifndef _RISCV_PROBES_H
#define _RISCV_PROBES_H

typedef u32 probe_opcode_t;
typedef void (probes_handler_t) (u32 opcode, long addr, struct pt_regs *);

/* architecture specific copy of original instruction */
struct arch_specific_insn {
	probes_handler_t *handler;
	probe_opcode_t original_opcode;
	/* restore address after simulation */
	unsigned long restore;
	bool jump_insn;
};
#ifdef CONFIG_KPROBES
typedef u32 kprobe_opcode_t;
#endif

#endif /* _RISCV_PROBES_H */
