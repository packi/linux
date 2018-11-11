/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _RISCV_KERNEL_KPROBES_SIMULATE_INSN_H
#define _RISCV_KERNEL_KPROBES_SIMULATE_INSN_H

void rv_simulate_i_ins(u32 opcode, long addr, struct pt_regs *regs);
void rv_simulate_r_ins(u32 opcode, long addr, struct pt_regs *regs);
void rv_simulate_rb_ins(u32 opcode, long addr, struct pt_regs *regs);
void rv_simulate_jal(u32 opcode, long addr, struct pt_regs *regs);
void rv_simulate_jalr(u32 opcode, long addr, struct pt_regs *regs);
void rv_simulate_lui(u32 opcode, long addr, struct pt_regs *regs);
void rv_simulate_auipc(u32 opcode, long addr, struct pt_regs *regs);

#endif /* _RISCV_KERNEL_KPROBES_SIMULATE_INSN_H */
