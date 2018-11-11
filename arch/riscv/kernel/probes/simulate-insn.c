// SPDX-License-Identifier: GPL-2.0+

#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <asm/insn.h>

#include "simulate-insn.h"

static void set_register(struct pt_regs *regs, unsigned int reg,
			 unsigned long value)
{
	// Don't write to sepc, in this context we assume this is x0
	if (reg)
		regs_set_register(regs, reg * sizeof(unsigned long), value);
}

static unsigned long get_register(struct pt_regs *regs, unsigned int reg)
{
	// Don't read from sepc, in this context we assume this is x0
	if (reg)
		return regs_get_register(regs, reg * sizeof(unsigned long));

	return 0;
}

static int16_t rv_i_insn_imm(u32 opcode)
{
	return sign_extend32(opcode >> 20, 11);
}

static int32_t rv_u_insn_imm(u32 opcode)
{
	return opcode & 0xFFFFF000;
}

static u16 rv_ins_rs1(u32 opcode)
{
	return (opcode >> 15) & 0x001F;
}

static u16 rv_ins_rs2(u32 opcode)
{
	return (opcode >> 20) & 0x001F;
}

static u16 rv_ins_rd(u32 opcode)
{
	return (opcode >> 7) & 0x001F;
}

static u8 rv_ins_func3(u32 opcode)
{
	return (opcode >> 12) & 0x0007;
}

static u8 rv_ins_func7(u32 opcode)
{
	return opcode >> 25;
}

static int32_t rv_sb_insn_imm(u32 opcode)
{
	return sign_extend32(((opcode & 0x80000000) >> 19) | ((opcode & 0x7E000000) >> 20) |
		((opcode & 0xF00) >> 7) | ((opcode & 0x80) << 4), 12);
}

void rv_simulate_i_ins(u32 opcode, long addr, struct pt_regs *regs)
{
	int16_t imm;
	unsigned long src;
	unsigned long dest;
	u8 dest_reg = rv_ins_rd(opcode);
	if (dest_reg == RV_REG_ZERO)
		return;

	imm = rv_i_insn_imm(opcode);
	src = get_register(regs, rv_ins_rs1(opcode));
	switch (rv_ins_func3(opcode))
	{
		case 0x0:
			// ADDI
			dest = src + imm;
			break;
		case 0x1:
			// SLLI
			dest = src << (imm & 0x1F);
			break;
		case 0x2:
			// SLTI
			dest = (long)src < imm ? 1 : 0;
			break;
		case 0x3:
			// SLTIU
			dest = src < (unsigned long)imm ? 1 : 0;
			break;
		case 0x4:
			// XORI
			dest = src ^ (unsigned long)imm;
			break;
		case 0x5:
			// SRLI / SRAI
			if ((imm & 0x400) == 0x400)
				dest = (long)src >> (imm & 0x1F);
			else
				dest = src >> imm;
			break;
		case 0x6:
			// ORI
			dest = src | (unsigned long)imm;
			break;
		case 0x7:
			// ANDI
			dest = src & (unsigned long)imm;
			break;
	}
//	pr_warning("src: %lx, imm %d %lx dest: %lx\n", src, imm, (unsigned long)imm, dest);
	set_register(regs, rv_ins_rd(opcode), dest);
}
NOKPROBE_SYMBOL(rv_simulate_i_ins);

void rv_simulate_r_ins(u32 opcode, long addr, struct pt_regs *regs)
{
	unsigned long rs1 = get_register(regs, rv_ins_rs1(opcode));
	unsigned long rs2 = get_register(regs, rv_ins_rs2(opcode));
	unsigned long func7 = rv_ins_func7(opcode);
	unsigned long dest;
	switch (rv_ins_func3(opcode))
	{
		case 0:
			// ADD / SUB
			if (func7 == 0x20)
				dest = rs1 - rs2;
			else
				dest = rs1 + rs2;
			break;
		case 1:
			// SLL
			dest = rs1 << (rs2 & 0x1F);
			break;
		case 2:
			// SLT
			dest = (unsigned long)rs1 < (unsigned long)rs2 ? 1 : 0;
			break;
		case 3:
			// SLTU
			dest = rs1 < rs2 ? 1 : 0;
			break;
		case 4:
			// XOR
			dest = rs1 ^ rs2;
			break;
		case 5:
			// SRL / SRA
			if (func7 == 0x20)
				dest = rs1 >> (rs2 & 0x1F);
			else
				dest = (long)rs1 >> (rs2 & 0x1F);
			break;
		case 6:
			// OR
			dest = rs1 | rs2;
			break;
		case 7:
			// AND
			dest = rs1 & rs2;
			break;
	}
//	pr_warning("rs1: %lx, rs2: %lx dest: %lx\n", rs1, rs2, dest);
	set_register(regs, rv_ins_rd(opcode), dest);
}
NOKPROBE_SYMBOL(rv_simulate_r_ins);

void rv_simulate_rb_ins(u32 opcode, long addr, struct pt_regs *regs)
{
	unsigned long rs1 = get_register(regs, rv_ins_rs1(opcode));
	unsigned long rs2 = get_register(regs, rv_ins_rs2(opcode));
	bool taken = 0;
	switch (rv_ins_func3(opcode))
	{
		case 0:
			// BEQ
			taken = rs1 == rs2;
			break;
		case 1:
			// BNE
			taken = rs1 != rs2;
			break;
		case 4:
			// BLT
			taken = (long)rs1 < (long)rs2;
			break;
		case 5:
			// BGE
			taken = (long)rs1 >= (long)rs2;
			break;
		case 6:
			// BLTU
			taken = rs1 < rs2;
			break;
		case 7:
			// BGEU
			taken = rs1 >= rs2;
			break;
	}
	//pr_warning("rs1: %lx, rs2: %lx taken: %d offset: %d %x\n", rs1, rs2, taken, rv_sb_insn_imm(opcode), (unsigned int)rv_sb_insn_imm(opcode));
	if (taken) {
		regs->sepc += rv_sb_insn_imm(opcode);
	}

}
NOKPROBE_SYMBOL(rv_simulate_rb_ins);

void rv_simulate_jal(u32 opcode, long addr, struct pt_regs *regs)
{
	int32_t imm = sign_extend32(
			((opcode & 0x80000000) >> 11) |
			((opcode & 0x7FE00000) >> 20) |
			((opcode & 0x100000) >> 9) |
			(opcode & 0xFF000)
			, 20);
	set_register(regs, rv_ins_rd(opcode), regs->sepc + 4);
	regs->sepc += imm;
}
NOKPROBE_SYMBOL(rv_simulate_jal);

void rv_simulate_jalr(u32 opcode, long addr, struct pt_regs *regs)
{
	int32_t imm = rv_i_insn_imm(opcode);
	set_register(regs, rv_ins_rd(opcode), regs->sepc + 4);
	regs->sepc = get_register(regs, rv_ins_rs1(opcode)) + imm;
	regs->sepc &= 0xFFFFFFFE;
}
NOKPROBE_SYMBOL(rv_simulate_jalr);

void rv_simulate_lui(u32 opcode, long addr, struct pt_regs *regs)
{
	int32_t imm = rv_u_insn_imm(opcode);
	set_register(regs, rv_ins_rd(opcode), imm);
}
NOKPROBE_SYMBOL(rv_simulate_lui);

void rv_simulate_auipc(u32 opcode, long addr, struct pt_regs *regs)
{
	int32_t imm = rv_u_insn_imm(opcode);
	set_register(regs, rv_ins_rd(opcode), regs->sepc + imm);
}
NOKPROBE_SYMBOL(rv_simulate_auipc);
