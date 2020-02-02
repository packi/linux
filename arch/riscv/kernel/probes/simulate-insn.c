// SPDX-License-Identifier: GPL-2.0+

#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <asm/insn.h>

#include "simulate-insn.h"

static void set_register(struct pt_regs *regs, unsigned int reg,
			 unsigned long value)
{
	// Don't write to epc, in this context we assume this is x0
	if (reg)
		regs_set_register(regs, reg * sizeof(unsigned long), value);
}

static unsigned long get_register(struct pt_regs *regs, unsigned int reg)
{
	// Don't read from epc, in this context we assume this is x0
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
		regs->epc += rv_sb_insn_imm(opcode);
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
	set_register(regs, rv_ins_rd(opcode), regs->epc + 4);
	regs->epc += imm;
}
NOKPROBE_SYMBOL(rv_simulate_jal);

void rv_simulate_jalr(u32 opcode, long addr, struct pt_regs *regs)
{
	int32_t imm = rv_i_insn_imm(opcode);
	set_register(regs, rv_ins_rd(opcode), regs->epc + 4);
	regs->epc = get_register(regs, rv_ins_rs1(opcode)) + imm;
	regs->epc &= 0xFFFFFFFE;
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
	set_register(regs, rv_ins_rd(opcode), regs->epc + imm);
}
NOKPROBE_SYMBOL(rv_simulate_auipc);

static __init int rv_simulate_i_ins_self_tests(void)
{
	struct pt_regs regs;
	u32 opcode;
	memset(&regs, '\0', sizeof(regs));

	pr_info(" Simulating I instructions...\n");

	pr_debug("ADDI\n");
        opcode = rv_addi(RV_REG_SP, RV_REG_SP, 0x0);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0)
		pr_warn("Expected sp to be 0: %lx\n", regs.sp);

        opcode = rv_addi(RV_REG_SP, RV_REG_SP, 0x1);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 1)
		pr_warn("Expected sp to be 1: %lx\n", regs.sp);

        opcode = rv_addi(RV_REG_SP, RV_REG_SP, 0xFFF);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0)
		pr_warn("Expected sp to be 0: %lx\n", regs.sp);

	// SLLI
	pr_debug("SLLI\n");
	regs.t0 = 1;
	opcode = rv_slli(RV_REG_SP, RV_REG_T0, 0x1);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0x2)
		pr_warn("Expected sp to be 2: %lx\n", regs.sp);
	if (regs.t0 != 0x1)
		pr_warn("t0 should be unchanged: %lx\n", regs.t0);

	opcode = rv_slli(RV_REG_SP, RV_REG_T0, 0x2);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0x4)
		pr_warn("Expected sp to be 4: %lx\n", regs.sp);

	opcode = rv_slli(RV_REG_SP, RV_REG_T0, 0x10);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0x10000)
		pr_warn("Expected sp to be 0x10000: %lx\n", regs.sp);

	opcode = rv_slli(RV_REG_SP, RV_REG_ZERO, 0x10);
	if (regs.sepc != 0)
		pr_warn("sepc shouln't be touched\n");

	pr_debug("SRLI\n");
	opcode = rv_srli(RV_REG_T0, RV_REG_SP, 0x10);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t0);

	regs.t3 = 0x8000000000000000;
	opcode = rv_srli(RV_REG_T0, RV_REG_T3, 0x02);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0x2000000000000000)
		pr_warn("Expected t0 to be 0x2000000000000000: %lx\n", regs.t0);

	pr_debug("SRAI\n");
	opcode = rv_srai(RV_REG_T0, RV_REG_T3, 0x03);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xF000000000000000)
		pr_warn("Expected t0 to be 0xF000000000000000: %lx\n", regs.t0);

	pr_debug("SLTI\n");
	regs.sp = 0x1;
	opcode = rv_i_insn(0x2, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	opcode = rv_i_insn(0x1, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-1;
	opcode = rv_i_insn(0x0, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	opcode = rv_i_insn(0xFFF, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-2;
	opcode = rv_i_insn(0xFFF, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	pr_debug("SLTIU\n");
	regs.sp = 0x1;
	opcode = rv_i_insn(0x2, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	opcode = rv_i_insn(0x1, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-1;
	opcode = rv_i_insn(0x0, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	opcode = rv_i_insn(0xFFF, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-2;
	opcode = rv_i_insn(0xFFF, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	pr_debug("XORI\n");
	regs.t1 = 0xAAA;
	opcode = rv_xori(RV_REG_T0, RV_REG_T1, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFFF)
		pr_warn("Expected t0 to be 0xFFF: %lx\n", regs.t0);

	opcode = rv_xori(RV_REG_T1, RV_REG_T0, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0xAAA)
		pr_warn("Expected t0 to be 0xAAA: %lx\n", regs.t1);

	opcode = rv_xori(RV_REG_T0, RV_REG_T1, 0xAAA);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xfffffffffffff000)
		pr_warn("Expected t0 to be fffffffffffff000: %lx\n", regs.t0);

	pr_debug("ORI\n");
	regs.t1 = 0xAAA;
	opcode = rv_ori(RV_REG_T0, RV_REG_T1, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFFF)
		pr_warn("Expected t0 to be 0xFFF: %lx\n", regs.t0);

	regs.t1 = 0xFF3;
	opcode = rv_ori(RV_REG_T0, RV_REG_T1, 0xFFF);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFFFFFFFFFFFFFFFF)
		pr_warn("Expected t0 to be 0xFFFFFFFFFFFFFFFF: %lx\n", regs.t0);

	pr_debug("ANDI\n");
	regs.t1 = 0xAAA;
	opcode = rv_andi(RV_REG_T0, RV_REG_T1, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0x0)
		pr_warn("Expected t0 to be 0x0: %lx\n", regs.t0);

	regs.t1 = 0xFF3;
	opcode = rv_andi(RV_REG_T0, RV_REG_T1, 0xFFD);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFF1)
		pr_warn("Expected t0 to be 0xFF1: %lx\n", regs.t0);

	return 0;
}

static __init int rv_simulate_r_ins_self_tests(void)
{
	struct pt_regs regs;
	u32 opcode;
	memset(&regs, '\0', sizeof(regs));

	pr_info(" Simulating R instructions...\n");

	pr_debug("ADD\n");
	regs.t0 = 3;
        opcode = rv_add(RV_REG_T1, RV_REG_T0, RV_REG_T0);
	rv_simulate_r_ins(opcode, 0x0, &regs);
	if (regs.t1 != 6)
		pr_warn("Expected t0 to be 6: %lx\n", regs.t1);

        opcode = rv_add(RV_REG_T1, RV_REG_T1, RV_REG_T0);
	rv_simulate_r_ins(opcode, 0x0, &regs);
	if (regs.t1 != 9)
		pr_warn("Expected t1 to be 9: %lx\n", regs.t1);

	regs.t2 = (unsigned long)-1;
        opcode = rv_add(RV_REG_T0, RV_REG_T1, RV_REG_T2);
	rv_simulate_r_ins(opcode, 0x0, &regs);
	if (regs.t0 != 8)
		pr_warn("Expected t0 to be 8: %lx\n", regs.t0);

	pr_debug("SUB\n");
	regs.t0 = 3;
	regs.t1 = 1;
        opcode = rv_sub(RV_REG_T2, RV_REG_T0, RV_REG_T1);
	rv_simulate_r_ins(opcode, 0x0, &regs);
	if (regs.t2 != 2)
		pr_warn("Expected t2 to be 2: %lx\n", regs.t2);

        opcode = rv_sub(RV_REG_T2, RV_REG_T2, RV_REG_T2);
	rv_simulate_r_ins(opcode, 0x0, &regs);
	if (regs.t2 != 0)
		pr_warn("Expected t2 to be 0: %lx\n", regs.t2);

        opcode = rv_sub(RV_REG_T2, RV_REG_T2, RV_REG_T1);
	rv_simulate_r_ins(opcode, 0x0, &regs);
	if (regs.t2 != 0xffffffffffffffff)
		pr_warn("Expected t2 to be 0xffffffffffffffff: %lx\n", regs.t2);

	return 0;

	// SLLI
	pr_debug("SLLI\n");
	regs.t0 = 1;
	opcode = rv_slli(RV_REG_SP, RV_REG_T0, 0x1);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0x2)
		pr_warn("Expected sp to be 2: %lx\n", regs.sp);
	if (regs.t0 != 0x1)
		pr_warn("t0 should be unchanged: %lx\n", regs.t0);

	opcode = rv_slli(RV_REG_SP, RV_REG_T0, 0x2);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0x4)
		pr_warn("Expected sp to be 4: %lx\n", regs.sp);

	opcode = rv_slli(RV_REG_SP, RV_REG_T0, 0x10);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.sp != 0x10000)
		pr_warn("Expected sp to be 0x10000: %lx\n", regs.sp);

	opcode = rv_slli(RV_REG_SP, RV_REG_ZERO, 0x10);
	if (regs.sepc != 0)
		pr_warn("sepc shouln't be touched\n");

	pr_debug("SRLI\n");
	opcode = rv_srli(RV_REG_T0, RV_REG_SP, 0x10);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t0);

	regs.t3 = 0x8000000000000000;
	opcode = rv_srli(RV_REG_T0, RV_REG_T3, 0x02);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0x2000000000000000)
		pr_warn("Expected t0 to be 0x2000000000000000: %lx\n", regs.t0);

	pr_debug("SRAI\n");
	opcode = rv_srai(RV_REG_T0, RV_REG_T3, 0x03);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xF000000000000000)
		pr_warn("Expected t0 to be 0xF000000000000000: %lx\n", regs.t0);

	pr_debug("SLTI\n");
	regs.sp = 0x1;
	opcode = rv_i_insn(0x2, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	opcode = rv_i_insn(0x1, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-1;
	opcode = rv_i_insn(0x0, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	opcode = rv_i_insn(0xFFF, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-2;
	opcode = rv_i_insn(0xFFF, RV_REG_SP, 2, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	pr_debug("SLTIU\n");
	regs.sp = 0x1;
	opcode = rv_i_insn(0x2, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	opcode = rv_i_insn(0x1, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-1;
	opcode = rv_i_insn(0x0, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	opcode = rv_i_insn(0xFFF, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x0)
		pr_warn("Expected t0 to be 0: %lx\n", regs.t1);

	regs.sp = (unsigned long)-2;
	opcode = rv_i_insn(0xFFF, RV_REG_SP, 3, RV_REG_T1, 0x13);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0x1)
		pr_warn("Expected t0 to be 1: %lx\n", regs.t1);

	pr_debug("XORI\n");
	regs.t1 = 0xAAA;
	opcode = rv_xori(RV_REG_T0, RV_REG_T1, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFFF)
		pr_warn("Expected t0 to be 0xFFF: %lx\n", regs.t0);

	opcode = rv_xori(RV_REG_T1, RV_REG_T0, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t1 != 0xAAA)
		pr_warn("Expected t0 to be 0xAAA: %lx\n", regs.t1);

	opcode = rv_xori(RV_REG_T0, RV_REG_T1, 0xAAA);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xfffffffffffff000)
		pr_warn("Expected t0 to be fffffffffffff000: %lx\n", regs.t0);

	pr_debug("ORI\n");
	regs.t1 = 0xAAA;
	opcode = rv_ori(RV_REG_T0, RV_REG_T1, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFFF)
		pr_warn("Expected t0 to be 0xFFF: %lx\n", regs.t0);

	regs.t1 = 0xFF3;
	opcode = rv_ori(RV_REG_T0, RV_REG_T1, 0xFFF);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFFFFFFFFFFFFFFFF)
		pr_warn("Expected t0 to be 0xFFFFFFFFFFFFFFFF: %lx\n", regs.t0);

	pr_debug("ANDI\n");
	regs.t1 = 0xAAA;
	opcode = rv_andi(RV_REG_T0, RV_REG_T1, 0x555);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0x0)
		pr_warn("Expected t0 to be 0x0: %lx\n", regs.t0);

	regs.t1 = 0xFF3;
	opcode = rv_andi(RV_REG_T0, RV_REG_T1, 0xFFD);
	rv_simulate_i_ins(opcode, 0x0, &regs);
	if (regs.t0 != 0xFF1)
		pr_warn("Expected t0 to be 0xFF1: %lx\n", regs.t0);
}

static __init int rv_simulate_rb_ins_self_tests(void)
{
	struct pt_regs regs;
	u32 opcode;
	memset(&regs, '\0', sizeof(regs));

	pr_info(" Simulating RB instructions...\n");

	pr_debug("BEQ\n");
        opcode = rv_beq(RV_REG_SP, RV_REG_T0, 0x6 >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.t0 = 1;
	opcode = rv_beq(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x6, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = 1;
	opcode = rv_beq(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x0)
		pr_warn("Expected sepc to be 0: %lx\n", regs.sepc);

	pr_debug("BNE\n");
	regs.t0 = 0;
        opcode = rv_bne(RV_REG_SP, RV_REG_T0, 0x6 >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = 0;
	opcode = rv_bne(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x6, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = 1;
	opcode = rv_bne(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x0)
		pr_warn("Expected sepc to be 0: %lx\n", regs.sepc);

	pr_debug("BLT\n");
	regs.t0 = 0;
	regs.sp = (unsigned long)-1;
        opcode = rv_blt(RV_REG_SP, RV_REG_T0, 0x6 >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.t0 = (unsigned long)-2;
	opcode = rv_blt(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x6, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = 1;
	regs.t0 = 2;
	opcode = rv_blt(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x0)
		pr_warn("Expected sepc to be 0: %lx\n", regs.sepc);

	pr_debug("BGE\n");
	regs.t0 = 0;
	regs.sp = 0;
        opcode = rv_bge(RV_REG_SP, RV_REG_T0, 0x6 >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = (unsigned long)-2;
	opcode = rv_bge(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x6, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = 2;
	regs.t0 = 1;
	opcode = rv_bge(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x0)
		pr_warn("Expected sepc to be 0: %lx\n", regs.sepc);

	pr_debug("BLTU\n");
	regs.sp = 0;
	regs.t0 = (unsigned long)-1;
        opcode = rv_bltu(RV_REG_SP, RV_REG_T0, 0x6 >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = (unsigned long)-1;
	regs.t0 = (unsigned long)-2;
	opcode = rv_bltu(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x6, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = 1;
	regs.t0 = 2;
	opcode = rv_bltu(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x0)
		pr_warn("Expected sepc to be 0: %lx\n", regs.sepc);

	pr_debug("BGEU\n");
	regs.t0 = 0;
	regs.sp = 0;
        opcode = rv_bgeu(RV_REG_SP, RV_REG_T0, 0x6 >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.t0 = (unsigned long)-2;
	opcode = rv_bgeu(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x6, &regs);
	if (regs.sepc != 0x6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);

	regs.sp = 2;
	regs.t0 = 1;
	opcode = rv_bgeu(RV_REG_SP, RV_REG_T0, 0x1FFA >> 1);
	rv_simulate_rb_ins(opcode, 0x0, &regs);
	if (regs.sepc != 0x0)
		pr_warn("Expected sepc to be 0: %lx\n", regs.sepc);
	return 0;
}

static __init int rv_simulate_jump_ins_self_tests(void)
{
	struct pt_regs regs;
	u32 opcode;
	memset(&regs, '\0', sizeof(regs));

	pr_info(" Simulating jump instructions...\n");

	pr_debug("JAL\n");
        opcode = rv_jal(RV_REG_T0, 0xaaa >> 1);
	rv_simulate_jal(opcode, 0x0, &regs);
	if (regs.sepc != 0xaaa)
		pr_warn("Expected sepc to be 0xaaa: %lx\n", regs.sepc);
	if (regs.t0 != 4)
		pr_warn("Expected t0 to be 4: %lx\n", regs.t0);

	regs.sepc = 8;
        opcode = rv_jal(RV_REG_T0, 0xFFFFE);
	rv_simulate_jal(opcode, 0x0, &regs);
	if (regs.sepc != 4)
		pr_warn("Expected sepc to be 4: %lx\n", regs.sepc);
	if (regs.t0 != 12)
		pr_warn("Expected t0 to be 8: %lx\n", regs.t0);

	pr_debug("JALR\n");
	regs.t1 = 3;
        opcode = rv_jalr(RV_REG_T0, RV_REG_T1, 4);
	rv_simulate_jalr(opcode, 0x0, &regs);
	if (regs.sepc != 6)
		pr_warn("Expected sepc to be 6: %lx\n", regs.sepc);
	if (regs.t0 != 8)
		pr_warn("Expected t0 to be 8: %lx\n", regs.t0);

	regs.sepc = 8;
	regs.t1 = 8;
        opcode = rv_jalr(RV_REG_T0, RV_REG_T1, 0xFFD);
	rv_simulate_jalr(opcode, 0x0, &regs);
	if (regs.sepc != 4)
		pr_warn("Expected sepc to be 4: %lx\n", regs.sepc);
	if (regs.t0 != 12)
		pr_warn("Expected t0 to be 8: %lx\n", regs.t0);

	return 0;
}

static __init int rv_simulate_ui_ins_self_tests(void)
{
	struct pt_regs regs;
	u32 opcode;
	memset(&regs, '\0', sizeof(regs));

	pr_info(" Simulating upper-immediate instructions...\n");

	pr_debug("LUI\n");
	regs.t0 = 0x321;
        opcode = rv_lui(RV_REG_T0, 0x12345000 >> 12);
	rv_simulate_lui(opcode, 0x0, &regs);
	if (regs.t0 != 0x12345000)
		pr_warn("Expected t0 to be 0x12345000: %lx\n", regs.t0);

	pr_debug("AUIPC\n");
	regs.t0 = 0;
	regs.sepc = 0x321;
        opcode = rv_lui(RV_REG_T0, 0x12345000 >> 12);
	opcode &= 0xFFFFFF9F;  // change it to auipc
	rv_simulate_auipc(opcode, 0x0, &regs);
	if (regs.t0!= 0x12345321)
		pr_warn("Expected t0 to be 0x12345321: %lx\n", regs.t0);
	if (regs.sepc != 0x321)
		pr_warn("Expected sepc to be 0x123: %lx\n", regs.sepc);
	return 0;
}

static __init int simulate_insn_self_tests_init(void)
{
	pr_info("Running RISC-V insn simulation tests...\n");

	rv_simulate_i_ins_self_tests();
	rv_simulate_r_ins_self_tests();
	rv_simulate_rb_ins_self_tests();
	rv_simulate_jump_ins_self_tests();
	rv_simulate_ui_ins_self_tests();

	pr_info("Done running RISC-V insn simulation tests.\n");
	return 0;
}

late_initcall(simulate_insn_self_tests_init);
