// SPDX-License-Identifier: GPL-2.0+

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <asm/sections.h>
#include <asm/insn.h>

#include "decode-insn.h"
#include "simulate-insn.h"

#define C_ADDISP16_MASK 0x6F83
#define C_ADDISP16_VAL  0x6101
#define OPCODE_MASK     0x7F

#define bit_at(value, bit)		((value) & (1 << (bit)))
#define move_bit_at(value, bit, to)	((bit_at(value, bit) >> bit) << to)


static u8 riscv_c_func3(probe_opcode_t insn)
{
	return (insn & 0xE000) >> 13;
}

static u8 riscv_c_q0_rd(probe_opcode_t insn)
{
	return (insn & 0x001C) >> 2;
}

static u16 riscv_c_nzuimm(probe_opcode_t insn)
{
	return 	move_bit_at(insn, 12, 5) |
			((insn & 0x7C) >> 2);
}

static s16 riscv_c_q1_imm_signed(probe_opcode_t insn)
{
	return sign_extend32(riscv_c_nzuimm(insn), 5);
}

static enum probe_insn
riscv_decompress_q0_insn(probe_opcode_t insn, struct kprobe *p)
{
	u8 func3 = riscv_c_func3(insn);

	if ((insn & 0x00FF) == 0)
		/* Illegal instruction */
		return INSN_REJECTED;

	if (func3 == 0) {
		/* c.addi4spn */
		u16 imm = ((insn & 0x1800) >> 7) | ((insn & 0x710) >> 1) |
			move_bit_at(insn, 6, 2) | move_bit_at(insn, 5, 3);

		p->opcode = rv_addi(riscv_c_q0_rd(insn), RV_REG_SP, imm);
		p->ainsn.handler = rv_simulate_i_ins;
		return INSN_GOOD_NO_SLOT;
	}
	return INSN_REJECTED;
}

static s16
riscv_c_q1_b_offset(probe_opcode_t insn)
{
	return sign_extend32(move_bit_at(insn, 12, 8) |
		((insn >> 7) & 0x18) |
		((insn << 1) & 0xC0) |
		((insn >> 2) & 0x6) |
		move_bit_at(insn, 2, 5), 8);
}

static enum probe_insn
riscv_decompress_q1_rr(s16 imm, u8 rd, struct kprobe *p)
{
	u8 group = (imm & 0x20) >> 5;
	u8 rs1_rd = (rd & 0x7) + 8; // TODO: constant for 8...
	u8 rs2 = (imm & 0x7) + 8;
	u8 func = (imm & 0x18) >> 3;

	/* group == 1 would be c.subw/c.addw and we don't have simulation
	 * support for them at the moment */
	if (group == 0) {
		switch (func) {
			case 0:
				/* c.sub */
				p->opcode = rv_sub(rs1_rd, rs1_rd, rs2);
				p->ainsn.handler = rv_simulate_r_ins;
				break;
			case 1:
				/* c.xor */
				p->opcode = rv_xor(rs1_rd, rs1_rd, rs2);
				p->ainsn.handler = rv_simulate_r_ins;
				break;
			case 2:
				/* c.or */
				p->opcode = rv_or(rs1_rd, rs1_rd, rs2);
				p->ainsn.handler = rv_simulate_r_ins;
				break;
			case 3:
				/* c.and */
				p->opcode = rv_and(rs1_rd, rs1_rd, rs2);
				p->ainsn.handler = rv_simulate_r_ins;
				break;
		}
		return INSN_GOOD_NO_SLOT;
	}
	return INSN_REJECTED;
}

static enum probe_insn
riscv_decompress_q1_insn(probe_opcode_t insn, struct kprobe *p)
{
	u8 func3 = riscv_c_func3(insn);
	u8 rd;
	s16 imm;
	if (func3 == 0) {
		/* c.nop / c.addi */
		rd = (insn & 0xF80) >> 7;
		imm = riscv_c_q1_imm_signed(insn);

		p->opcode = rv_addi(rd, rd, imm & 0xFFF);
		p->ainsn.handler = rv_simulate_i_ins;
		return INSN_GOOD_NO_SLOT;
	} else if (func3 == 1) {
		/* c.addiw, RV64/RV128 only */
		rd = (insn & 0xF80) >> 7;
		imm = riscv_c_q1_imm_signed(insn);

		if (rd == 0)
			/* c.jal RV32 only */
			return INSN_REJECTED;

		p->opcode = rv_addiw(rd, rd, imm & 0xFFF);
		p->ainsn.handler = rv_simulate_i_ins;
		return INSN_GOOD_NO_SLOT;
	} else if (func3 == 2) {
		/* c.li */
		rd = (insn & 0xF80) >> 7;
		imm = riscv_c_q1_imm_signed(insn);

		if (rd == 0)
			return INSN_REJECTED;

		p->opcode = rv_addi(rd, RV_REG_ZERO, imm & 0xFFF);
		p->ainsn.handler = rv_simulate_i_ins;
		return INSN_GOOD_NO_SLOT;
	} else if (func3 == 3) {
		rd = (insn & 0xF80) >> 7;
		if (rd == 2) {
			/* c.addisp16 */
			s16 imm = sign_extend32(
				move_bit_at(insn, 12, 9) |
				move_bit_at(insn, 6, 4) |
				move_bit_at(insn, 5, 6) |
				move_bit_at(insn, 4, 8) |
				move_bit_at(insn, 3, 7) |
				move_bit_at(insn, 2, 5),
				9);
			p->opcode = rv_addi(RV_REG_SP, RV_REG_SP, imm & 0x0FFF);
			p->ainsn.handler = rv_simulate_i_ins;
			return INSN_GOOD_NO_SLOT;
		} else if (rd != 0) {
			/* c.lui */
			s32 imm = sign_extend32(
				move_bit_at(insn, 12, 17) |
				(insn & 0x7C) << 10,
				17);
			p->opcode = rv_lui(rd, imm);
			return INSN_GOOD_NO_SLOT;
		}
	} else if (func3 == 4) {
		rd = (insn & 0xF80) >> 7;
		imm = riscv_c_q1_imm_signed(insn);

		switch ((rd & 0x18) >> 3) {
			case 0:
				if (imm == 0)
					/* c.srli64 */
					return INSN_REJECTED;
				p->opcode = rv_srli((rd & 0x7) + 8, (rd & 0x7) + 8, imm & 0xFFF);
				p->ainsn.handler = rv_simulate_i_ins;
				break;
			case 1:
				if (imm == 0)
					/* c.srai64 */
					return INSN_REJECTED;
				p->opcode = rv_srai((rd & 0x7) + 8, (rd & 0x7) + 8, imm & 0xFFF);
				p->ainsn.handler = rv_simulate_i_ins;
				break;
			case 2:
				/* c.andi */
				p->opcode = rv_andi((rd & 0x7) + 8, (rd & 0x7) + 8, imm & 0xFFF);
				p->ainsn.handler = rv_simulate_i_ins;
				break;
			case 3:
				return riscv_decompress_q1_rr(imm, rd, p);
			default:
				return INSN_REJECTED;
		}
		return INSN_GOOD_NO_SLOT;
	} else if (func3 == 5) {
		/* c.j */
		imm = move_bit_at(insn, 12, 11) |
			move_bit_at(insn, 11, 4) |
			((insn >> 1) & 0x300) |
			move_bit_at(insn, 8, 10) |
			move_bit_at(insn, 7, 6) |
			move_bit_at(insn, 6, 7) |
			((insn >> 2) & 0xE) |
			move_bit_at(insn, 2, 5);

		p->opcode = rv_jal(RV_REG_ZERO, imm >> 1);
		p->ainsn.handler = rv_simulate_jal;
		return INSN_GOOD_NO_SLOT;
	} else if (func3 == 6) {
		/* c.beqz */
		rd = ((insn & 0x380) >> 7) + 8;
		p->opcode = rv_beq(rd, RV_REG_ZERO, (riscv_c_q1_b_offset(insn) & 0x1FFF) >> 1);
		p->ainsn.handler = rv_simulate_rb_ins;
		return INSN_GOOD_NO_SLOT;
	} else if (func3 == 7) {
		/* c.bnez */
		rd = ((insn & 0x380) >> 7) + 8;
		p->opcode = rv_bne(rd, RV_REG_ZERO, (riscv_c_q1_b_offset(insn) & 0x1FFF) >> 1);
		p->ainsn.handler = rv_simulate_rb_ins;
		return INSN_GOOD_NO_SLOT;
	}
	return INSN_REJECTED;
}

static u8 riscv_q2_rs1_rd(probe_opcode_t insn)
{
	return (insn >> 7) & 0x1F;
}

static enum probe_insn
riscv_decompress_q2_insn(probe_opcode_t insn, struct kprobe *p)
{
	u8 func3 = riscv_c_func3(insn);
	u8 rd = riscv_q2_rs1_rd(insn);
	u16 imm = riscv_c_nzuimm(insn);
	if (func3 == 0) {
		/* c.slli/c.slli64 */
		p->opcode = rv_slli(rd, rd, imm);
		p->ainsn.handler = rv_simulate_i_ins;
		return INSN_GOOD_NO_SLOT;
	} else if (func3 == 4) {
		if (imm == 0) {
			/* c.jr */
			p->opcode = rv_jalr(RV_REG_ZERO, rd, 0);
			p->ainsn.handler = rv_simulate_jalr;
		} else if ((imm & 0x20) == 0 && (imm & 0x1f) != 0)  {
			/* c.mv */
			p->opcode = rv_addi(rd, ((insn >> 2) & 0x1F), 0);
			p->ainsn.handler = rv_simulate_i_ins;
		} else if ((imm & 0x20) == 0x20 && (imm & 0x1f) != 0)  {
			/* c.add */
			p->opcode = rv_add(rd, rd, (insn >> 2) & 0x1f);
			p->ainsn.handler = rv_simulate_r_ins;
		} else {
			return INSN_REJECTED;
		}
		return INSN_GOOD_NO_SLOT;
	}
	return INSN_REJECTED;
}

static enum probe_insn
riscv_decompress_insn(probe_opcode_t insn, struct kprobe *p)
{
	u32 quadrant  = insn & 0x0003;

	p->ainsn.original_opcode = insn;

	if (quadrant == 0)
		return riscv_decompress_q0_insn(insn, p);
	else if (quadrant == 1)
		return riscv_decompress_q1_insn(insn, p);
	else if (quadrant == 2)
		return riscv_decompress_q2_insn(insn, p);

	pr_warn("Rejected unknown instruction %x\n", insn);
	return INSN_REJECTED;
}
NOKPROBE_SYMBOL(riscv_decompress_insn);

static enum probe_insn
riscv_decode_insn(probe_opcode_t insn, struct kprobe *p)
{
	u32 opcode = insn & OPCODE_MASK;
	if (opcode == 0x12)
		p->ainsn.handler = rv_simulate_i_ins;
	else if (opcode == 0x22)
		p->ainsn.handler = rv_simulate_r_ins;
	else if (opcode == 0x62)
		p->ainsn.handler = rv_simulate_rb_ins;
	else if (opcode == 0x23)
		p->ainsn.handler = rv_simulate_lui;
	else if (opcode == 0x13)
		p->ainsn.handler = rv_simulate_auipc;
	else if (opcode == 0x6f) {
		p->ainsn.handler = rv_simulate_jal;
		p->ainsn.jump_insn = true;
	}
	else if (opcode == 0x67) {
		p->ainsn.handler = rv_simulate_jalr;
		p->ainsn.jump_insn = true;
	}

	if (p->ainsn.handler) {
		p->opcode = insn;
		p->ainsn.original_opcode = insn;
		return INSN_GOOD_NO_SLOT;
	}
	return INSN_REJECTED;
}
NOKPROBE_SYMBOL(riscv_decode_insn);

/* Return:
 *   INSN_REJECTED     If instruction is one not allowed to kprobe,
 *   INSN_GOOD_NO_SLOT If instruction is supported but doesn't use its slot.
 */
enum probe_insn
riscv_probe_decode_insn(struct kprobe *p)
{
	probe_opcode_t insn = le32_to_cpu(*p->addr);

	if (!is_compressed_insn(insn)) {
		return riscv_decode_insn(insn, p);
	}

	return riscv_decompress_insn(insn, p);
}
NOKPROBE_SYMBOL(riscv_probe_decode_insn);



static __init int decode_insn_self_tests_init(void)
{
	struct kprobe p;
	enum probe_insn res;
        pr_info("Running RISC-V insn decode tests...\n");

	/* c.li a2, 1 */
	res = riscv_decompress_insn(0x4605, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.li a2, 1");
	if (p.opcode != rv_addi(RV_REG_A2, RV_REG_ZERO, 1))
		pr_warn("error uncompressing c.li a2, 1 %x", p.opcode);

	/* c.lui t0,0x6 */
	res = riscv_decompress_insn(0x6299, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.lui t0, 0x6");
	if (p.opcode != rv_lui(RV_REG_T0, 0x6 << 12))
		pr_warn("error uncompressing c.lui t0, 0x6 %x", p.opcode);

	/* c.mv s0, a0 */
	res = riscv_decompress_insn(0x842a, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.mv s0, a0");
	if (p.opcode != rv_addi(RV_REG_FP, RV_REG_A0, 0))
		pr_warn("error uncompressing c.mv s0, a0 %x", p.opcode);

	/* c.mv s1, a1 */
	res = riscv_decompress_insn(0x84ae, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.mv s1, a1");
	if (p.opcode != rv_addi(RV_REG_S1, RV_REG_A1, 0))
		pr_warn("error uncompressing c.mv s1, a1 %x", p.opcode);

	/* c.sub a1, a1, a0 */
	res = riscv_decompress_insn(0x8d89, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.sub a1, a1, a0");
	if (p.opcode != rv_sub(RV_REG_A1, RV_REG_A1, RV_REG_A0))
		pr_warn("error uncompressing c.sub a1, a1, a0 %x", p.opcode);

	/* c.add ra, ra, a1 */
	res = riscv_decompress_insn(0x90ae, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.add ra, ra, a1");
	if (p.opcode != rv_add(RV_REG_RA, RV_REG_RA, RV_REG_A1))
		pr_warn("error uncompressing c.add ra, ra, a1 %x", p.opcode);

	/* c.add a0, a0, a1 */
	res = riscv_decompress_insn(0x952e, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.add a0, a0, a1");
	if (p.opcode != rv_add(RV_REG_A0, RV_REG_A0, RV_REG_A1))
		pr_warn("error uncompressing c.add a0, a0, a1 %x", p.opcode);

	/* c.or a2, a2, a1 */
	res = riscv_decompress_insn(0x8e4d, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.or a2, a2, a1");
	if (p.opcode != rv_or(RV_REG_A2,  RV_REG_A2, RV_REG_A1))
		pr_warn("error uncompressing c.or a2, a2, a1 %x", p.opcode);

	/* c.srli a2, a2, 0xc */
	res = riscv_decompress_insn(0x8231, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.srli a2, a2, 0xc");
	if (p.opcode != rv_srli(RV_REG_A2,  RV_REG_A2, 0xc))
		pr_warn("error uncompressing c.srli a2, a2, 0xc %x", p.opcode);

	/* c.slli a5, a5, 0x20 */
	res = riscv_decompress_insn(0x1782, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.slli a5, a5, 0x20");
	if (p.opcode != rv_slli(RV_REG_A5,  RV_REG_A5, 0x20))
		pr_warn("error uncompressing c.slli a5, a5, 0x20 %x", p.opcode);

	/* c.li a1, 8 */
	res = riscv_decompress_insn(0x45a1, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.li a1, 8");
	if (p.opcode != rv_addi(RV_REG_A1, RV_REG_ZERO,  8))
		pr_warn("error uncompressing c.li a1, 8 %x", p.opcode);

	/* c,bnez a3, 0xba */
	res = riscv_decompress_insn(0xeecd, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.bnez a3, 0xba");
	if (p.opcode != rv_bne(RV_REG_A3, RV_REG_ZERO,  0xba >> 1))
		pr_warn("error uncompressing c.bnez a3, 0xba %x", p.opcode);

	/* c.beqz a0, 0x28 */
	res = riscv_decompress_insn(0xc505, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing beqz a0, 0x28");
	if (p.opcode != rv_beq(RV_REG_A0, RV_REG_ZERO,  0x28 >> 1))
		pr_warn("error uncompressing beqz a0, 0x28 %x", p.opcode);

	/* c.nop */
	res = riscv_decompress_insn(0x0001, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.nop");
	if (p.opcode != rv_addi(RV_REG_ZERO, RV_REG_ZERO,  0x0))
		pr_warn("error uncompressing c.nop %x", p.opcode);

	/* c.j 0x34 */
	res = riscv_decompress_insn(0xa815, &p);
	if (res != INSN_GOOD_NO_SLOT)
		pr_warn("error uncompressing c.j");
	if (p.opcode != rv_jal(RV_REG_ZERO, 0x34 >> 1))
		pr_warn("error uncompressing c.j %x", p.opcode);

	pr_info("Done running RISC-V insn decode tests.\n");
        return 0;
}

late_initcall(decode_insn_self_tests_init);
