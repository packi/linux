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

static enum probe_insn
riscv_decompress_insn(probe_opcode_t insn, struct kprobe *p)
{
	p->ainsn.jump_insn = false;
	/* c.addisp16 imm */
	if ((insn & C_ADDISP16_MASK) == C_ADDISP16_VAL) {
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
		p->ainsn.original_opcode = insn;
	} else {
		pr_warn("Rejected unknown instruction %x\n", insn);
		return INSN_REJECTED;
	}

	return INSN_GOOD_NO_SLOT;
}
NOKPROBE_SYMBOL(riscv_decompress_insn);

static enum probe_insn
riscv_decode_insn(probe_opcode_t insn, struct kprobe *p)
{
	u32 opcode = insn & OPCODE_MASK;
	bool jump_insn = false;
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
		jump_insn = true;
	}
	else if (opcode == 0x67) {
		p->ainsn.handler = rv_simulate_jalr;
		jump_insn = true;
	}

	if (p->ainsn.handler) {
		p->opcode = insn;
		p->ainsn.original_opcode = insn;
		p->ainsn.jump_insn = jump_insn;
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
