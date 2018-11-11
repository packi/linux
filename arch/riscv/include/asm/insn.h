
#include <linux/types.h>

#ifndef _RISCV_INSN_H
#define _RISCV_INSN_H

enum {
	RV_REG_ZERO =	0,	/* The constant value 0 */
	RV_REG_RA =	1,	/* Return address */
	RV_REG_SP =	2,	/* Stack pointer */
	RV_REG_GP =	3,	/* Global pointer */
	RV_REG_TP =	4,	/* Thread pointer */
	RV_REG_T0 =	5,	/* Temporaries */
	RV_REG_T1 =	6,
	RV_REG_T2 =	7,
	RV_REG_FP =	8,
	RV_REG_S1 =	9,	/* Saved registers */
	RV_REG_A0 =	10,	/* Function argument/return values */
	RV_REG_A1 =	11,	/* Function arguments */
	RV_REG_A2 =	12,
	RV_REG_A3 =	13,
	RV_REG_A4 =	14,
	RV_REG_A5 =	15,
	RV_REG_A6 =	16,
	RV_REG_A7 =	17,
	RV_REG_S2 =	18,	/* Saved registers */
	RV_REG_S3 =	19,
	RV_REG_S4 =	20,
	RV_REG_S5 =	21,
	RV_REG_S6 =	22,
	RV_REG_S7 =	23,
	RV_REG_S8 =	24,
	RV_REG_S9 =	25,
	RV_REG_S10 =	26,
	RV_REG_S11 =	27,
	RV_REG_T3 =	28,	/* Temporaries */
	RV_REG_T4 =	29,
	RV_REG_T5 =	30,
	RV_REG_T6 =	31,
};

u32 rv_addiw(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_addi(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_addw(u8 rd, u8 rs1, u8 rs2);
u32 rv_add(u8 rd, u8 rs1, u8 rs2);
u32 rv_subw(u8 rd, u8 rs1, u8 rs2);
u32 rv_sub(u8 rd, u8 rs1, u8 rs2);
u32 rv_and(u8 rd, u8 rs1, u8 rs2);
u32 rv_or(u8 rd, u8 rs1, u8 rs2);
u32 rv_xor(u8 rd, u8 rs1, u8 rs2);
u32 rv_mulw(u8 rd, u8 rs1, u8 rs2);
u32 rv_mul(u8 rd, u8 rs1, u8 rs2);
u32 rv_divuw(u8 rd, u8 rs1, u8 rs2);
u32 rv_divu(u8 rd, u8 rs1, u8 rs2);
u32 rv_remuw(u8 rd, u8 rs1, u8 rs2);
u32 rv_remu(u8 rd, u8 rs1, u8 rs2);
u32 rv_sllw(u8 rd, u8 rs1, u8 rs2);
u32 rv_sll(u8 rd, u8 rs1, u8 rs2);
u32 rv_srlw(u8 rd, u8 rs1, u8 rs2);
u32 rv_srl(u8 rd, u8 rs1, u8 rs2);
u32 rv_sraw(u8 rd, u8 rs1, u8 rs2);
u32 rv_sra(u8 rd, u8 rs1, u8 rs2);
u32 rv_lui(u8 rd, u32 imm31_12);
u32 rv_slli(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_andi(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_ori(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_xori(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_slliw(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_srliw(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_srli(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_sraiw(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_srai(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_jal(u8 rd, u32 imm20_1);
u32 rv_jalr(u8 rd, u8 rs1, u16 imm11_0);
u32 rv_beq(u8 rs1, u8 rs2, u16 imm12_1);
u32 rv_bltu(u8 rs1, u8 rs2, u16 imm12_1);
u32 rv_bgeu(u8 rs1, u8 rs2, u16 imm12_1);
u32 rv_bne(u8 rs1, u8 rs2, u16 imm12_1);
u32 rv_blt(u8 rs1, u8 rs2, u16 imm12_1);
u32 rv_bge(u8 rs1, u8 rs2, u16 imm12_1);
u32 rv_sb(u8 rs1, u16 imm11_0, u8 rs2);
u32 rv_sh(u8 rs1, u16 imm11_0, u8 rs2);
u32 rv_sw(u8 rs1, u16 imm11_0, u8 rs2);
u32 rv_sd(u8 rs1, u16 imm11_0, u8 rs2);
u32 rv_lbu(u8 rd, u16 imm11_0, u8 rs1);
u32 rv_lhu(u8 rd, u16 imm11_0, u8 rs1);
u32 rv_lwu(u8 rd, u16 imm11_0, u8 rs1);
u32 rv_ld(u8 rd, u16 imm11_0, u8 rs1);
u32 rv_amoadd_w(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
u32 rv_amoadd_d(u8 rd, u8 rs2, u8 rs1, u8 aq, u8 rl);
u32 rv_i_insn(u16 imm11_0, u8 rs1, u8 funct3, u8 rd, u8 opcode);


#endif /* _RISCV_INSN_H */
