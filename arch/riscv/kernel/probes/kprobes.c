// SPDX-License-Identifier: GPL-2.0+

/*
 * Kprobes support for RISC-V
 *
 * Author: Patrick Stählin <me@packi.ch>
 */
#include <linux/kprobes.h>
#include <linux/extable.h>
#include <linux/slab.h>
#include <asm/ptrace.h>
#include <linux/uaccess.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#include "decode-insn.h"

DEFINE_PER_CPU(struct kprobe *, current_kprobe) = NULL;
DEFINE_PER_CPU(struct kprobe_ctlblk, kprobe_ctlblk);

static void
post_kprobe_handler(struct kprobe_ctlblk *, struct pt_regs *);

static void patch_text(kprobe_opcode_t *addr, u32 opcode)
{
	if (is_compressed_insn(opcode))
		*(u16 *)addr = cpu_to_le16(opcode);
	else
		*addr = cpu_to_le32(opcode);

	flush_icache_all();
}
NOKPROBE_SYMBOL(patch_text);

static void arch_prepare_simulate(struct kprobe *p)
{
	if (!p->ainsn.jump_insn) {
		p->ainsn.restore = (unsigned long)p->addr +
			(is_compressed_insn(p->ainsn.original_opcode) ? 2 : 4);
	}
}
NOKPROBE_SYMBOL(arch_prepare_simulate);

static void arch_simulate_insn(struct kprobe *p, struct pt_regs *regs)
{
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();

	p->ainsn.handler((u32)p->opcode, (long)p->addr, regs);

	/* single instruction simulated, now go for post processing */
	post_kprobe_handler(kcb, regs);
}
NOKPROBE_SYMBOL(arch_simulate_insn);

int arch_prepare_kprobe(struct kprobe *p)
{
	unsigned long probe_addr = (unsigned long)p->addr;
	extern char __start_rodata[];
	extern char __end_rodata[];

	if (probe_addr & 0x1) {
		pr_warn("Address not aligned.\n");
		return -EINVAL;
	}

	/* copy instruction */
	p->opcode = le32_to_cpu(*p->addr);

	if (probe_addr >= (unsigned long) __start_rodata &&
	    probe_addr <= (unsigned long) __end_rodata) {
		return -EINVAL;
	}

	/* decode instruction */
	switch (riscv_probe_decode_insn(p)) {
	case INSN_REJECTED:	/* insn not supported */
		return -EINVAL;

	case INSN_GOOD_NO_SLOT:	/* insn needs simulation */
		break;
	}

	arch_prepare_simulate(p);

	return 0;
}
NOKPROBE_SYMBOL(arch_prepare_kprobe);

#define C_EBREAK_OPCODE 0x9002

/* arm kprobe: install breakpoint in text */
void arch_arm_kprobe(struct kprobe *p)
{
	patch_text(p->addr, C_EBREAK_OPCODE);
}
NOKPROBE_SYMBOL(arch_arm_kprobe);

/* disarm kprobe: remove breakpoint from text */
void arch_disarm_kprobe(struct kprobe *p)
{
	patch_text(p->addr, p->ainsn.original_opcode);
}
NOKPROBE_SYMBOL(arch_disarm_kprobe);

void arch_remove_kprobe(struct kprobe *p)
{
}
NOKPROBE_SYMBOL(arch_remove_kprobe);

static void save_previous_kprobe(struct kprobe_ctlblk *kcb)
{
	kcb->prev_kprobe.kp = kprobe_running();
	kcb->prev_kprobe.status = kcb->kprobe_status;
}
NOKPROBE_SYMBOL(save_previous_kprobe);

static void restore_previous_kprobe(struct kprobe_ctlblk *kcb)
{
	__this_cpu_write(current_kprobe, kcb->prev_kprobe.kp);
	kcb->kprobe_status = kcb->prev_kprobe.status;
}
NOKPROBE_SYMBOL(restore_previous_kprobe);

static void set_current_kprobe(struct kprobe *p)
{
	__this_cpu_write(current_kprobe, p);
}
NOKPROBE_SYMBOL(set_current_kprobe);

static void simulate(struct kprobe *p, struct pt_regs *regs,
		     struct kprobe_ctlblk *kcb, int reenter)
{
	if (reenter) {
		save_previous_kprobe(kcb);
		set_current_kprobe(p);
		kcb->kprobe_status = KPROBE_REENTER;
	} else {
		kcb->kprobe_status = KPROBE_HIT_SS;
	}

	arch_simulate_insn(p, regs);
}
NOKPROBE_SYMBOL(simulate);

static void reenter_kprobe(struct kprobe *p, struct pt_regs *regs,
			  struct kprobe_ctlblk *kcb)
{
	switch (kcb->kprobe_status) {
	case KPROBE_HIT_SSDONE:
	case KPROBE_HIT_ACTIVE:
		kprobes_inc_nmissed_count(p);
		simulate(p, regs, kcb, 1);
		break;
	case KPROBE_HIT_SS:
	case KPROBE_REENTER:
		pr_warn("Unrecoverable kprobe detected.\n");
		dump_kprobe(p);
		BUG();
		break;
	default:
		WARN_ON(1);
	}
}
NOKPROBE_SYMBOL(reenter_kprobe);

static void post_kprobe_handler(struct kprobe_ctlblk *kcb, struct pt_regs *regs)
{
	struct kprobe *cur = kprobe_running();

	if (!cur)
		return;

	/* return addr restore if non-branching insn */
	if (cur->ainsn.restore != 0)
		instruction_pointer_set(regs, cur->ainsn.restore);

	/* restore back original saved kprobe variables and continue */
	if (kcb->kprobe_status == KPROBE_REENTER) {
		restore_previous_kprobe(kcb);
		return;
	}
	/* call post handler */
	kcb->kprobe_status = KPROBE_HIT_SSDONE;
	if (cur->post_handler)	{
		/* post_handler can hit breakpoint and single step
		 * again, so we enable D-flag for recursive exception.
		 */
		cur->post_handler(cur, regs, 0);
	}

	reset_current_kprobe();
}
NOKPROBE_SYMBOL(post_kprobe_handler);

int kprobe_fault_handler(struct pt_regs *regs, unsigned int cause)
{
	struct kprobe *cur = kprobe_running();
	struct kprobe_ctlblk *kcb = get_kprobe_ctlblk();

	switch (kcb->kprobe_status) {
	case KPROBE_HIT_SS:
	case KPROBE_REENTER:
		/*
		 * We are here because the instruction being single
		 * stepped caused a page fault. We reset the current
		 * kprobe and the ip points back to the probe address
		 * and allow the page fault handler to continue as a
		 * normal page fault.
		 */
		instruction_pointer_set(regs, (unsigned long) cur->addr);
		BUG_ON(!instruction_pointer(regs));

		if (kcb->kprobe_status == KPROBE_REENTER)
			restore_previous_kprobe(kcb);
		else
			reset_current_kprobe();

		break;
	case KPROBE_HIT_ACTIVE:
	case KPROBE_HIT_SSDONE:
		/*
		 * We increment the nmissed count for accounting,
		 * we can also use npre/npostfault count for accounting
		 * these specific fault cases.
		 */
		kprobes_inc_nmissed_count(cur);

		/*
		 * We come here because instructions in the pre/post
		 * handler caused the page_fault, this could happen
		 * if handler tries to access user space by
		 * copy_from_user(), get_user() etc. Let the
		 * user-specified handler try to fix it first.
		 */
		if (cur->fault_handler && cur->fault_handler(cur, regs, cause))
			return 1;

		/*
		 * In case the user-specified fault handler returned
		 * zero, try to fix up.
		 */
		if (fixup_exception(regs))
			return 1;
	}
	return 0;
}
NOKPROBE_SYMBOL(kprobe_fault_handler);

int kprobe_handler(struct pt_regs *regs)
{
	struct kprobe *p, *cur_kprobe;
	struct kprobe_ctlblk *kcb;
	unsigned long addr = instruction_pointer(regs);

	preempt_disable();
	kcb = get_kprobe_ctlblk();
	cur_kprobe = kprobe_running();

	p = get_kprobe((kprobe_opcode_t *) addr);

	if (p) {
		if (cur_kprobe) {
			reenter_kprobe(p, regs, kcb);
		} else {
			/* Probe hit */
			set_current_kprobe(p);
			kcb->kprobe_status = KPROBE_HIT_ACTIVE;

			/*
			 * If we have no pre-handler or it returned 0, we
			 * continue with normal processing.  If we have a
			 * pre-handler and it returned non-zero, it will
			 * modify the execution path and no need to single
			 * stepping. Let's just reset current kprobe and exit.
			 */
			if (!p->pre_handler || !p->pre_handler(p, regs))
				simulate(p, regs, kcb, 0);
			else
				reset_current_kprobe();
		}
	} else {
		if (*(u16 *)addr != C_EBREAK_OPCODE) {
			/*
			 * The breakpoint instruction was removed right
			 * after we hit it.  Another cpu has removed
			 * either a probepoint or a debugger breakpoint
			 * at this address.  In either case, no further
			 * handling of this interrupt is appropriate.
			 */
			p = NULL;
		}
	}
	preempt_enable_no_resched();

	return p != NULL;
}
NOKPROBE_SYMBOL(kprobe_handler);

bool arch_within_kprobe_blacklist(unsigned long addr)
{
	if ((addr >= (unsigned long)__kprobes_text_start &&
	    addr < (unsigned long)__kprobes_text_end) ||
	    (addr >= (unsigned long)__entry_text_start &&
	    addr < (unsigned long)__entry_text_end) ||
	    !!search_exception_tables(addr))
		return true;

	return false;
}
NOKPROBE_SYMBOL(arch_within_kprobe_blacklist);

void __used *trampoline_probe_handler(struct pt_regs *regs)
{
	struct kretprobe_instance *ri = NULL;
	struct hlist_head *head, empty_rp;
	struct hlist_node *tmp;
	unsigned long flags, orig_ret_address = 0;
	unsigned long trampoline_address =
		(unsigned long)&kretprobe_trampoline;
	kprobe_opcode_t *correct_ret_addr = NULL;

	INIT_HLIST_HEAD(&empty_rp);
	kretprobe_hash_lock(current, &head, &flags);

	/*
	 * It is possible to have multiple instances associated with a given
	 * task either because multiple functions in the call path have
	 * return probes installed on them, and/or more than one
	 * return probe was registered for a target function.
	 *
	 * We can handle this because:
	 *     - instances are always pushed into the head of the list
	 *     - when multiple return probes are registered for the same
	 *	 function, the (chronologically) first instance's ret_addr
	 *	 will be the real return address, and all the rest will
	 *	 point to kretprobe_trampoline.
	 */
	hlist_for_each_entry_safe(ri, tmp, head, hlist) {
		if (ri->task != current)
			/* another task is sharing our hash bucket */
			continue;

		orig_ret_address = (unsigned long)ri->ret_addr;

		if (orig_ret_address != trampoline_address)
			/*
			 * This is the real return address. Any other
			 * instances associated with this task are for
			 * other calls deeper on the call stack
			 */
			break;
	}

	kretprobe_assert(ri, orig_ret_address, trampoline_address);

	correct_ret_addr = ri->ret_addr;
	hlist_for_each_entry_safe(ri, tmp, head, hlist) {
		if (ri->task != current)
			/* another task is sharing our hash bucket */
			continue;

		orig_ret_address = (unsigned long)ri->ret_addr;
		if (ri->rp && ri->rp->handler) {
			__this_cpu_write(current_kprobe, &ri->rp->kp);
			get_kprobe_ctlblk()->kprobe_status = KPROBE_HIT_ACTIVE;
			ri->ret_addr = correct_ret_addr;
			ri->rp->handler(ri, regs);
			__this_cpu_write(current_kprobe, NULL);
		}

		recycle_rp_inst(ri, &empty_rp);

		if (orig_ret_address != trampoline_address)
			/*
			 * This is the real return address. Any other
			 * instances associated with this task are for
			 * other calls deeper on the call stack
			 */
			break;
	}

	kretprobe_hash_unlock(current, &flags);

	hlist_for_each_entry_safe(ri, tmp, &empty_rp, hlist) {
		hlist_del(&ri->hlist);
		kfree(ri);
	}
	return (void *)orig_ret_address;
}
NOKPROBE_SYMBOL(trampoline_probe_handler);

void arch_prepare_kretprobe(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	ri->ret_addr = (kprobe_opcode_t *)regs->ra;
	regs->ra = (long)&kretprobe_trampoline;
}
NOKPROBE_SYMBOL(arch_prepare_kretprobe);

int arch_trampoline_kprobe(struct kprobe *p)
{
	return 0;
}
NOKPROBE_SYMBOL(arch_trampoline_kprobe);

int __init arch_init_kprobes(void)
{
	return 0;
}
