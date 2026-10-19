// SPDX-License-Identifier: GPL-2.0
/* grus 4.9 port: plain-syscall hooks + list LSM + FIX_TEXT_POKE0 patch. */
#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ioprio.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/lsm_hooks.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/resource.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/user.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/memory.h>
#include <asm/pgtable.h>
#ifndef __nocfi
#define __nocfi
#endif
#include "uidfake.h"
#include "kaux.h"

static struct kaux_status g_status = {
	.magic = KAUX_STATUS_MAGIC,
	.version = KAUX_FAMILY_VERSION,
	.va_bits = CONFIG_ARM64_VA_BITS,
	.page_shift = PAGE_SHIFT,
};
void uidfake_status_get(struct kaux_status *out)
{
	*out = g_status;
	out->policy_pairs = policy_live_pairs();
	out->magic = KAUX_STATUS_MAGIC;
	out->size = sizeof(*out);
	out->version = KAUX_FAMILY_VERSION;
}
void uidfake_status_set_hooks(unsigned int native, unsigned int compat)
{
	g_status.native = native;
	g_status.compat = compat;
	if (native == g_status.native_expected)
		g_status.flags |= KAUX_F_NATIVE;
	if (compat == g_status.compat_expected)
		g_status.flags |= KAUX_F_COMPAT;
}
void uidfake_status_set_lsm(int state, int error, const char *target)
{
	g_status.lsm_state = state;
	g_status.lsm_error = error;
	if (state == KAUX_LSM_TAKEN || state == KAUX_LSM_FALLBACK)
		g_status.flags |= KAUX_F_SETUID;
	if (target)
		strscpy(g_status.lsm_target, target, sizeof(g_status.lsm_target));
}
void uidfake_status_set_apks(unsigned int inodes, unsigned int expected, unsigned int failed)
{
	g_status.apk_inodes = inodes;
	g_status.apk_offered = expected;
	g_status.apk_failed = failed;
	g_status.apk_failed_total += failed;
	g_status.apk_updates++;
	if (failed == 0)
		g_status.flags |= KAUX_F_APKS;
}
void uidfake_status_note(int error) { g_status.last_error = error; }
void uidfake_tag_close(void);
unsigned long uidfake_lookup(const char *name);
#include "policy.c"
unsigned long uidfake_lookup(const char *name)
{
	if (!name) return 0;
	return kallsyms_lookup_name(name);
}
unsigned long uidfake_lookup_raw(const char *name) { return uidfake_lookup(name); }
int uidfake_patch_init(void) { return 0; }
typedef void (*uf_set_fixmap_fn)(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot);
static unsigned long uf_set_fixmap_addr;
static DEFINE_RAW_SPINLOCK(uf_fixmap_lock);
struct uf_patch_req { void *dst; unsigned long val; };
static int uf_patch_one(void *data)
{
	struct uf_patch_req *r = data;
	unsigned long dst = (unsigned long)r->dst;
	unsigned long voff = kimage_voffset;
	phys_addr_t phys = (phys_addr_t)(dst - voff);
	unsigned long flags;
	void *map;
	raw_spin_lock_irqsave(&uf_fixmap_lock, flags);
	((uf_set_fixmap_fn)uf_set_fixmap_addr)(FIX_TEXT_POKE0, phys & PAGE_MASK, PAGE_KERNEL);
	map = (void *)(__fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK));
	*(volatile unsigned long *)map = r->val;
	((uf_set_fixmap_fn)uf_set_fixmap_addr)(FIX_TEXT_POKE0, 0, __pgprot(0));
	raw_spin_unlock_irqrestore(&uf_fixmap_lock, flags);
	return 0;
}
int uidfake_patch_text(void *dst, const void *src, size_t len, bool sync)
{
	struct uf_patch_req req;
	unsigned long v;
	int ret;
	(void)sync;
	if (!dst || !src) return -EINVAL;
	if (len != sizeof(void *)) return -EINVAL;
	if ((unsigned long)dst & (__alignof__(void *) - 1)) return -EINVAL;
	if (!uf_set_fixmap_addr) return -ENODEV;
	memcpy(&v, src, sizeof(v));
	req.dst = dst; req.val = v;
	ret = stop_machine(uf_patch_one, &req, NULL);
	if (ret) return ret;
	if (*(volatile unsigned long *)dst != v) return -EIO;
	return 0;
}
typedef long (*uf_sys2_fn)(int, int);
typedef long (*uf_sys3_fn)(int, int, int);
typedef long (*uf_setuid_fn)(uid_t);
typedef long (*uf_setresuid_fn)(uid_t, uid_t, uid_t);
struct uf_slot { unsigned int nr; void *ours; void *orig; };
static void **uf_native_table;
static void **uf_compat_table;
static uf_sys2_fn g_orig_getpriority;
static uf_sys3_fn g_orig_setpriority;
static uf_sys2_fn g_orig_ioprio_get;
static uf_sys3_fn g_orig_ioprio_set;
static uf_sys2_fn g_corig_getpriority;
static uf_sys3_fn g_corig_setpriority;
static uf_sys2_fn g_corig_ioprio_get;
static uf_sys3_fn g_corig_ioprio_set;
static long uf_wrap_getpriority(int which, int who)
{
	u32 repl;
	if (which != PRIO_USER || !g_orig_getpriority)
		return g_orig_getpriority ? g_orig_getpriority(which, who) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_orig_getpriority(which, who);
}
static long uf_wrap_setpriority(int which, int who, int niceval)
{
	u32 repl;
	if (which != PRIO_USER || !g_orig_setpriority)
		return g_orig_setpriority ? g_orig_setpriority(which, who, niceval) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_orig_setpriority(which, who, niceval);
}
static long uf_wrap_ioprio_get(int which, int who)
{
	u32 repl;
	if (which != IOPRIO_WHO_USER || !g_orig_ioprio_get)
		return g_orig_ioprio_get ? g_orig_ioprio_get(which, who) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_orig_ioprio_get(which, who);
}
static long uf_wrap_ioprio_set(int which, int who, int ioprio)
{
	u32 repl;
	if (which != IOPRIO_WHO_USER || !g_orig_ioprio_set)
		return g_orig_ioprio_set ? g_orig_ioprio_set(which, who, ioprio) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_orig_ioprio_set(which, who, ioprio);
}
static long uf_cwrap_getpriority(int which, int who)
{
	u32 repl;
	if (which != PRIO_USER || !g_corig_getpriority)
		return g_corig_getpriority ? g_corig_getpriority(which, who) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_corig_getpriority(which, who);
}
static long uf_cwrap_setpriority(int which, int who, int niceval)
{
	u32 repl;
	if (which != PRIO_USER || !g_corig_setpriority)
		return g_corig_setpriority ? g_corig_setpriority(which, who, niceval) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_corig_setpriority(which, who, niceval);
}
static long uf_cwrap_ioprio_get(int which, int who)
{
	u32 repl;
	if (which != IOPRIO_WHO_USER || !g_corig_ioprio_get)
		return g_corig_ioprio_get ? g_corig_ioprio_get(which, who) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_corig_ioprio_get(which, who);
}
static long uf_cwrap_ioprio_set(int which, int who, int ioprio)
{
	u32 repl;
	if (which != IOPRIO_WHO_USER || !g_corig_ioprio_set)
		return g_corig_ioprio_set ? g_corig_ioprio_set(which, who, ioprio) : -ENOSYS;
	repl = policy_query((uid_t)who);
	if (repl) who = (int)repl;
	return g_corig_ioprio_set(which, who, ioprio);
}
#define UF_NR64_IOPRIO_SET 30
#define UF_NR64_IOPRIO_GET 31
#define UF_NR64_SETPRIORITY 140
#define UF_NR64_GETPRIORITY 141
#define UF_NR32_GETPRIORITY 96
#define UF_NR32_SETPRIORITY 97
#define UF_NR32_IOPRIO_SET 314
#define UF_NR32_IOPRIO_GET 315
static struct uf_slot g_native[] = {
	{ UF_NR64_GETPRIORITY, uf_wrap_getpriority, NULL },
	{ UF_NR64_SETPRIORITY, uf_wrap_setpriority, NULL },
	{ UF_NR64_IOPRIO_GET, uf_wrap_ioprio_get, NULL },
	{ UF_NR64_IOPRIO_SET, uf_wrap_ioprio_set, NULL },
};
static struct uf_slot g_compat[] = {
	{ UF_NR32_GETPRIORITY, uf_cwrap_getpriority, NULL },
	{ UF_NR32_SETPRIORITY, uf_cwrap_setpriority, NULL },
	{ UF_NR32_IOPRIO_GET, uf_cwrap_ioprio_get, NULL },
	{ UF_NR32_IOPRIO_SET, uf_cwrap_ioprio_set, NULL },
};
static uf_setuid_fn g_orig_setuid;
static uf_setresuid_fn g_orig_setresuid;
static uf_setuid_fn g_corig_setuid;
static uf_setresuid_fn g_corig_setresuid;
#define UF_NR64_SETUID 146
#define UF_NR64_SETRESUID 147
#define UF_NR32_SETUID 213
#define UF_NR32_SETRESUID 208
static long uf_change_hook(unsigned long before, long ret)
{
	u32 after;
	if (ret != 0) return ret;
	if (before != 0 && (before % 100000u) < UF_APP_MIN) return ret;
	if (uidfake_tag_isset()) return ret;
	after = (u32)__kuid_val(current_fsuid());
	if ((after % 100000u) >= UF_APP_MIN) {
		uidfake_tag_adopt((u32)before, after);
		uidfake_tag_note(0, 0, (u32)before, after);
	}
	return ret;
}
static long uf_wrap_setuid(uid_t uid)
{
	unsigned long before = (unsigned long)__kuid_val(current_fsuid());
	bool interesting = before == 0 || (before % 100000u) >= UF_APP_MIN;
	if (interesting && uidfake_tag_isset()) return g_orig_setuid(uid);
	return uf_change_hook(before, g_orig_setuid(uid));
}
static long uf_wrap_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	unsigned long before = (unsigned long)__kuid_val(current_fsuid());
	bool interesting = before == 0 || (before % 100000u) >= UF_APP_MIN;
	if (interesting && uidfake_tag_isset()) return g_orig_setresuid(ruid, euid, suid);
	return uf_change_hook(before, g_orig_setresuid(ruid, euid, suid));
}
static long uf_cwrap_setuid(uid_t uid)
{
	unsigned long before = (unsigned long)__kuid_val(current_fsuid());
	bool interesting = before == 0 || (before % 100000u) >= UF_APP_MIN;
	if (interesting && uidfake_tag_isset()) return g_corig_setuid(uid);
	return uf_change_hook(before, g_corig_setuid(uid));
}
static long uf_cwrap_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	unsigned long before = (unsigned long)__kuid_val(current_fsuid());
	bool interesting = before == 0 || (before % 100000u) >= UF_APP_MIN;
	if (interesting && uidfake_tag_isset()) return g_corig_setresuid(ruid, euid, suid);
	return uf_change_hook(before, g_corig_setresuid(ruid, euid, suid));
}
static struct uf_slot g_set_native[] = {
	{ UF_NR64_SETUID, uf_wrap_setuid, NULL },
	{ UF_NR64_SETRESUID, uf_wrap_setresuid, NULL },
};
static struct uf_slot g_set_compat[] = {
	{ UF_NR32_SETUID, uf_cwrap_setuid, NULL },
	{ UF_NR32_SETRESUID, uf_cwrap_setresuid, NULL },
};
static int uf_swap_slot(void **table, unsigned int nr, void *fn, void **save)
{
	void *old = READ_ONCE(table[nr]);
	int ret;
	*save = old;
	ret = uidfake_patch_text(&table[nr], &fn, sizeof(fn), true);
	if (ret) return ret;
	if (READ_ONCE(table[nr]) != fn) return -EIO;
	return 0;
}
static unsigned int uf_patch_list(void **table, struct uf_slot *list, unsigned int n, bool required)
{
	unsigned int i, done = 0;
	for (i = 0; i < n; i++) {
		if (uf_swap_slot(table, list[i].nr, list[i].ours, &list[i].orig)) {
			pr_warn("uidfake: patching syscall %u failed\n", list[i].nr);
			list[i].orig = NULL;
			uidfake_status_note(-EIO);
			if (required) return done;
			continue;
		}
		done++;
	}
	return done;
}
static void uf_unpatch_list(void **table, struct uf_slot *list, unsigned int n)
{
	unsigned int i;
	if (!table) return;
	for (i = 0; i < n; i++) {
		void *ours = list[i].ours;
		void *orig = list[i].orig;
		if (!orig) continue;
		if (READ_ONCE(table[list[i].nr]) != ours) {
			pr_warn("uidfake: syscall %u is no longer ours; leaving it alone\n", list[i].nr);
		} else {
			uidfake_patch_text(&table[list[i].nr], &orig, sizeof(orig), true);
		}
		list[i].orig = NULL;
	}
}
/* ---- tag group helpers (from upstream hooks.c/policy.c, cmpxchg-safe) ---- */
static bool uidfake_tag_pending(void)
{
	return (READ_ONCE(task_thread_info(current)->flags) & UF_TAG_PENDING) != 0;
}
static void uidfake_tag_group(u32 tag)
{
	struct task_struct *t;
	rcu_read_lock();
	for_each_thread(current, t) {
		const unsigned long flags = READ_ONCE(task_thread_info(t)->flags);
		const unsigned long next = (flags & ~((UF_TAG_MASK << UF_TAG_SHIFT) | UF_TAG_PENDING)) | ((unsigned long)tag << UF_TAG_SHIFT);
		if (next != flags)
			WRITE_ONCE(task_thread_info(t)->flags, next);
	}
	rcu_read_unlock();
}
static void uidfake_tag_verify(u32 tag)
{
	if (!uidfake_tag_pending())
		return;
	uidfake_tag_group(tag);
}
void uidfake_tag_name(u32 app)
{
	uidfake_tag_verify(app + 1u);
}
static void uidfake_tag_unmark(void)
{
	struct task_struct *t;
	rcu_read_lock();
	for_each_thread(current, t) {
		unsigned long *pp = (unsigned long *)&task_thread_info(t)->flags;
		unsigned long old;
		do {
			old = READ_ONCE(*pp);
			if ((old & UF_TAG_PENDING) == 0)
				break;
		} while (cmpxchg(pp, old, old & ~UF_TAG_PENDING) != old);
	}
	rcu_read_unlock();
}
void uidfake_tag_close(void)
{
	uidfake_tag_unmark();
}

typedef int (*uf_setid_fn)(struct cred *new, const struct cred *old, int flags);
static void **g_lsm_slot;
static void *g_lsm_orig;
static int uf_orig_setuid(struct cred *new, const struct cred *old, int flags)
{
	return ((uf_setid_fn)g_lsm_orig)(new, old, flags);
}
static int uf_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	const u32 before = (u32)__kuid_val(old->fsuid);
	const u32 after = (u32)__kuid_val(new->fsuid);
	const bool interesting = before == 0 || (before % 100000u) >= UF_APP_MIN;
	int ret;
	if (uidfake_tag_isset()) return uf_orig_setuid(new, old, flags);
	ret = uf_orig_setuid(new, old, flags);
	if (ret == 0 && interesting && (after % 100000u) >= UF_APP_MIN) {
		uidfake_tag_adopt(before, after);
		uidfake_tag_note(0, 0, before, after);
	}
	return ret;
}
int uidfake_lsm_install(void)
{
	struct security_hook_list *e;
	void *target;
	void *ours = (void *)uf_fix_setuid;
	target = (void *)uidfake_lookup("cap_task_fix_setuid");
	if (!target) return -ENOENT;
	struct security_hook_heads *heads = (void *)uidfake_lookup("security_hook_heads");
	if (!heads) return -ENOENT;
	list_for_each_entry(e, &heads->task_fix_setuid, list) {
		void **slot = (void **)&e->hook.task_fix_setuid;
		if (READ_ONCE(*slot) != target) continue;
		g_lsm_orig = *slot;
		if (uidfake_patch_text(slot, &ours, sizeof(ours), true) || READ_ONCE(*slot) != ours) {
			g_lsm_orig = NULL;
			return -EIO;
		}
		smp_wmb();
		g_lsm_slot = slot;
		pr_info("uidfake: task_fix_setuid taken over (cap_task_fix_setuid)\n");
		uidfake_status_set_lsm(KAUX_LSM_TAKEN, 0, "cap_task_fix_setuid");
		return 0;
	}
	return -ENOENT;
}
void uidfake_lsm_remove(void)
{
	void *orig;
	if (!g_lsm_slot) return;
	if (READ_ONCE(*g_lsm_slot) != (void *)uf_fix_setuid) {
		pr_warn("uidfake: the setuid hook is no longer ours; leaving it alone\n");
		return;
	}
	orig = g_lsm_orig;
	uidfake_patch_text(g_lsm_slot, &orig, sizeof(orig), true);
	smp_wmb();
	synchronize_rcu();
	g_lsm_slot = NULL;
	g_lsm_orig = NULL;
}
static bool g_lsm_failed;
static int g_lsm_err;
int hooks_install(void)
{
	unsigned long native, compat;
	unsigned int n, cn = 0;
	uf_set_fixmap_addr = uidfake_lookup("__set_fixmap");
	if (!uf_set_fixmap_addr) { pr_err("uidfake: __set_fixmap not found; nothing patched\n"); return 0; }
	native = uidfake_lookup("sys_call_table");
	if (!native) { pr_err("uidfake: sys_call_table not found\n"); return 0; }
	uf_native_table = (void **)native;
	compat = uidfake_lookup("compat_sys_call_table");
	uf_compat_table = compat ? (void **)compat : NULL;
	if (uidfake_lsm_install()) {
		pr_warn("uidfake: setuid hook not taken; falling back to the syscall setters\n");
		g_lsm_err = -ENOENT;
		g_lsm_failed = true;
	} else {
		pr_info("uidfake: id changes are watched at the commit\n");
	}
	g_status.native_expected = ARRAY_SIZE(g_native);
	g_status.compat_expected = uf_compat_table ? ARRAY_SIZE(g_compat) : 0;
	n = uf_patch_list(uf_native_table, g_native, ARRAY_SIZE(g_native), true);
	if (n != ARRAY_SIZE(g_native)) {
		uf_unpatch_list(uf_native_table, g_native, n);
		uidfake_lsm_remove();
		return 0;
	}
	g_orig_getpriority = g_native[0].orig;
	g_orig_setpriority = g_native[1].orig;
	g_orig_ioprio_get = g_native[2].orig;
	g_orig_ioprio_set = g_native[3].orig;
	pr_info("uidfake: %u uid syscall(s) hooked in sys_call_table\n", n);
	uidfake_status_set_hooks(n, 0);
	if (uf_compat_table) {
		cn = uf_patch_list(uf_compat_table, g_compat, ARRAY_SIZE(g_compat), false);
		if (cn != ARRAY_SIZE(g_compat))
			pr_warn("uidfake: %u of %u 32-bit entr(ies) hooked\n", cn, (unsigned)ARRAY_SIZE(g_compat));
		pr_info("uidfake: %u uid syscall(s) hooked in compat_sys_call_table\n", cn);
		g_corig_getpriority = g_compat[0].orig;
		g_corig_setpriority = g_compat[1].orig;
		g_corig_ioprio_get = g_compat[2].orig;
		g_corig_ioprio_set = g_compat[3].orig;
		uidfake_status_set_hooks(n, cn);
	}
	if (g_lsm_failed) {
		unsigned int set_done, cset_done = 0;
		set_done = uf_patch_list(uf_native_table, g_set_native, ARRAY_SIZE(g_set_native), true);
		if (set_done != ARRAY_SIZE(g_set_native)) {
			uf_unpatch_list(uf_native_table, g_set_native, set_done);
			uf_unpatch_list(uf_native_table, g_native, ARRAY_SIZE(g_native));
			if (uf_compat_table) uf_unpatch_list(uf_compat_table, g_compat, cn);
			return 0;
		}
		g_orig_setuid = g_set_native[0].orig;
		g_orig_setresuid = g_set_native[1].orig;
		pr_warn("uidfake: LSM hook unavailable (%d); id changes are watched in the syscall tables\n", g_lsm_err);
		if (uf_compat_table) {
			cset_done = uf_patch_list(uf_compat_table, g_set_compat, ARRAY_SIZE(g_set_compat), false);
			g_corig_setuid = g_set_compat[0].orig;
			g_corig_setresuid = g_set_compat[1].orig;
			pr_info("uidfake: %u of %u 32-bit id setter(s) hooked\n", cset_done, (unsigned)ARRAY_SIZE(g_set_compat));
		}
		g_status.native_expected += ARRAY_SIZE(g_set_native);
		if (uf_compat_table) g_status.compat_expected += ARRAY_SIZE(g_set_compat);
		uidfake_status_set_hooks(n + set_done, cn + cset_done);
		uidfake_status_set_lsm(KAUX_LSM_FALLBACK, g_lsm_err, "syscall setters");
	}
	uidfake_tag_prime();
	return (int)(n + cn + 1);
}
void hooks_remove(void)
{
	uidfake_apk_remove();
	if (!uf_native_table) return;
	uf_unpatch_list(uf_native_table, g_native, ARRAY_SIZE(g_native));
	if (g_lsm_failed) {
		if (uf_compat_table) uf_unpatch_list(uf_compat_table, g_set_compat, ARRAY_SIZE(g_set_compat));
		uf_unpatch_list(uf_native_table, g_set_native, ARRAY_SIZE(g_set_native));
	}
	if (uf_compat_table) uf_unpatch_list(uf_compat_table, g_compat, ARRAY_SIZE(g_compat));
	uf_compat_table = NULL;
	uf_native_table = NULL;
	uidfake_lsm_remove();
}
