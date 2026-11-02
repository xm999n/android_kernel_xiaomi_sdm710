/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_FGETPRIORITY_H
#define _LINUX_FGETPRIORITY_H

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/user_namespace.h>

#define FGP_MIN_APP_UID		10000
#define FGP_MIN_ISOLATED_UID	90000
#define FGP_AID_USER_OFFSET	100000

/*
 * (uid_t)-1 cannot own a task, so every PRIO_USER / IOPRIO_WHO_USER walk
 * ends in -ESRCH -- the same answer a stock kernel gives for a uid that
 * has no tasks at all.
 */
#define FGP_HIDDEN_UID		(-1)

static inline bool fgp_seccomp_enabled(void)
{
#ifdef TIF_SECCOMP
	return test_thread_flag(TIF_SECCOMP);
#else
	return !!current->seccomp.mode;
#endif
}

/*
 * Called only for the PRIO_USER / IOPRIO_WHO_USER cases.  An app asking
 * about another app's uid would otherwise learn whether anything runs
 * under that uid, which is one way to find a hidden process without
 * touching /proc.  A caller asking about its own uid, and any caller
 * that is not an app, is left alone.
 */
static inline int fgp_filter_who(int who)
{
	struct user_namespace *ns;
	kuid_t kuid;
	int cuid;

	if (!fgp_seccomp_enabled())
		return who;

	cuid = current_uid().val;
	if (cuid < FGP_MIN_APP_UID || who < FGP_MIN_APP_UID)
		return who;

	if (cuid >= FGP_AID_USER_OFFSET)
		cuid %= FGP_AID_USER_OFFSET;

	/*
	 * An isolated process lives in its own user namespace; treat it as
	 * the uid it maps to in the init namespace.
	 */
	ns = current_cred()->user_ns;
	if (ns && ns != &init_user_ns) {
		kuid = make_kuid(ns, 0);
		if (uid_valid(kuid)) {
			if (cuid >= FGP_MIN_ISOLATED_UID)
				cuid = from_kuid(&init_user_ns, kuid);
			if (who >= FGP_MIN_ISOLATED_UID)
				who = from_kuid(&init_user_ns, kuid);
		}
	}

	if (who >= FGP_AID_USER_OFFSET)
		who %= FGP_AID_USER_OFFSET;

	if (cuid == who)
		return who;

	return FGP_HIDDEN_UID;
}

#endif /* _LINUX_FGETPRIORITY_H */
