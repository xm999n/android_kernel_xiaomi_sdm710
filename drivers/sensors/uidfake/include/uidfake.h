/* SPDX-License-Identifier: GPL-2.0 */
/* uidfake_grus: 4.9 sdm710 out-of-tree port header. */
#ifndef UIDFAKE_GRUS_H
#define UIDFAKE_GRUS_H

#include <linux/jump_label.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/uidgid.h>

#define POLICY_MAX_PAIRS 65536
#define POLICY_WAY 8
#define POLICY_PROBE_MAX 4
#define POLICY_CLINE_WAY 8
#define POLICY_MIN_LINES 16
#define POLICY_MAX_LINES 32768
#define POLICY_MAX_CALLERS 4096
#define POLICY_REPL_BITS 12
#define POLICY_REPL_BASE 20001u
#define POLICY_REPL_MAX (1u << POLICY_REPL_BITS)
#define POLICY_ID_NONE 0xffffffffu
#define POLICY_APP_ID_MIN 10000u
#define POLICY_APP_ID_SPAN 10000u
#define POLICY_WILD_FLAG (1u << 15)

struct uid_pair {
	u32 target;
	u16 repl_k;
	u16 mask_id;
};

void policy_apply(const u32 *pairs, u32 npairs);
u32 policy_live_pairs(void);

extern struct static_key_false uidfake_debug_key;
#define UF_DEBUG_ON() static_branch_unlikely(&uidfake_debug_key)
void uidfake_debug_init(bool on);
u32 policy_lookup_as(uid_t caller, uid_t target);

#define UF_TAG_SHIFT 40
#define UF_TAG_MASK 0x3fffUL
#define UF_APP_MIN POLICY_APP_ID_MIN
#define UF_APP_SPAN POLICY_APP_ID_SPAN
#define UF_ISOLATED_START 90000u
#define UF_TAG_PENDING (1UL << 55)
#define UF_APK_MAX 10000

u32 uidfake_tag_app(void);
int uidfake_apk_apply(const u32 *blob, u32 n);
int uidfake_apk_apply_len(const u32 *blob, u32 len);
void uidfake_apk_remove(void);
void uidfake_tag_adopt(u32 old_uid, u32 new_uid);
void uidfake_tag_prime(void);
bool uidfake_tag_isset(void);
void uidfake_tag_note(u32 before_sid, u32 after_sid, u32 old_uid, u32 new_uid);

int uidfake_lsm_install(void);
void uidfake_lsm_remove(void);

struct kaux_status;
void uidfake_status_get(struct kaux_status *out);
void uidfake_status_set_hooks(unsigned int native, unsigned int compat);
void uidfake_status_set_lsm(int state, int error, const char *target);
void uidfake_status_set_apks(unsigned int inodes, unsigned int expected, unsigned int failed);
void uidfake_status_note(int error);

int policy_init(void);
void policy_free(void);

int hooks_install(void);
void hooks_remove(void);

int uidfake_patch_text(void *dst, const void *src, size_t len, bool sync);
int uidfake_patch_init(void);
unsigned long uidfake_lookup(const char *name);
unsigned long uidfake_lookup_raw(const char *name);

int netlink_init(void);
void netlink_exit(void);

#endif
