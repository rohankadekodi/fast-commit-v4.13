// SPDX-License-Identifier: GPL-2.0
/*
 * Interface between ext4 and JBD
 */

#include "ext4_jbd2.h"
#include "ext4_extents.h"

#include <trace/events/ext4.h>

/* Just increment the non-pointer handle value */
static handle_t *ext4_get_nojournal(void)
{
	handle_t *handle = current->journal_info;
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt >= EXT4_NOJOURNAL_MAX_REF_COUNT);

	ref_cnt++;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
	return handle;
}


/* Decrement the non-pointer handle value */
static void ext4_put_nojournal(handle_t *handle)
{
	unsigned long ref_cnt = (unsigned long)handle;

	BUG_ON(ref_cnt == 0);

	ref_cnt--;
	handle = (handle_t *)ref_cnt;

	current->journal_info = handle;
}

/*
 * Wrappers for jbd2_journal_start/end.
 */
static int ext4_journal_check_start(struct super_block *sb)
{
	journal_t *journal;

	might_sleep();

	if (unlikely(ext4_forced_shutdown(EXT4_SB(sb))))
		return -EIO;

	if (sb_rdonly(sb))
		return -EROFS;
	WARN_ON(sb->s_writers.frozen == SB_FREEZE_COMPLETE);
	journal = EXT4_SB(sb)->s_journal;
	/*
	 * Special case here: if the journal has aborted behind our
	 * backs (eg. EIO in the commit thread), then we still need to
	 * take the FS itself readonly cleanly.
	 */
	if (journal && is_journal_aborted(journal)) {
		ext4_abort(sb, "Detected aborted journal");
		return -EROFS;
	}
	return 0;
}

handle_t *__ext4_journal_start_sb(struct super_block *sb, unsigned int line,
				  int type, int blocks, int rsv_blocks)
{
	journal_t *journal;
	int err;

	trace_ext4_journal_start(sb, blocks, rsv_blocks, _RET_IP_);
	err = ext4_journal_check_start(sb);
	if (err < 0)
		return ERR_PTR(err);

	journal = EXT4_SB(sb)->s_journal;
	if (!journal)
		return ext4_get_nojournal();
	return jbd2__journal_start(journal, blocks, rsv_blocks, GFP_NOFS,
				   type, line);
}

int __ext4_journal_stop(const char *where, unsigned int line, handle_t *handle)
{
	struct super_block *sb;
	int err;
	int rc;

	if (!ext4_handle_valid(handle)) {
		ext4_put_nojournal(handle);
		return 0;
	}

	err = handle->h_err;
	if (!handle->h_transaction) {
		rc = jbd2_journal_stop(handle);
		return err ? err : rc;
	}

	sb = handle->h_transaction->t_journal->j_private;
	rc = jbd2_journal_stop(handle);

	if (!err)
		err = rc;
	if (err)
		__ext4_std_error(sb, where, line, err);
	return err;
}

handle_t *__ext4_journal_start_reserved(handle_t *handle, unsigned int line,
					int type)
{
	struct super_block *sb;
	int err;

	if (!ext4_handle_valid(handle))
		return ext4_get_nojournal();

	sb = handle->h_journal->j_private;
	trace_ext4_journal_start_reserved(sb, handle->h_buffer_credits,
					  _RET_IP_);
	err = ext4_journal_check_start(sb);
	if (err < 0) {
		jbd2_journal_free_reserved(handle);
		return ERR_PTR(err);
	}

	err = jbd2_journal_start_reserved(handle, type, line);
	if (err < 0)
		return ERR_PTR(err);
	return handle;
}

static void ext4_journal_abort_handle(const char *caller, unsigned int line,
				      const char *err_fn,
				      struct buffer_head *bh,
				      handle_t *handle, int err)
{
	char nbuf[16];
	const char *errstr = ext4_decode_error(NULL, err, nbuf);

	BUG_ON(!ext4_handle_valid(handle));

	if (bh)
		BUFFER_TRACE(bh, "abort");

	if (!handle->h_err)
		handle->h_err = err;

	if (is_handle_aborted(handle))
		return;

	printk(KERN_ERR "EXT4-fs: %s:%d: aborting transaction: %s in %s\n",
	       caller, line, errstr, err_fn);

	jbd2_journal_abort_handle(handle);
}

int __ext4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_get_write_access(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
	}
	return err;
}

/*
 * The ext4 forget function must perform a revoke if we are freeing data
 * which has been journaled.  Metadata (eg. indirect blocks) must be
 * revoked in all cases.
 *
 * "bh" may be NULL: a metadata block may have been freed from memory
 * but there may still be a record of it in the journal, and that record
 * still needs to be revoked.
 *
 * If the handle isn't valid we're not journaling, but we still need to
 * call into ext4_journal_revoke() to put the buffer head.
 */
int __ext4_forget(const char *where, unsigned int line, handle_t *handle,
		  int is_metadata, struct inode *inode,
		  struct buffer_head *bh, ext4_fsblk_t blocknr)
{
	int err;

	might_sleep();

	trace_ext4_forget(inode, is_metadata, blocknr);
	BUFFER_TRACE(bh, "enter");

	jbd_debug(4, "forgetting bh %p: is_metadata = %d, mode %o, "
		  "data mode %x\n",
		  bh, is_metadata, inode->i_mode,
		  test_opt(inode->i_sb, DATA_FLAGS));

	/* In the no journal case, we can just do a bforget and return */
	if (!ext4_handle_valid(handle)) {
		bforget(bh);
		return 0;
	}

	/* Never use the revoke function if we are doing full data
	 * journaling: there is no need to, and a V1 superblock won't
	 * support it.  Otherwise, only skip the revoke on un-journaled
	 * data blocks. */

	if (test_opt(inode->i_sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA ||
	    (!is_metadata && !ext4_should_journal_data(inode))) {
		if (bh) {
			BUFFER_TRACE(bh, "call jbd2_journal_forget");
			err = jbd2_journal_forget(handle, bh);
			if (err)
				ext4_journal_abort_handle(where, line, __func__,
							  bh, handle, err);
			return err;
		}
		return 0;
	}

	/*
	 * data!=journal && (is_metadata || should_journal_data(inode))
	 */
	BUFFER_TRACE(bh, "call jbd2_journal_revoke");
	err = jbd2_journal_revoke(handle, blocknr, bh);
	if (err) {
		ext4_journal_abort_handle(where, line, __func__,
					  bh, handle, err);
		__ext4_abort(inode->i_sb, where, line,
			   "error %d when attempting revoke", err);
	}
	BUFFER_TRACE(bh, "exit");
	return err;
}

int __ext4_journal_get_create_access(const char *where, unsigned int line,
				handle_t *handle, struct buffer_head *bh)
{
	int err = 0;

	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_get_create_access(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	}
	return err;
}

int __ext4_handle_dirty_metadata(const char *where, unsigned int line,
				 handle_t *handle, struct inode *inode,
				 struct buffer_head *bh)
{
	int err = 0;

	might_sleep();

	set_buffer_meta(bh);
	set_buffer_prio(bh);
	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		/* Errors can only happen due to aborted journal or a nasty bug */
		if (!is_handle_aborted(handle) && WARN_ON_ONCE(err)) {
			ext4_journal_abort_handle(where, line, __func__, bh,
						  handle, err);
			if (inode == NULL) {
				pr_err("EXT4: jbd2_journal_dirty_metadata "
				       "failed: handle type %u started at "
				       "line %u, credits %u/%u, errcode %d",
				       handle->h_type,
				       handle->h_line_no,
				       handle->h_requested_credits,
				       handle->h_buffer_credits, err);
				return err;
			}
			ext4_error_inode(inode, where, line,
					 bh->b_blocknr,
					 "journal_dirty_metadata failed: "
					 "handle type %u started at line %u, "
					 "credits %u/%u, errcode %d",
					 handle->h_type,
					 handle->h_line_no,
					 handle->h_requested_credits,
					 handle->h_buffer_credits, err);
		}
	} else {
		if (inode)
			mark_buffer_dirty_inode(bh, inode);
		else
			mark_buffer_dirty(bh);
		if (inode && inode_needs_sync(inode)) {
			sync_dirty_buffer(bh);
			if (buffer_req(bh) && !buffer_uptodate(bh)) {
				struct ext4_super_block *es;

				es = EXT4_SB(inode->i_sb)->s_es;
				es->s_last_error_block =
					cpu_to_le64(bh->b_blocknr);
				ext4_error_inode(inode, where, line,
						 bh->b_blocknr,
					"IO error syncing itable block");
				err = -EIO;
			}
		}
	}
	return err;
}

int __ext4_handle_dirty_super(const char *where, unsigned int line,
			      handle_t *handle, struct super_block *sb)
{
	struct buffer_head *bh = EXT4_SB(sb)->s_sbh;
	int err = 0;

	ext4_superblock_csum_set(sb);
	if (ext4_handle_valid(handle)) {
		err = jbd2_journal_dirty_metadata(handle, bh);
		if (err)
			ext4_journal_abort_handle(where, line, __func__,
						  bh, handle, err);
	} else
		mark_buffer_dirty(bh);
	return err;
}

static struct kmem_cache *ext4_fc_dentry_cachep;

static inline
void ext4_reset_inode_fc_info(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	ei->i_fc_tid = 0;
	ei->i_fc_lblk_start = 0;
	ei->i_fc_lblk_end = 0;
	ei->i_fc_mdata_update = NULL;
	ext4_clear_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);
}

void ext4_init_inode_fc_info(struct inode *inode)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	ext4_reset_inode_fc_info(inode);
	INIT_LIST_HEAD(&ei->i_fc_list);
}

static void ext4_fc_enqueue_inode(struct inode *inode)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

	if (!ext4_should_fast_commit(inode->i_sb) ||
	    (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY))
		return;

	spin_lock(&sbi->s_fc_lock);
	if (list_empty(&EXT4_I(inode)->i_fc_list))
		list_add_tail(&EXT4_I(inode)->i_fc_list, &sbi->s_fc_q);
	spin_unlock(&sbi->s_fc_lock);
}

static inline tid_t get_running_txn_tid(struct super_block *sb)
{
	if (EXT4_SB(sb)->s_journal)
		return EXT4_SB(sb)->s_journal->j_commit_sequence + 1;
	return 0;
}

bool ext4_is_inode_fc_ineligible(struct inode *inode)
{
	if (get_running_txn_tid(inode->i_sb) == EXT4_I(inode)->i_fc_tid)
		return !ext4_test_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);
	return false;
}

void ext4_fc_mark_ineligible(struct inode *inode, int reason)
{
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct ext4_inode_info *ei = EXT4_I(inode);

	if (!ext4_should_fast_commit(inode->i_sb) ||
	    (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY))
		return;

	WARN_ON(reason >= EXT4_FC_REASON_MAX);
	sbi->s_fc_stats.fc_ineligible_reason_count[reason]++;
	if (sbi->s_journal)
		ei->i_fc_tid = get_running_txn_tid(inode->i_sb);
	ext4_clear_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);

	ext4_fc_enqueue_inode(inode);
}

void ext4_fc_disable(struct super_block *sb, int reason)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	sbi->s_mount_state |= EXT4_FC_INELIGIBLE;
	WARN_ON(reason >= EXT4_FC_REASON_MAX);
	sbi->s_fc_stats.fc_ineligible_reason_count[reason]++;
}

/*
 * Generic fast commit tracking function. If this is the first
 * time this we are called after a full commit, we initialize
 * fast commit fields and then call __fc_track_fn() with
 * update = 0. If we have already been called after a full commit,
 * we pass update = 1. Based on that, the track function can
 * determine if it needs to track a field for the first time
 * or if it needs to just update the previously tracked value.
 */
static int __ext4_fc_track_template(
	struct inode *inode,
	int (*__fc_track_fn)(struct inode *, void *, bool),
	void *args)
{
	tid_t running_txn_tid = get_running_txn_tid(inode->i_sb);
	bool update = false;
	struct ext4_inode_info *ei = EXT4_I(inode);
	int ret;

	if (!ext4_should_fast_commit(inode->i_sb) ||
	    (EXT4_SB(inode->i_sb)->s_mount_state & EXT4_FC_REPLAY))
		return -EOPNOTSUPP;

	write_lock(&ei->i_fc_lock);
	if (running_txn_tid == ei->i_fc_tid) {
		if (!ext4_test_inode_state(inode, EXT4_STATE_FC_ELIGIBLE)) {
			write_unlock(&ei->i_fc_lock);
			return -EINVAL;
		}
		update = true;
	} else {
		ext4_reset_inode_fc_info(inode);
		ei->i_fc_tid = running_txn_tid;
		ext4_set_inode_state(inode, EXT4_STATE_FC_ELIGIBLE);
	}
	ret = __fc_track_fn(inode, args, update);
	write_unlock(&ei->i_fc_lock);

	ext4_fc_enqueue_inode(inode);

	return ret;
}

struct __ext4_dentry_update_args {
	struct dentry *dentry;
	int op;
};

static int __ext4_dentry_update(struct inode *inode, void *arg, bool update)
{
	struct ext4_fc_dentry_update *node;
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct __ext4_dentry_update_args *dentry_update =
		(struct __ext4_dentry_update_args *)arg;
	struct dentry *dentry = dentry_update->dentry;

	write_unlock(&ei->i_fc_lock);
	node = kmem_cache_alloc(ext4_fc_dentry_cachep, GFP_NOFS);
	if (!node) {
		ext4_fc_disable(inode->i_sb, EXT4_FC_REASON_MEM);
		write_lock(&ei->i_fc_lock);
		return -ENOMEM;
	}

	node->fcd_op = dentry_update->op;
	node->fcd_parent = dentry->d_parent->d_inode->i_ino;
	node->fcd_ino = inode->i_ino;
	if (dentry->d_name.len > DNAME_INLINE_LEN) {
		node->fcd_name.name = kmalloc(dentry->d_name.len + 1,
						GFP_KERNEL);
		if (!node->fcd_iname) {
			kmem_cache_free(ext4_fc_dentry_cachep, node);
			return -ENOMEM;
		}
		memcpy((u8 *)node->fcd_name.name, dentry->d_name.name,
			dentry->d_name.len);
	} else {
		memcpy(node->fcd_iname, dentry->d_name.name,
			dentry->d_name.len);
		node->fcd_name.name = node->fcd_iname;
	}
	node->fcd_name.len = dentry->d_name.len;

	spin_lock(&EXT4_SB(inode->i_sb)->s_fc_lock);
	list_add_tail(&node->fcd_list, &EXT4_SB(inode->i_sb)->s_fc_dentry_q);
	spin_unlock(&EXT4_SB(inode->i_sb)->s_fc_lock);
	write_lock(&ei->i_fc_lock);
	EXT4_I(inode)->i_fc_mdata_update = node;

	return 0;
}

void ext4_fc_track_unlink(struct inode *inode, struct dentry *dentry)
{
	struct __ext4_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = EXT4_FC_TAG_DEL_DENTRY;

	ret = __ext4_fc_track_template(inode, __ext4_dentry_update,
				       (void *)&args);
	trace_ext4_fc_track_unlink(inode, dentry, ret);
}

void ext4_fc_track_link(struct inode *inode, struct dentry *dentry)
{
	struct __ext4_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = EXT4_FC_TAG_ADD_DENTRY;

	ret = __ext4_fc_track_template(inode, __ext4_dentry_update,
				       (void *)&args);
	trace_ext4_fc_track_link(inode, dentry, ret);
}

void ext4_fc_track_create(struct inode *inode, struct dentry *dentry)
{
	struct __ext4_dentry_update_args args;
	int ret;

	args.dentry = dentry;
	args.op = EXT4_FC_TAG_CREAT_DENTRY;

	ret = __ext4_fc_track_template(inode, __ext4_dentry_update,
				       (void *)&args);
	trace_ext4_fc_track_create(inode, dentry, ret);
}

static int __ext4_fc_add_inode(struct inode *inode, void *arg, bool update)
{
	struct ext4_inode_info *ei = EXT4_I(inode);

	if (update)
		return -EEXIST;

	ei->i_fc_lblk_start = (i_size_read(inode) - 1) >> inode->i_blkbits;
	ei->i_fc_lblk_end = (i_size_read(inode) - 1) >> inode->i_blkbits;

	return 0;
}

void ext4_fc_track_inode(struct inode *inode)
{
	int ret;

	ret = __ext4_fc_track_template(inode, __ext4_fc_add_inode, NULL);
	trace_ext4_fc_track_inode(inode, ret);
}

struct __ext4_fc_track_range_args {
	ext4_lblk_t start, end;
};

#define MIN(__a, __b)  ((__a) < (__b) ? (__a) : (__b))
#define MAX(__a, __b)  ((__a) > (__b) ? (__a) : (__b))

int __ext4_fc_track_range(struct inode *inode, void *arg, bool update)
{
	struct ext4_inode_info *ei = EXT4_I(inode);
	struct __ext4_fc_track_range_args *__arg =
		(struct __ext4_fc_track_range_args *)arg;

	if (inode->i_ino < EXT4_FIRST_INO(inode->i_sb)) {
		ext4_debug("Special inode %ld being modified\n", inode->i_ino);
		return -ECANCELED;
	}

	if (update) {
		ei->i_fc_lblk_start = MIN(ei->i_fc_lblk_start, __arg->start);
		ei->i_fc_lblk_end = MAX(ei->i_fc_lblk_end, __arg->end);
	} else {
		ei->i_fc_lblk_start = __arg->start;
		ei->i_fc_lblk_end = __arg->end;
	}

	return 0;
}

void ext4_fc_track_range(struct inode *inode, ext4_lblk_t start,
			 ext4_lblk_t end)
{
	struct __ext4_fc_track_range_args args;
	int ret;

	args.start = start;
	args.end = end;

	ret = __ext4_fc_track_template(inode,
					__ext4_fc_track_range, &args);

	trace_ext4_fc_track_range(inode, start, end, ret);
}

void ext4_init_fast_commit(struct super_block *sb, journal_t *journal)
{
	if (!ext4_should_fast_commit(sb))
		return;
	jbd2_init_fast_commit(journal, EXT4_NUM_FC_BLKS);
}

int __init ext4_init_fc_dentry_cache(void)
{
	ext4_fc_dentry_cachep = KMEM_CACHE(ext4_fc_dentry_update,
					   SLAB_RECLAIM_ACCOUNT);

	if (ext4_fc_dentry_cachep == NULL)
		return -ENOMEM;

	return 0;
}
