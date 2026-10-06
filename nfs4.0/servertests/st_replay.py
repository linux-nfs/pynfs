from xdrdef.nfs4_const import *
from .environment import check
from xdrdef.nfs4_type import *
import nfs_ops
op = nfs_ops.NFS4ops()

def _replay(env, c, ops, error=NFS4_OK, newconn=False):
    # Can send in an error list, but replays must return same error as orig
    if type(error) is list:
        check_funct = check
    else:
        check_funct = check
    res = c.compound(ops)
    check_funct(res, error, "Call to be replayed")
    error = res.status
    xid = c.xid
    orig_funct = c.get_new_xid
    try:
        c.get_new_xid = lambda : xid

        if newconn:
            c.reconnect_same_port()

        # note: this is really cheesy: we happen to know the current
        # Linux server implementation will drop a replay if it comes
        # "too quickly" (<.02 seconds).
        # Also, note no 4.0 client should really be replaying like this
        # without reconnecting first, so this test is really acting like
        # a buggy client and a server would probably be in its rights to
        # ignore these replays or return unexpected errors:

        env.sleep(.3)
        res = c.compound(ops)
        check(res, error, "Replay the first time")
        env.sleep(.3)
        res = c.compound(ops)
        check(res, error, "Replay the second time")
    finally:
        c.get_new_xid = orig_funct

def testOpen(t, env):
    """REPLAY: Send three OPEN calls with the same XID, SEQID, check DRC

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY1
    """
    c = env.c1
    c.init_connection()
    ops = c.use_obj(c.homedir)
    ops += [c.open(t.word(), type=OPEN4_CREATE), op.getfh()]
    _replay(env, c, ops)
    # Note that seqid is now off on this and other replay tests


def testReplayState1(t, env):
    """REPLAY an erroneous OPEN of a nonexistant file

    FLAGS: replay all
    DEPEND: MKDIR INIT
    CODE: RPLY2
    """
    c = env.c1
    c.init_connection()
    c.maketree([t.word()])
    ops = c.use_obj(c.homedir + [t.word()])
    ops += [c.open(t.word(), b'vapor'), op.getfh()]
    _replay(env, c, ops, NFS4ERR_NOENT)
    
def testReplayState2(t, env):
    """REPLAY an erroneous OPEN of a dir

    FLAGS: replay all
    DEPEND: MKDIR INIT
    CODE: RPLY3
    """
    c = env.c1
    c.init_connection()
    c.maketree([t.word()])
    ops = c.use_obj(c.homedir)
    ops += [c.open(t.word()), op.getfh()]
    _replay(env, c, ops, NFS4ERR_ISDIR)

def testReplayNonState(t, env):
    """REPLAY an erroneous LOOKUP

    FLAGS: replay all
    DEPEND: MKDIR
    CODE: RPLY4
    """
    c = env.c1
    c.maketree([t.word()])
    ops = c.use_obj(c.homedir + [t.word(), b'vapor'])
    _replay(env, c, ops, NFS4ERR_NOENT)

def testLock(t, env):
    """REPLAY a LOCK command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY5
    """
    c = env.c1
    c.init_connection()
    # Create a file and partially lock it
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res, msg="Locking file %s" % t.word())
    # Create and replay LOCK ops
    ops = c.use_obj(fh)
    lock_owner = exist_lock_owner4(res.lockid, 1)
    locker = locker4(FALSE, lock_owner=lock_owner)
    ops += [op.lock(WRITE_LT, FALSE, 0, 10, locker)]
    _replay(env, c, ops)
    
def testLockDenied(t, env):
    """REPLAY a LOCK command that fails

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY6
    """
    c = env.c1
    c.init_connection()
    # Create a file and lock it
    fh, stateid = c.create_confirm(t.word())
    res1 = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res1, msg="Locking file %s for first owner" % t.word())
    res2 = c.lock_file(t.word(), fh, stateid, 0, 10)
    check(res2, msg="Locking file %s for second owner" % t.word())
    # Create and replay LOCK ops
    ops = c.use_obj(fh)
    lock_owner = exist_lock_owner4(res1.lockid, 1)
    locker = locker4(FALSE, lock_owner=lock_owner)
    ops += [op.lock(WRITE_LT, FALSE, 0, 10, locker)]
    _replay(env, c, ops, NFS4ERR_DENIED)
    
def testUnlock(t, env):
    """REPLAY a LOCKU command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY7
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res, msg="Locking file %s" % t.word())
    ops = c.use_obj(fh)
    ops += [op.locku(READ_LT, 1, res.lockid, 0, 0xffffffffffffffff)]
    _replay(env, c, ops)

def testUnlockWait(t, env):
    """REPLAY a LOCKU command after lease has expired

    FLAGS: replay all timed
    DEPEND: MKFILE
    CODE: RPLY8
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    res = c.lock_file(t.word(), fh, stateid, 20, 100)
    check(res, msg="Locking file %s" % t.word())
    sleeptime = c.getLeaseTime() * 2
    env.sleep(sleeptime)
    ops = c.use_obj(fh)
    ops += [op.locku(READ_LT, 1, res.lockid, 0, 0xffffffffffffffff)]
    _replay(env, c, ops, [NFS4_OK, NFS4ERR_EXPIRED])

def testClose(t, env):
    """REPLAY a CLOSE command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY9
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    ops += [op.close(c.get_seqid(t.word()), stateid)]
    _replay(env, c, ops)
    
def testCloseWait(t, env):
    """REPLAY a CLOSE command after lease has expired

    FLAGS: replay all timed
    DEPEND: MKFILE
    CODE: RPLY10
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    sleeptime = c.getLeaseTime() * 2
    env.sleep(sleeptime)
    ops = c.use_obj(fh)
    ops += [op.close(c.get_seqid(t.word()), stateid)]
    _replay(env, c, ops, [NFS4_OK, NFS4ERR_EXPIRED])
    
def testCloseFail(t, env):
    """REPLAY a CLOSE command that fails

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY11
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh)
    ops += [op.close(c.get_seqid(t.word())+1, stateid)]
    _replay(env, c, ops, NFS4ERR_BAD_SEQID)
    
def testOpenConfirm(t, env):
    """REPLAY an OPEN_CONFIRM command

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY12
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    fh = res.resarray[-1].switch.switch.object
    stateid = res.resarray[-2].switch.switch.stateid
    rflags = res.resarray[-2].switch.switch.rflags
    if not rflags & OPEN4_RESULT_CONFIRM:
        t.pass_warn("OPEN did not require CONFIRM")
    ops = c.use_obj(fh)
    ops += [op.open_confirm(stateid, c.get_seqid(t.word()))]
    _replay(env, c, ops)
    
def testOpenConfirmFail(t, env):
    """REPLAY an OPEN_CONFIRM command that fails

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY13
    """
    c = env.c1
    c.init_connection()
    res = c.create_file(t.word())
    check(res)
    fh = res.resarray[-1].switch.switch.object
    stateid = res.resarray[-2].switch.switch.stateid
    rflags = res.resarray[-2].switch.switch.rflags
    if not rflags & OPEN4_RESULT_CONFIRM:
        t.pass_warn("OPEN did not require CONFIRM")
    ops = c.use_obj(fh)
    ops += [op.open_confirm(stateid, c.get_seqid(t.word())+1)]
    _replay(env, c, ops, NFS4ERR_BAD_SEQID)

def testMkdirReplay(t, env):
    """REPLAY a succesful directory CREATE

    FLAGS: replay all
    DEPEND: MKDIR
    CODE: RPLY14
    """
    c = env.c1
    c.init_connection()
    ops = c.go_home() + [op.create(createtype4(NF4DIR), t.word(), {})]
    _replay(env, c, ops, newconn=True)

#
# Stateowner replay cache (so_replay) tests. Each resends a
# seqid-mutating operation with the same seqid and a new xid, which
# bypasses the DRC (no OP_CACHEME operation in the COMPOUND) and
# reaches the per-owner replay cache.
#

def _pack_resop(c, resop):
    p = c.nfs4packer
    p.reset()
    p.pack_nfs_resop4(resop)
    return p.get_buffer()

def _resend(c, ops, error, msg):
    """Resend ops unchanged (same seqid, new xid) and check status"""
    res = c.compound(ops)
    check(res, error, msg)
    return res

def _old_stateid(stateid):
    return stateid4(0, stateid.other)

def testFailedOpenReplay(t, env):
    """REPLAY a failed OPEN (NOENT) by a confirmed owner, new xid

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY15
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    c.create_confirm(owner)
    missing = t.word() + b'_missing'
    ops = c.use_obj(c.homedir) + [c.open(owner, missing), op.getfh()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOENT, "OPEN of a missing name")
    c.advance_seqid(owner, res)
    # Create the name through another owner, so a re-executed OPEN
    # would now succeed
    c.create_confirm(t.word() + b'_owner2', path=c.homedir + [missing])
    _resend(c, ops, NFS4ERR_NOENT, "Resend of the failed OPEN")
    res = c.open_file(owner, c.homedir + [missing], deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="OPEN with seqid N+1 after the resend")

def testFailedOpenConfirmReplay(t, env):
    """REPLAY a failed OPEN_CONFIRM (OLD_STATEID), new xid

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY16
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    res = c.create_file(owner)
    check(res)
    fh = res.resarray[-1].switch.switch.object
    stateid = res.resarray[-2].switch.switch.stateid
    rflags = res.resarray[-2].switch.switch.rflags
    if not rflags & OPEN4_RESULT_CONFIRM:
        t.pass_warn("OPEN did not require CONFIRM")
    ops = [op.putfh(fh),
           op.open_confirm(_old_stateid(stateid), c.get_seqid(owner))]
    res = c.compound(ops)
    check(res, NFS4ERR_OLD_STATEID, "OPEN_CONFIRM with an old stateid")
    c.advance_seqid(owner, res)
    _resend(c, ops, NFS4ERR_OLD_STATEID, "Resend of the failed OPEN_CONFIRM")
    res = c.compound([op.putfh(fh),
                      op.open_confirm(stateid, c.get_seqid(owner))])
    check(res, msg="OPEN_CONFIRM with seqid N+1 after the resend")

def testFailedOpenDowngradeReplay(t, env):
    """REPLAY a failed OPEN_DOWNGRADE (INVAL), new xid

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY17
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    fh, stateid = c.create_confirm(owner, access=OPEN4_SHARE_ACCESS_READ,
                                   deny=OPEN4_SHARE_DENY_NONE)
    ops = [op.putfh(fh),
           op.open_downgrade(stateid, c.get_seqid(owner),
                             OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE)]
    res = c.compound(ops)
    check(res, NFS4ERR_INVAL, "OPEN_DOWNGRADE to a mode never opened")
    c.advance_seqid(owner, res)
    _resend(c, ops, NFS4ERR_INVAL, "Resend of the failed OPEN_DOWNGRADE")
    res = c.close_file(owner, fh, stateid)
    check(res, msg="CLOSE with seqid N+1 after the resend")

def testFailedCloseReplay(t, env):
    """REPLAY a failed CLOSE (OLD_STATEID), new xid

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY18
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    fh, stateid = c.create_confirm(owner)
    ops = [op.putfh(fh),
           op.close(c.get_seqid(owner), _old_stateid(stateid))]
    res = c.compound(ops)
    check(res, NFS4ERR_OLD_STATEID, "CLOSE with an old stateid")
    c.advance_seqid(owner, res)
    _resend(c, ops, NFS4ERR_OLD_STATEID, "Resend of the failed CLOSE")
    res = c.close_file(owner, fh, stateid)
    check(res, msg="CLOSE with seqid N+1 after the resend")

def testFailedUnlockReplay(t, env):
    """REPLAY a failed LOCKU (OLD_STATEID), new xid

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY19
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    fh, stateid = c.create_confirm(owner)
    res = c.lock_file(owner, fh, stateid, 20, 100)
    check(res, msg="Locking file")
    lockid = res.lockid
    ops = [op.putfh(fh),
           op.locku(READ_LT, 1, _old_stateid(lockid), 20, 100)]
    res = c.compound(ops)
    check(res, NFS4ERR_OLD_STATEID, "LOCKU with an old stateid")
    _resend(c, ops, NFS4ERR_OLD_STATEID, "Resend of the failed LOCKU")
    res = c.compound([op.putfh(fh), op.locku(READ_LT, 2, lockid, 20, 100)])
    check(res, msg="LOCKU with seqid N+1 after the resend")

def testSuccessfulOpenReplayNewXid(t, env):
    """REPLAY a successful OPEN by a confirmed owner, new xid; GETFH follows

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY20
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    fh, stateid = c.create_confirm(owner)
    dirfh = c.do_getfh(c.homedir)
    ops = [op.putfh(dirfh),
           c.open(owner, owner, deny=OPEN4_SHARE_DENY_NONE), op.getfh()]
    res1 = c.compound(ops)
    check(res1, msg="Second OPEN of the file")
    c.advance_seqid(owner, res1)
    res2 = _resend(c, ops, NFS4_OK, "Resend of the successful OPEN")
    if _pack_resop(c, res1.resarray[-2]) != _pack_resop(c, res2.resarray[-2]):
        t.fail("Resend did not return the original OPEN result")
    fh2 = res2.resarray[-1].switch.switch.object
    if fh2 != fh:
        if fh2 == dirfh:
            t.fail("GETFH after the replayed OPEN returned the directory's handle")
        t.fail("GETFH after the replayed OPEN returned a different handle")

def testFailedFirstOpenReplay(t, env):
    """REPLAY a failed first OPEN (NOENT) by a new owner, new xid

    FLAGS: replay all
    DEPEND: MKDIR
    CODE: RPLY21
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    ops = c.use_obj(c.homedir) + [c.open(owner, t.word() + b'_missing'),
                                  op.getfh()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOENT, "First OPEN of a missing name")
    c.advance_seqid(owner, res)
    _resend(c, ops, NFS4ERR_NOENT, "Resend of the failed first OPEN")

def testFailedOpenReplayStaleFh(t, env):
    """REPLAY a failed OPEN after the owner's last opened file is removed

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY22
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    # A second open keeps the owner alive across the CLOSE below;
    # with no stateid left, the next OPEN gets a fresh owner and
    # the resend executes instead of replaying.
    c.create_confirm(owner, path=c.homedir + [t.word() + b'_keep'])
    fh, stateid = c.create_confirm(owner)
    res = c.close_file(owner, fh, stateid)
    check(res, msg="CLOSE")
    res = c.compound(c.use_obj(c.homedir) + [op.remove(owner)])
    check(res, msg="REMOVE of the opened file")
    ops = c.use_obj(c.homedir) + [c.open(owner, t.word() + b'_missing'),
                                  op.getfh()]
    res = c.compound(ops)
    check(res, NFS4ERR_NOENT, "OPEN of a missing name")
    c.advance_seqid(owner, res)
    _resend(c, ops, NFS4ERR_NOENT, "Resend of the failed OPEN")

def testFailedOpenReplaySymlink(t, env):
    """REPLAY a failed OPEN of a symlink (SYMLINK, a mapped status)

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY23
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    c.create_confirm(owner)
    link = t.word() + b'_link'
    res = c.create_obj(c.homedir + [link], NF4LNK)
    check(res, msg="CREATE symlink")
    ops = c.use_obj(c.homedir) + [c.open(owner, link), op.getfh()]
    res = c.compound(ops)
    check(res, NFS4ERR_SYMLINK, "OPEN of a symlink")
    c.advance_seqid(owner, res)
    _resend(c, ops, NFS4ERR_SYMLINK, "Resend of the failed OPEN")
    res = c.open_file(owner, deny=OPEN4_SHARE_DENY_NONE)
    check(res, msg="OPEN with seqid N+1 after the resend")

def _lock_ops(c, fh, owner, openstateid, lockowner, offset, length):
    oo = open_to_lock_owner4(c.get_seqid(owner), openstateid, 0,
                             lock_owner4(c.clientid, lockowner))
    return [op.putfh(fh),
            op.lock(WRITE_LT, FALSE, offset, length, locker4(TRUE, open_owner=oo))]

def testLockReplayNewXid(t, env):
    """REPLAY successful and denied LOCKs (new-lock-owner arm), new xid

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY24
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    fh, stateid = c.create_confirm(owner)
    # The lock-owner's first LOCK, resent
    ops = _lock_ops(c, fh, owner, stateid, b'first', 0, 10)
    res1 = c.compound(ops)
    check(res1, msg="LOCK by a new lock-owner")
    c.advance_seqid(owner, res1)
    res2 = _resend(c, ops, NFS4_OK, "Resend of the successful LOCK")
    if _pack_resop(c, res1.resarray[-1]) != _pack_resop(c, res2.resarray[-1]):
        t.fail("Resend did not return the original LOCK result")
    # Denied by a small conflicting owner, then by a large one
    for name in [b'first', b'L' * 200]:
        if name != b'first':
            ops = _lock_ops(c, fh, owner, stateid, name, 100, 10)
            res = c.compound(ops)
            check(res, msg="LOCK by the large-named lock-owner")
            c.advance_seqid(owner, res)
            off = 100
        else:
            off = 0
        ops = _lock_ops(c, fh, owner, stateid, b'loser_' + name[:8], off, 10)
        res1 = c.compound(ops)
        check(res1, NFS4ERR_DENIED, "Conflicting LOCK")
        c.advance_seqid(owner, res1)
        res2 = _resend(c, ops, NFS4ERR_DENIED, "Resend of the denied LOCK")
        if _pack_resop(c, res1.resarray[-1]) != _pack_resop(c, res2.resarray[-1]):
            t.fail("Resend did not return the original LOCK denial (owner %d bytes)" % len(name))

def testFailedUnlockReplaysLargeDenial(t, env):
    """REPLAY a failed LOCKU after a large denial on the same lock-owner

    FLAGS: replay all
    DEPEND: MKFILE
    CODE: RPLY25
    """
    c = env.c1
    c.init_connection()
    owner = t.word()
    fh, stateid = c.create_confirm(owner)
    # Holder with a large owner name, so the denial body exceeds
    # NFSD4_REPLAY_ISIZE
    res = c.compound(_lock_ops(c, fh, owner, stateid, b'H' * 200, 100, 10))
    check(res, msg="LOCK by the holder")
    c.advance_seqid(owner, res)
    # The tested lock-owner: a successful first LOCK
    res = c.compound(_lock_ops(c, fh, owner, stateid, b'tested', 0, 10))
    check(res, msg="LOCK by the tested lock-owner")
    c.advance_seqid(owner, res)
    lockid = res.resarray[-1].switch.switch.lock_stateid
    # A denied LOCK through the existing-lock-owner arm
    locker = locker4(FALSE, lock_owner=exist_lock_owner4(lockid, 1))
    res = c.compound([op.putfh(fh), op.lock(WRITE_LT, FALSE, 100, 10, locker)])
    check(res, NFS4ERR_DENIED, "Conflicting LOCK by the tested lock-owner")
    denial = _pack_resop(c, res.resarray[-1])
    if len(denial) <= 112 + 8:
        t.fail("Encoded denial is %d bytes, not above NFSD4_REPLAY_ISIZE" % len(denial))
    # A failing LOCKU by the same lock-owner, then its resend
    ops = [op.putfh(fh), op.locku(READ_LT, 2, _old_stateid(lockid), 0, 10)]
    res = c.compound(ops)
    check(res, NFS4ERR_OLD_STATEID, "LOCKU with an old stateid")
    _resend(c, ops, NFS4ERR_OLD_STATEID, "Resend of the failed LOCKU")
    res = c.compound([op.putfh(fh), op.locku(READ_LT, 3, lockid, 0, 10)])
    check(res, msg="LOCKU with seqid N+1 after the resend")
