from .st_create_session import create_session
from .st_open import open_claim4
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file, do_getattrdict, close_file, write_file, read_file, compareTimes
from xdrdef.nfs4_type import *
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4lib
import threading
import copy
import time

def _got_deleg(deleg):
    return (deleg.delegation_type != OPEN_DELEGATE_NONE and
            deleg.delegation_type != OPEN_DELEGATE_NONE_EXT)

def __create_file_with_deleg(sess, name, access):
    res = create_file(sess, name, access = access)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    deleg = res.resarray[-2].delegation
    if (not _got_deleg(deleg)):
        res = open_file(sess, name, access = access)
        fh = res.resarray[-1].object
        stateid = res.resarray[-2].stateid
        deleg = res.resarray[-2].delegation
        if (not _got_deleg(deleg)):
            fail("Could not get delegation")
    return (fh, stateid, deleg)

def _create_file_with_deleg(sess, name, access):
    fh, stateid, deleg = __create_file_with_deleg(sess, name, access)
    return (fh, stateid)

def _testDeleg(t, env, openaccess, want, breakaccess, sec = None, sec2 = None):
    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid # NOTE this must be done before set()
        recall.cred = env.cred.raw_cred
        env.notify = recall.set # This is called after compound sent to queue
    def post_hook(arg, env, res):
        return res
    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t), sec = sec)
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)
    if sec2:
        sess1.compound([op.backchannel_ctl(env.c1.prog, sec2)])
    fh, stateid = _create_file_with_deleg(sess1, env.testname(t), openaccess | want)
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, breakaccess, OPEN4_SHARE_DENY_NONE, owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op])
    # Wait for recall, and return delegation
    completed = recall.wait(2)
    # Getting here means CB_RECALL reply is in the send queue.
    # Give it a moment to actually be sent
    env.sleep(.1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(recall.stateid)])
    check(res)
    # Now get OPEN reply
    res = sess2.listen(slot)
    check(res, [NFS4_OK, NFS4ERR_DELAY])
    if not completed:
        fail("delegation break not received")
    close_file(sess1, fh, stateid=stateid)
    return recall

def testReadDeleg(t, env):
    """Test read delegation handout and return

    FLAGS: open deleg all
    CODE: DELEG1
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH)

def testWriteDeleg(t, env):
    """Test write delegation handout and return

    FLAGS: writedelegations deleg all
    CODE: DELEG2
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ|OPEN4_SHARE_ACCESS_WRITE,
       OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG, OPEN4_SHARE_ACCESS_READ)

def testAnyDeleg(t, env):
    """Test any delegation handout and return

    FLAGS: open deleg all
    CODE: DELEG3
    """
    _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_ANY_DELEG, OPEN4_SHARE_ACCESS_BOTH);

def testNoDeleg(t, env):
    """Test no delegation handout

    FLAGS: open deleg all
    CODE: DELEG4
    """
    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    res = create_file(sess1, env.testname(t),
                      access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    deleg = res.resarray[-2].delegation
    if deleg.delegation_type == OPEN_DELEGATE_NONE:
        fail("Got no delegation, expected OPEN_DELEGATE_NONE_EXT")
    if deleg.delegation_type != OPEN_DELEGATE_NONE_EXT:
        fail("Got a delegation (type "+str(deleg.delegation_type)+") despite asking for none")
    if deleg.ond_why != WND4_NOT_WANTED:
        fail("Wrong reason ("+str(deleg.ond_why)+") for giving no delegation")
    close_file(sess1, fh, stateid=stateid)


def testCBSecParms(t, env):
    """Test auth_sys callbacks

    FLAGS: create_session open deleg all
    CODE: DELEG5
    """
    uid = 17
    gid = 19
    sys_cred = authsys_parms(13, b"fake name", uid, gid, [])
    recall = _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH,
        sec = [callback_sec_parms4(AUTH_SYS, sys_cred)])
    if recall.cred.body.uid != uid or recall.cred.body.gid != gid:
        fail("expected callback with uid, gid == %d, %d, got %d, %d"
                % (uid, gid, recall.cred.body.uid, recall.cred.body.gid))

def testCBSecParmsNull(t, env):
    """Test auth_null callbacks

    FLAGS: create_session open deleg all
    CODE: DELEG6
    """
    recall = _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH,
        sec = [callback_sec_parms4(AUTH_NONE)])
    if recall.cred.flavor != AUTH_NONE:
        fail("expected callback flavor %d, got %d"
                % (AUTH_NONE, recall.cred.flavor))

def testCBSecParmsChange(t, env):
    """Test changing of auth_sys callbacks with backchannel_ctl

    FLAGS: create_session open deleg backchannel_ctl all
    CODE: DELEG7
    """
    uid1 = 17
    gid1 = 19
    sys_cred1 = cbsp_sy_cred = authsys_parms(13, b"fake name", uid1, gid1, [])
    uid2 = 29
    gid2 = 31
    sys_cred2 = cbsp_sy_cred = authsys_parms(13, b"fake name", uid2, gid2, [])
    recall = _testDeleg(t, env, OPEN4_SHARE_ACCESS_READ,
        OPEN4_SHARE_ACCESS_WANT_READ_DELEG, OPEN4_SHARE_ACCESS_BOTH,
        sec  = [callback_sec_parms4(AUTH_SYS, sys_cred1)],
        sec2 = [callback_sec_parms4(AUTH_SYS, sys_cred2)])
    if recall.cred.body.uid != uid2 or recall.cred.body.gid != gid2:
        fail("expected callback with uid, gid == %d, %d, got %d, %d"
                % (uid2, gid2, recall.cred.body.uid, recall.cred.body.gid))

def testDelegRevocation(t, env):
    """Allow a delegation to be revoked, check that TEST_STATEID and
       FREE_STATEID have the required effect.

    FLAGS: deleg all
    CODE: DELEG8
    """

    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    fh, stateid, deleg = __create_file_with_deleg(sess1, env.testname(t),
            OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    delegstateid = deleg.read.stateid
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"My Open Owner 2")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_WRITE, OPEN4_SHARE_DENY_NONE,
                        owner, how, claim)
    while 1:
        res = sess2.compound(env.home + [open_op, op.getfh()])
        if res.status == NFS4_OK:
            break;
        check(res, [NFS4_OK, NFS4ERR_DELAY])
        # just to keep sess1 renewed.  This is a bit fragile, as we
        # depend on the above compound waiting no longer than the
        # server's lease period:
        res = sess1.compound([])
    if res.status == NFS4_OK:
        fh2 = res.resarray[-1].object
        stateid2 = res.resarray[-2].stateid
    else:
        fh2 = None
        stateid2 = None
    res = sess1.compound([op.putfh(fh), op.read(delegstateid, 0, 1000)])
    check(res, NFS4ERR_DELEG_REVOKED, "Read with a revoked delegation")
    slot, seq_op = sess1._prepare_compound({})
    res = sess1.c.compound([seq_op])
    flags = res.resarray[0].sr_status_flags;
    if not(flags & SEQ4_STATUS_RECALLABLE_STATE_REVOKED):
        fail("SEQ4_STATUS_RECALLABLE_STATE_REVOKED should be set after"
             " sucess of open conflicting with delegation")
    flags &= ~SEQ4_STATUS_RECALLABLE_STATE_REVOKED
    if flags:
        print("WARNING: unexpected status flag(s) 0x%x set" % flags);
    res = sess1.update_seq_state(res, slot)
    res = sess1.compound([op.test_stateid([delegstateid])])
    stateid_stat = res.resarray[0].tsr_status_codes[0]
    if stateid_stat != NFS4ERR_DELEG_REVOKED:
        fail("TEST_STATEID on revoked stateid should report status"
             " NFS4ERR_DELEG_REVOKED, instead got %s" %
             nfsstat4[stateid_stat]);
    res = sess1.compound([op.free_stateid(delegstateid)])
    check(res)
    slot, seq_op = sess1._prepare_compound({})
    res = sess1.c.compound([seq_op])
    flags = res.resarray[0].sr_status_flags
    if flags & SEQ4_STATUS_RECALLABLE_STATE_REVOKED:
        fail("SEQ4_STATUS_RECALLABLE_STATE_REVOKED should be cleared after"
             " FREE_STATEID")
    if flags & ~SEQ4_STATUS_RECALLABLE_STATE_REVOKED:
        print("WARNING: unexpected status flag(s) 0x%x set" % flags)

    close_file(sess1, fh, stateid=stateid)
    if fh2 is not None and stateid2 is not None:
        close_file(sess2, fh2, stateid=stateid2)

def testWriteOpenvsReadDeleg(t, env):
    """Ensure that a write open prevents granting a read delegation

    FLAGS: deleg all
    CODE: DELEG9
    """

    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    owner = b"owner_%s" % env.testname(t)
    res = create_file(sess1, owner, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    access = OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG;
    res = open_file(sess2, owner, access = access)
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid

    deleg = res.resarray[-2].delegation
    if (not _got_deleg(deleg)):
        res = open_file(sess2, owner, access = access)
        fh2 = res.resarray[-1].object
        stateid2 = res.resarray[-2].stateid
        deleg = res.resarray[-2].delegation
    if (_got_deleg(deleg)):
        fail("Granted delegation to a file write-opened by another client")

    close_file(sess1, fh, stateid=stateid)
    close_file(sess2, fh2, stateid=stateid2)

def testServerSelfConflict3(t, env):
    """DELEGATION test

    Get a read delegation, then do a write open from the same client.
    That should succeed.  Then do a write open from a different client,
    and verify that it breaks the delegation.

    FLAGS: deleg all
    CODE: DELEG23
    """

    recall = threading.Event()
    def pre_hook(arg, env):
        recall.stateid = arg.stateid
        recall.cred = env.cred.raw_cred
        env.notify = recall.set
    def post_hook(arg, env, res):
        return res
    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)

    fh, stateid, deleg = __create_file_with_deleg(sess1, env.testname(t),
            OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    delegstateid = deleg.read.stateid
    res = open_file(sess1, env.testname(t), access = OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # XXX: cut-n-paste from _testDeleg; make helper instead:
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))

    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"owner")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_WRITE,
                      OPEN4_SHARE_DENY_NONE, owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op, op.getfh()])
    completed = recall.wait(2)
    env.sleep(.1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(delegstateid)])
    check(res)
    res = sess2.listen(slot)
    check(res, [NFS4_OK, NFS4ERR_DELAY])
    if res.status == NFS4_OK:
        fh2 = res.resarray[-1].object
        stateid2 = res.resarray[-2].stateid
    else:
        fh2 = None
        stateid2 = None
    if not completed:
        fail("delegation break not received")

    close_file(sess1, fh, stateid=stateid)
    if fh2 is not None and stateid2 is not None:
        close_file(sess2, fh2, stateid=stateid2)

def _testCbGetattr(t, env, change=0, size=0):
    cb = threading.Event()
    cbattrs = {}
    def getattr_post_hook(arg, env, res):
        res.obj_attributes = cbattrs
        env.notify = cb.set
        return res

    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    sess1.client.cb_post_hook(OP_CB_GETATTR, getattr_post_hook)

    res = sess1.compound([op.putrootfh(),
                          op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS,
                                                          FATTR4_OPEN_ARGUMENTS]))])
    check(res)
    caps = res.resarray[-1].obj_attributes

    openmask = (OPEN4_SHARE_ACCESS_READ  |
                OPEN4_SHARE_ACCESS_WRITE |
                OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG)

    if caps[FATTR4_SUPPORTED_ATTRS] & (1 << FATTR4_OPEN_ARGUMENTS):
        if caps[FATTR4_OPEN_ARGUMENTS].oa_share_access_want & OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS:
            openmask |= 1<<OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS

    fh, stateid, deleg = __create_file_with_deleg(sess1, env.testname(t), openmask)
    delegtype = deleg.delegation_type
    if delegtype != OPEN_DELEGATE_WRITE_ATTRS_DELEG and delegtype != OPEN_DELEGATE_WRITE:
        fail("Didn't get a write delegation.")
    attrs1 = do_getattrdict(sess1, fh, [FATTR4_CHANGE, FATTR4_SIZE,
                                        FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY])

    cbattrs[FATTR4_CHANGE] = attrs1[FATTR4_CHANGE]
    cbattrs[FATTR4_SIZE] = attrs1[FATTR4_SIZE]

    if change != 0:
        cbattrs[FATTR4_CHANGE] += 1
        if size > 0:
            cbattrs[FATTR4_SIZE] = size

    if delegtype == OPEN_DELEGATE_WRITE_ATTRS_DELEG:
        cbattrs[FATTR4_TIME_DELEG_ACCESS] = nfstime4(attrs1[FATTR4_TIME_ACCESS].seconds,
                                                     attrs1[FATTR4_TIME_ACCESS].nseconds)
        cbattrs[FATTR4_TIME_DELEG_MODIFY] = nfstime4(attrs1[FATTR4_TIME_MODIFY].seconds,
                                                     attrs1[FATTR4_TIME_MODIFY].nseconds)
        if change != 0:
            cbattrs[FATTR4_TIME_DELEG_ACCESS].seconds += 1
            cbattrs[FATTR4_TIME_DELEG_MODIFY].seconds += 1

    # create a new client session and do a GETATTR
    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    slot = sess2.compound_async([op.putfh(fh), op.getattr(1<<FATTR4_CHANGE | 1<<FATTR4_SIZE |
                                                          1<<FATTR4_TIME_ACCESS | 1<<FATTR4_TIME_MODIFY)])

    # wait for the CB_GETATTR
    completed = cb.wait(2)
    res = sess2.listen(slot)
    attrs2 = res.resarray[-1].obj_attributes
    sess1.compound([op.putfh(fh), op.delegreturn(deleg.write.stateid)])
    check(res, [NFS4_OK, NFS4ERR_DELAY])
    if not completed:
        fail("CB_GETATTR not received")
    close_file(sess1, fh, stateid=stateid)
    return attrs1, attrs2

def testCbGetattrNoChange(t, env):
    """Test CB_GETATTR with no changes

    Get a write delegation, then do a getattr from a second client. Have the
    client regurgitate back the same attrs (indicating no changes). Then test
    that the attrs that the second client gets back match the first.

    FLAGS: deleg all
    CODE: DELEG24
    """
    attrs1, attrs2 = _testCbGetattr(t, env)
    if attrs1[FATTR4_SIZE] != attrs2[FATTR4_SIZE]:
        fail(f"Bad size: {attrs1[FATTR4_SIZE]} != {attrs2[FATTR4_SIZE]}")
    if attrs1[FATTR4_CHANGE] != attrs2[FATTR4_CHANGE]:
        fail(f"Bad change attribute: {attrs1[FATTR4_CHANGE]} != {attrs2[FATTR4_CHANGE]}")
    if compareTimes(attrs1[FATTR4_TIME_MODIFY], attrs2[FATTR4_TIME_MODIFY]) != 0:
        fail(f"Bad modify time: {attrs1[FATTR4_TIME_MODIFY]} != {attrs2[FATTR4_TIME_MODIFY]}")

def testCbGetattrWithChange(t, env):
    """Test CB_GETATTR with simulated changes to file

    Get a write delegation, then do a getattr from a second client. Modify the
    attrs before sending them back to the server. Test that the second client
    sees different attrs than the original one.

    FLAGS: deleg all
    CODE: DELEG25
    """
    attrs1, attrs2 = _testCbGetattr(t, env, change=1, size=5)
    if attrs2[FATTR4_SIZE] != 5:
        fail(f"Bad size: {attrs2[FATTR4_SIZE]} != 5")
    if attrs1[FATTR4_CHANGE] == attrs2[FATTR4_CHANGE]:
        fail(f"Bad change attribute: {attrs1[FATTR4_CHANGE]} == {attrs2[FATTR4_CHANGE]}")
    if compareTimes(attrs1[FATTR4_TIME_MODIFY], attrs2[FATTR4_TIME_MODIFY]) == 0:
        fail(f"Bad modify time: {attrs1[FATTR4_TIME_MODIFY]} == {attrs2[FATTR4_TIME_MODIFY]}")

def testDelegReadAfterClose(t, env):
    """Test read with delegation stateid after close

    Create file with some data. Open the file for read, get delegation, close the file.
    Tesr that reads with delegation stateid still works.

    FLAGS: deleg all
    CODE: DELEG26
    """
    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))

    name = env.testname(t)
    owner = b"owner_%s" % name

    # create file with some data
    res = create_file(sess1, owner)
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    res = write_file(sess1, fh, b'data', 0, stateid)
    check(res)

    res = close_file(sess1, fh, stateid=stateid)
    check(res)


    # open file, get delegation, close the file
    access = OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG;
    res = open_file(sess1, owner, access = access)
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    if not _got_deleg(res.resarray[-2].delegation):
        fail("Failed to get delegation")
    delegstateid = res.resarray[-2].delegation.read.stateid

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

    # Issue READ with delegation stateid
    res = read_file(sess1, fh, 0, 10, delegstateid)
    check(res)

    # cleanup: return delegation
    res = sess1.compound([op.putfh(fh), op.delegreturn(delegstateid)])
    check(res)

def testCbGetattrAfterSyncWrite(t, env):
    """Test CB_GETATTR after a FILE_SYNC4 WRITE

    1. Client 1 opens a file (getting a write deleg or a write attrs deleg) and
       does a GETATTR
    2. Client 1 does a FILE_SYNC4 WRITE.  If we got a write delegation, it
       follows this up with a GETATTR.  Otherwise we got a write attrs deleg
       and we construct the attrs ourself.
    3. Client 2 does a GETATTR, triggering a CB_GETATTR to client 1.  Client 2
       then does an OPEN, triggering a CB_RECALL to client 1.
    4. Client 1 does a PUTFH|SETATTR|GETATTR|DELEGRETURN if we have a write
       attrs deleg, otherwise it does a PUTFH|GETATTR|DELEGRETURN.

    time_modify should only change between steps 1 and 2.  It should not change
    from steps 2 thru 4.

    FLAGS: deleg all
    CODE: DELEG27
    """
    cb = threading.Event()
    cbattrs = {}
    def getattr_post_hook(arg, env, res):
        res.obj_attributes = cbattrs
        env.notify = cb.set
        return res

    recall = threading.Event()
    def recall_pre_hook(arg, env):
        recall.stateid = arg.stateid
        recall.cred = env.cred.raw_cred
        env.notify = recall.set
    def recall_post_hook(arg, env, res):
        return res

    size = 5

    sess1 = env.c1.new_client_session(b"%s_1" % env.testname(t))
    sess1.client.cb_post_hook(OP_CB_GETATTR, getattr_post_hook)
    sess1.client.cb_pre_hook(OP_CB_RECALL, recall_pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, recall_post_hook)

    res = sess1.compound([op.putrootfh(),
                          op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS,
                                                          FATTR4_OPEN_ARGUMENTS]))])
    check(res)
    caps = res.resarray[-1].obj_attributes

    openmask = (OPEN4_SHARE_ACCESS_READ  |
                OPEN4_SHARE_ACCESS_WRITE |
                OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG)

    if caps[FATTR4_SUPPORTED_ATTRS] & (1 << FATTR4_OPEN_ARGUMENTS):
        if caps[FATTR4_OPEN_ARGUMENTS].oa_share_access_want & (1 << OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS):
            openmask |= 1<<OPEN_ARGS_SHARE_ACCESS_WANT_DELEG_TIMESTAMPS

    fh, stateid, deleg = __create_file_with_deleg(sess1, env.testname(t), openmask)
    delegtype = deleg.delegation_type
    if delegtype != OPEN_DELEGATE_WRITE_ATTRS_DELEG and delegtype != OPEN_DELEGATE_WRITE:
        fail("Didn't get a write delegation.")
    delegstateid = deleg.write.stateid

    attrs1 = do_getattrdict(sess1, fh, [FATTR4_CHANGE, FATTR4_SIZE,
                                        FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY])

    cbattrs[FATTR4_CHANGE] = attrs1[FATTR4_CHANGE]
    cbattrs[FATTR4_SIZE] = attrs1[FATTR4_SIZE]

    env.sleep(1)
    res = write_file(sess1, fh, b'z' * size, 0, delegstateid)
    check(res)

    if delegtype == OPEN_DELEGATE_WRITE_ATTRS_DELEG:
        attrs2 = copy.deepcopy(attrs1)
        now = divmod(time.time_ns(), 1000000000)
        attrs2[FATTR4_TIME_ACCESS] = nfstime4(*now)
        attrs2[FATTR4_TIME_MODIFY] = nfstime4(*now)
        cbattrs[FATTR4_TIME_DELEG_ACCESS] = nfstime4(*now)
        cbattrs[FATTR4_TIME_DELEG_MODIFY] = nfstime4(*now)
    else:
        attrs2 = do_getattrdict(sess1, fh, [FATTR4_CHANGE, FATTR4_SIZE,
                                            FATTR4_TIME_ACCESS, FATTR4_TIME_MODIFY])

    # No need to bump FATTR4_CHANGE because we've already flushed our data
    cbattrs[FATTR4_SIZE] = size

    sess2 = env.c1.new_client_session(b"%s_2" % env.testname(t))
    slot = sess2.compound_async([op.putfh(fh),
                                 op.getattr(1<<FATTR4_CHANGE |
                                            1<<FATTR4_SIZE |
                                            1<<FATTR4_TIME_ACCESS |
                                            1<<FATTR4_TIME_MODIFY)])

    completed = cb.wait(2)
    if not completed:
        fail("CB_GETATTR not received")

    res = sess2.listen(slot)
    check(res)
    attrs3 = res.resarray[-1].obj_attributes

    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"owner")
    how = openflag4(OPEN4_NOCREATE)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_WRITE,
                      OPEN4_SHARE_DENY_NONE, owner, how, claim)
    slot = sess2.compound_async(env.home + [open_op, op.getfh()])
    completed = recall.wait(2)
    if not completed:
        fail("CB_RECALL not received")

    env.sleep(.1)

    # Note if we have a write attrs deleg we should do a setattr before the
    # delegreturn (see RFC 9754, section 5)
    res = sess1.compound([op.putfh(fh),
                          *([op.setattr(delegstateid,
                                        {FATTR4_TIME_DELEG_ACCESS: cbattrs[FATTR4_TIME_DELEG_ACCESS],
                                         FATTR4_TIME_DELEG_MODIFY: cbattrs[FATTR4_TIME_DELEG_MODIFY]})]
                              if delegtype == OPEN_DELEGATE_WRITE_ATTRS_DELEG else []),
                          op.getattr(1<<FATTR4_CHANGE |
                                     1<<FATTR4_SIZE |
                                     1<<FATTR4_TIME_ACCESS |
                                     1<<FATTR4_TIME_MODIFY),
                          op.delegreturn(delegstateid)])
    check(res)
    attrs4 = res.resarray[-2].obj_attributes

    res = sess2.listen(slot)
    check(res, [NFS4_OK, NFS4ERR_DELAY])
    if res.status == NFS4_OK:
        fh2 = res.resarray[-1].object
        stateid2 = res.resarray[-2].stateid
    else:
        fh2 = None
        stateid2 = None

    close_file(sess1, fh, stateid=stateid)
    if fh2 is not None and stateid2 is not None:
        close_file(sess2, fh2, stateid=stateid2)

    #print(f"attrs1: size {attrs1[FATTR4_SIZE]} change {attrs1[FATTR4_CHANGE]} mtime {attrs1[FATTR4_TIME_MODIFY]}")
    #print(f"attrs2: size {attrs2[FATTR4_SIZE]} change {attrs2[FATTR4_CHANGE]} mtime {attrs2[FATTR4_TIME_MODIFY]}")
    #print(f"attrs3: size {attrs3[FATTR4_SIZE]} change {attrs3[FATTR4_CHANGE]} mtime {attrs3[FATTR4_TIME_MODIFY]}")
    #print(f"attrs4: size {attrs4[FATTR4_SIZE]} change {attrs4[FATTR4_CHANGE]} mtime {attrs4[FATTR4_TIME_MODIFY]}")

    if compareTimes(attrs2[FATTR4_TIME_MODIFY], attrs4[FATTR4_TIME_MODIFY]) != 0:
        fail(f"mtime after write ({attrs2[FATTR4_TIME_MODIFY]}) != "
             f"mtime from delegreturn ({attrs4[FATTR4_TIME_MODIFY]})")

def _open_claim_fh(sess, fh, owner, access):
    """OPEN by filehandle. No GETFH follows, so OPEN is the last result."""
    open_op = op.open(0, access, OPEN4_SHARE_DENY_NONE, open_owner4(0, owner),
                      openflag4(OPEN4_NOCREATE), open_claim4(CLAIM_FH))
    return sess.compound([op.putfh(fh), open_op])

def _open_claim_fh_retry(sess, fh, owner, access):
    """Send OPEN(CLAIM_FH) again if the first reply carries no delegation

    The first OPEN after CREATE_SESSION can race the server's backchannel
    probe.
    """
    res = _open_claim_fh(sess, fh, owner, access)
    check(res)
    if not _got_deleg(res.resarray[-1].delegation):
        res = _open_claim_fh(sess, fh, owner, access)
        check(res)
    return res

def _delegreturn(sess, fh, deleg):
    """Return the delegation, if OPEN granted one"""
    if _got_deleg(deleg):
        res = sess.compound([op.putfh(fh), op.delegreturn(deleg.stateid)])
        check(res)

def _deleg_desc(deleg):
    desc = "%s" % open_delegation_type4.get(deleg.delegation_type,
                                            deleg.delegation_type)
    if deleg.delegation_type == OPEN_DELEGATE_NONE_EXT:
        desc += ", ond_why %s" % why_no_delegation4.get(deleg.ond_why,
                                                        deleg.ond_why)
    return desc

def testClaimFHReadDeleg(t, env):
    """OPEN(CLAIM_FH) with WANT_READ_DELEG on a file with no open state

    FLAGS: open deleg all
    CODE: DELEG28
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(b"%s_1" % name)
    res = create_file(sess1, name, access=OPEN4_SHARE_ACCESS_BOTH |
                      OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh = res.resarray[-1].object
    res = close_file(sess1, fh, stateid=res.resarray[-2].stateid)
    check(res)

    res = _open_claim_fh_retry(sess1, fh, name, OPEN4_SHARE_ACCESS_READ |
                               OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    stateid = res.resarray[-1].stateid
    deleg = res.resarray[-1].delegation
    if deleg.delegation_type != OPEN_DELEGATE_READ:
        _delegreturn(sess1, fh, deleg)
        fail("Expected a read delegation, got %s" % _deleg_desc(deleg))

    res = sess1.compound([op.putfh(fh), op.delegreturn(deleg.read.stateid)])
    check(res)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testClaimFHUpgradeReadDeleg(t, env):
    """OPEN(CLAIM_FH) with WANT_READ_DELEG from an open-owner that
       already has the file open

    FLAGS: open deleg all
    CODE: DELEG29
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(b"%s_1" % name)
    res = create_file(sess1, name, access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # The second pass is the retry that _open_claim_fh_retry() makes.
    # Each OPEN bumps the seqid, so count them here.
    seqid = stateid.seqid
    for attempt in range(2):
        res = _open_claim_fh(sess1, fh, name, OPEN4_SHARE_ACCESS_READ |
                             OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
        check(res)
        seqid += 1
        upgraded = res.resarray[-1].stateid
        if upgraded.other != stateid.other:
            fail("OPEN by the same open-owner returned a different stateid")
        if upgraded.seqid != seqid:
            fail("Expected open stateid seqid %i, got %i" %
                 (seqid, upgraded.seqid))
        deleg = res.resarray[-1].delegation
        if _got_deleg(deleg):
            break
    if deleg.delegation_type != OPEN_DELEGATE_READ:
        _delegreturn(sess1, fh, deleg)
        fail("Expected a read delegation, got %s" % _deleg_desc(deleg))

    res = sess1.compound([op.putfh(fh), op.delegreturn(deleg.read.stateid)])
    check(res)
    res = close_file(sess1, fh, stateid=upgraded)
    check(res)

def testClaimFHAfterRecall(t, env):
    """OPEN(CLAIM_FH) with WANT_READ_DELEG after the delegation was
       recalled and the conflicting open has been closed

    The request is made three times: right after the conflicting open
    is closed, 65 seconds later, and 100 seconds later. A server can
    refuse a delegation on a recently recalled file for a while, and
    it can age that refusal only when a request arrives. The last
    request shows whether the refusal ever ends. Any reply may carry
    a delegation or WND4_CONTENTION.

    FLAGS: open deleg
    CODE: DELEG30
    """
    recall = threading.Event()
    def pre_hook(arg, env):
        env.notify = recall.set
    def post_hook(arg, env, res):
        return res
    name = env.testname(t)
    sess1 = env.c1.new_client_session(b"%s_1" % name)
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)
    access = OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG
    fh, stateid, deleg = __create_file_with_deleg(sess1, name, access)

    sess2 = env.c1.new_client_session(b"%s_2" % name)
    open_op = op.open(0, OPEN4_SHARE_ACCESS_BOTH, OPEN4_SHARE_DENY_NONE,
                      open_owner4(0, b"My Open Owner 2"),
                      openflag4(OPEN4_NOCREATE), open_claim4(CLAIM_NULL, name))
    slot = sess2.compound_async(env.home + [open_op])
    completed = recall.wait(2)
    env.sleep(.1)
    res = sess1.compound([op.putfh(fh), op.delegreturn(deleg.read.stateid)])
    check(res)
    res = sess2.listen(slot)
    if not completed:
        fail("delegation break not received")
    for i in range(5):
        if res.status != NFS4ERR_DELAY:
            break
        env.sleep(1)
        res = sess2.compound(env.home + [open_op])
    check(res)
    res = close_file(sess2, fh, stateid=res.resarray[-1].stateid)
    check(res)

    passed = True
    results = []
    elapsed = 0
    for delay in (0, 65, 100):
        # Sleep in short steps so that the lease does not expire
        while elapsed < delay:
            env.sleep(5)
            elapsed += 5
            check(sess1.compound([]))
        res = _open_claim_fh(sess1, fh, name, access)
        check(res)
        stateid = res.resarray[-1].stateid
        deleg = res.resarray[-1].delegation
        _delegreturn(sess1, fh, deleg)
        if (not _got_deleg(deleg) and
            (deleg.delegation_type != OPEN_DELEGATE_NONE_EXT or
             deleg.ond_why != WND4_CONTENTION)):
            passed = False
        results.append("after %i seconds: %s" % (delay, _deleg_desc(deleg)))
    results = "; ".join(results)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)
    if not passed:
        fail(results)
    print(results)

def _check_deleg_stateid(sess, stateid):
    res = sess.compound([op.test_stateid([stateid])])
    check(res)
    status = res.resarray[0].tsr_status_codes[0]
    if status != NFS4_OK:
        fail("TEST_STATEID on the delegation stateid returned %s" %
             nfsstat4[status])

def _testHolderSetattr(t, env, access, deleg_type):
    recall = threading.Event()
    def pre_hook(arg, env):
        env.notify = recall.set
    def post_hook(arg, env, res):
        return res
    name = env.testname(t)
    sess1 = env.c1.new_client_session(b"%s_1" % name)
    sess1.client.cb_pre_hook(OP_CB_RECALL, pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, post_hook)

    fh, stateid, deleg = __create_file_with_deleg(sess1, name, access)
    if deleg.delegation_type != deleg_type:
        _delegreturn(sess1, fh, deleg)
        t.fail_support("Wanted %s, got %s" %
                       (open_delegation_type4[deleg_type], _deleg_desc(deleg)))

    res = sess1.compound([op.putfh(fh),
                          op.setattr(nfs4lib.state00, {FATTR4_MODE: 0o600})])
    recalled = recall.wait(2)
    if recalled or res.status != NFS4_OK:
        _delegreturn(sess1, fh, deleg)
    if recalled:
        fail("SETATTR by the delegation holder recalled its delegation")
    check(res)
    _check_deleg_stateid(sess1, deleg.stateid)

    _delegreturn(sess1, fh, deleg)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testWriteDelegHolderSetattr(t, env):
    """SETATTR by the holder of a write delegation must not recall it

    FLAGS: writedelegations deleg all
    CODE: DELEG31
    """
    _testHolderSetattr(t, env, OPEN4_SHARE_ACCESS_BOTH |
                       OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG,
                       OPEN_DELEGATE_WRITE)

def testReadDelegHolderSetattr(t, env):
    """SETATTR by the holder of a read delegation must not recall it

    FLAGS: deleg all
    CODE: DELEG32
    """
    _testHolderSetattr(t, env, OPEN4_SHARE_ACCESS_READ |
                       OPEN4_SHARE_ACCESS_WANT_READ_DELEG,
                       OPEN_DELEGATE_READ)

def testClaimFHXorDeleg(t, env):
    """OPEN(CLAIM_FH) with WANT_OPEN_XOR_DELEGATION from a second
       open-owner returns a delegation and no open stateid

    FLAGS: open deleg all
    CODE: DELEG33
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(b"%s_1" % name)
    res = sess1.compound([op.putrootfh(),
                          op.getattr(nfs4lib.list2bitmap([FATTR4_OPEN_ARGUMENTS]))])
    check(res)
    caps = res.resarray[-1].obj_attributes
    xor = 1 << OPEN_ARGS_SHARE_ACCESS_WANT_OPEN_XOR_DELEGATION
    if (FATTR4_OPEN_ARGUMENTS not in caps or
        not caps[FATTR4_OPEN_ARGUMENTS].oa_share_access_want & xor):
        t.fail_support("Server does not advertise WANT_OPEN_XOR_DELEGATION")

    res = create_file(sess1, name, access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    owner2 = b"%s_2" % name
    access = (OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_READ_DELEG |
              OPEN4_SHARE_ACCESS_WANT_OPEN_XOR_DELEGATION)
    res = _open_claim_fh(sess1, fh, owner2, access)
    check(res)
    if not _got_deleg(res.resarray[-1].delegation):
        # Close first, so that the retry is not an upgrade of this open
        res = close_file(sess1, fh, stateid=res.resarray[-1].stateid)
        check(res)
        res = _open_claim_fh(sess1, fh, owner2, access)
        check(res)
    deleg = res.resarray[-1].delegation
    if deleg.delegation_type != OPEN_DELEGATE_READ:
        fail("Expected a read delegation, got %s" % _deleg_desc(deleg))
    if not res.resarray[-1].rflags & OPEN4_RESULT_NO_OPEN_STATEID:
        _delegreturn(sess1, fh, deleg)
        fail("Got a delegation, but OPEN4_RESULT_NO_OPEN_STATEID is not set")

    # An OPEN by the first open-owner bumps its seqid once. Any other
    # seqid means the second open-owner's OPEN changed that stateid.
    res = _open_claim_fh(sess1, fh, name, OPEN4_SHARE_ACCESS_READ |
                         OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    upgraded = res.resarray[-1].stateid
    if upgraded.other != stateid.other:
        fail("OPEN by the same open-owner returned a different stateid")
    if upgraded.seqid != stateid.seqid + 1:
        fail("Expected open stateid seqid %i, got %i" %
             (stateid.seqid + 1, upgraded.seqid))

    res = sess1.compound([op.putfh(fh), op.delegreturn(deleg.read.stateid)])
    check(res)
    res = close_file(sess1, fh, stateid=upgraded)
    check(res)

def testClaimFHDelegAfterClose(t, env):
    """A delegation from OPEN(CLAIM_FH) by a second open-owner outlives
       the CLOSE of that owner's open

    FLAGS: open deleg all
    CODE: DELEG34
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(b"%s_1" % name)
    res = create_file(sess1, name, access=OPEN4_SHARE_ACCESS_READ |
                      OPEN4_SHARE_ACCESS_WANT_NO_DELEG)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    res = _open_claim_fh_retry(sess1, fh, b"%s_2" % name,
                               OPEN4_SHARE_ACCESS_READ |
                               OPEN4_SHARE_ACCESS_WANT_READ_DELEG)
    deleg = res.resarray[-1].delegation
    if deleg.delegation_type != OPEN_DELEGATE_READ:
        _delegreturn(sess1, fh, deleg)
        fail("Expected a read delegation, got %s" % _deleg_desc(deleg))
    res = close_file(sess1, fh, stateid=res.resarray[-1].stateid)
    check(res)
    _check_deleg_stateid(sess1, deleg.read.stateid)

    res = sess1.compound([op.putfh(fh), op.delegreturn(deleg.read.stateid)])
    check(res)
    res = close_file(sess1, fh, stateid=stateid)
    check(res)
