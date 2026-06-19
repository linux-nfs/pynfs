from .st_create_session import create_session
from .st_open import open_claim4
from xdrdef.nfs4_const import *
from xdrdef.nfs4_pack import NFS4Unpacker

from .environment import check, fail, create_obj, use_obj, close_file, rename_obj
from xdrdef.nfs4_type import *
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4lib
import threading

zerotime = nfstime4(seconds=0, nseconds=0)

def decode_notify_event(change):
    """Decode a notify4 into its typed event structure."""
    mask = nfs4lib.bitmap2list(change.notify_mask)
    unpacker = NFS4Unpacker(change.notify_vals)
    if NOTIFY4_REMOVE_ENTRY in mask:
        return (NOTIFY4_REMOVE_ENTRY, unpacker.unpack_notify_remove4())
    elif NOTIFY4_ADD_ENTRY in mask:
        return (NOTIFY4_ADD_ENTRY, unpacker.unpack_notify_add4())
    elif NOTIFY4_RENAME_ENTRY in mask:
        return (NOTIFY4_RENAME_ENTRY, unpacker.unpack_notify_rename4())
    elif NOTIFY4_CHANGE_DIR_ATTRS in mask:
        return (NOTIFY4_CHANGE_DIR_ATTRS, unpacker.unpack_notify_attr4())
    return (None, None)

def bitmap4_to_int(bitmap):
    """Convert a bitmap4 (list of uint32 words) to a single integer."""
    result = 0
    for i, word in enumerate(bitmap):
        result |= word << (32 * i)
    return result

def _getDirDeleg(t, env, notify_mask, cb):
    def recall_pre_hook(arg, env):
        cb.stateid = arg.stateid # NOTE this must be done before set()
        cb.cred = env.cred.raw_cred
        cb.got_recall = True
        env.notify = cb.set # This is called after compound sent to queue
    def recall_post_hook(arg, env, res):
        return res
    def notify_pre_hook(arg, env):
        cb.stateid = arg.cna_stateid
        cb.fh = arg.cna_fh
        cb.changes = arg.cna_changes
        cb.got_notify = True
        env.notify = cb.set # This is called after compound sent to queue
    def notify_post_hook(arg, env, res):
        return res

    cb.got_recall = False
    cb.got_notify = False

    c = env.c1
    sess1 = c.new_client_session(b"%s_1" % env.testname(t))
    sess1.client.cb_pre_hook(OP_CB_RECALL, recall_pre_hook)
    sess1.client.cb_post_hook(OP_CB_RECALL, recall_post_hook)
    sess1.client.cb_pre_hook(OP_CB_NOTIFY, notify_pre_hook)
    sess1.client.cb_post_hook(OP_CB_NOTIFY, notify_post_hook)

    topdir = c.homedir + [t.code.encode('utf8')]
    res = create_obj(sess1, topdir)
    check(res)
    fh = res.resarray[-1].object

    mask_bm = nfs4lib.list2bitmap(notify_mask)
    ops = [ op.putfh(fh), op.get_dir_delegation(False, nfs4lib.list2bitmap(notify_mask),
                                                zerotime, zerotime,
                                                nfs4lib.list2bitmap([]),
                                                nfs4lib.list2bitmap([]))]
    res = sess1.compound(ops)
    check(res, [NFS4_OK, NFS4ERR_NOTSUPP])
    if (res.status == NFS4ERR_NOTSUPP):
        t.pass_warn("Server doesn't support GET_DIR_DELEGATION")

    nf = res.resarray[-1].gddr_res_non_fatal4
    if nf.gddrnf_status == GDD4_UNAVAIL:
        t.pass_warn("Server reported that delegation on new dir was unavailable.")
    elif nf.gddrnf_status != GDD4_OK:
        t.fail("Server returned unknown non-fatal status code.")

    deleg = res.resarray[-1].gddrnf_resok4.gddr_stateid
    if NOTIFY4_GFLAG_EXTEND in notify_mask and \
       nf.gddrnf_resok4.gddr_notification != mask_bm:
        ops = [ op.putfh(fh), op.delegreturn(deleg) ]
        res = sess1.compound(ops)
        t.pass_warn("Server didn't offer the necessary directory notifications for this test")

    return (sess1, fh, deleg)

def testDirDelegSimple(t, env):
    """Test basic dir delegation handout, recall and return

    FLAGS: dirdeleg all
    CODE: DIRDELEG1
    """
    c = env.c1
    recall = threading.Event()
    sess1, fh, deleg = _getDirDeleg(t, env, [], recall)

    # new client -- create a file in the dir
    sess2 = c.new_client_session(b"%s_2" % env.testname(t))
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"owner")
    how = openflag4(OPEN4_CREATE, createhow4(GUARDED4, {FATTR4_SIZE:0}))
    open_op = [ op.putfh(fh), op.open(0,
                                      OPEN4_SHARE_ACCESS_WRITE | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                                      OPEN4_SHARE_DENY_NONE, owner, how, claim), op.getfh() ]
    slot = sess2.compound_async(open_op)
    completed = recall.wait(2)
    env.sleep(.1)

    ops = [ op.putfh(fh), op.delegreturn(deleg) ]
    res = sess1.compound(ops)
    check(res)

    # Reap the async open and close any file it created
    res = sess2.listen(slot)
    if res.status == NFS4_OK:
        open_stateid = res.resarray[-2].stateid
        file_fh = res.resarray[-1].object
        close_file(sess2, file_fh, stateid=open_stateid)

def testDirDelegDuplicate(t, env):
    """Test that server returns GDD4_UNAVAIL on duplicate GDD4 request

    FLAGS: dirdeleg all
    CODE: DIRDELEG2
    """
    c = env.c1
    recall = threading.Event()
    sess1, fh, deleg = _getDirDeleg(t, env, [], recall)

    # get a dir deleg with no notifications
    ops = [ op.putfh(fh), op.get_dir_delegation(False,
                                                nfs4lib.list2bitmap([]),
                                                zerotime, zerotime,
                                                nfs4lib.list2bitmap([]),
                                                nfs4lib.list2bitmap([]))]
    res = sess1.compound(ops)
    check(res)
    nfstatus = res.resarray[-1].gddr_res_non_fatal4.gddrnf_status
    if (nfstatus != GDD4_UNAVAIL):
        fail("Server replied to duplicate request with %d" % nfstatus)

    ops = [ op.putfh(fh), op.delegreturn(deleg) ]
    res = sess1.compound(ops)
    check(res)

def testDirDelegRemoveRecall(t, env):
    """Verify remove triggers dir delegation recall

    FLAGS: dirdeleg all
    CODE: DIRDELEG3
    """
    c = env.c1
    recall = threading.Event()
    sess1, fh, deleg = _getDirDeleg(t, env, [], recall)

    # Create a file from sess1
    claim = open_claim4(CLAIM_NULL, env.testname(t))
    owner = open_owner4(0, b"owner")
    how = openflag4(OPEN4_CREATE, createhow4(GUARDED4, {FATTR4_SIZE:0}))
    open_op = [ op.putfh(fh), op.open(0,
                                      OPEN4_SHARE_ACCESS_WRITE | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
                                      OPEN4_SHARE_DENY_NONE, owner, how, claim), op.getfh() ]
    res = sess1.compound(open_op)
    check(res)
    open_stateid = res.resarray[-2].stateid
    file_fh = res.resarray[-1].object
    close_file(sess1, file_fh, stateid=open_stateid)

    # Remove the file from sess2 -- should trigger recall
    sess2 = c.new_client_session(b"%s_2" % env.testname(t))
    remove_op = [ op.putfh(fh), op.remove(env.testname(t)) ]
    slot = sess2.compound_async(remove_op)
    completed = recall.wait(2)
    env.sleep(.1)

    ops = [ op.putfh(fh), op.delegreturn(deleg) ]
    res = sess1.compound(ops)
    check(res)
