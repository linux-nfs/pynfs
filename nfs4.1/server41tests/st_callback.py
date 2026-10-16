from .environment import check, fail, create_file, open_file, close_file
from .environment import open_create_file_op
from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4
import nfs_ops
op = nfs_ops.NFS4ops()
import threading
import logging
log = logging.getLogger("test.env")

def _getleasetime(sess):
    res = sess.compound([op.putrootfh(), op.getattr(1 << FATTR4_LEASE_TIME)])
    return res.resarray[-1].obj_attributes[FATTR4_LEASE_TIME]

def testCbNotifyLockExpiredClient(t, env):
    """Tests CB_NOTIFY_LOCK with an expired client

    FLAGS: callback
    CODE: CALLBACK1
    """
    cb = threading.Event()
    def pre_hook(arg, env):
        log.info("inside pre_hook")
        cb.set()
    def post_hook(arg, env, res):
        log.info("inside post_hook")
        return res

    # create the first client
    c1 = env.c1.new_client(b"%s_1" % env.testname(t))
    sess1 = c1.create_session()
    res = sess1.compound([op.reclaim_complete(FALSE)])
    check(res)

    # create the test file and obtain write lock
    res = create_file(sess1, env.testname(t))
    check(res)
    fh1 = res.resarray[-1].object
    stateid1 = res.resarray[-2].stateid
    open_to_lock_owner = open_to_lock_owner4(0, stateid1, 0, lock_owner4(0, b"lock1"))
    locker = locker4(open_owner=open_to_lock_owner, new_lock_owner=True)
    lock_op = op.lock(WRITE_LT, False, 0, NFS4_UINT64_MAX, locker)
    res = sess1.compound([op.putfh(fh1), lock_op])
    check(res, NFS4_OK)

    # create the second client
    c2 = env.c1.new_client(b"%s_2" % env.testname(t))
    sess2 = c2.create_session()
    sess2.client.cb_pre_hook(OP_CB_NOTIFY_LOCK, pre_hook)
    sess2.client.cb_post_hook(OP_CB_NOTIFY_LOCK, post_hook)
    res = sess2.compound([op.reclaim_complete(FALSE)])
    check(res)

    # open the test file and attempt to obtain a read lock
    res = open_file(sess2, env.testname(t))
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid
    open_to_lock_owner = open_to_lock_owner4(0, stateid2, 0, lock_owner4(0, b"lock2"))
    locker = locker4(open_owner=open_to_lock_owner, new_lock_owner=True)
    lock_op = op.lock(READW_LT, False, 0, NFS4_UINT64_MAX, locker)
    res = sess2.compound([op.putfh(fh2), lock_op])
    check(res, NFS4ERR_DENIED)

    # keep the first client active, allow the second client to expire
    lease_time = _getleasetime(sess1)
    for i in range(4):
        env.sleep(lease_time // 2, "keeping the first client active")
        res = sess1.compound([])
        check(res, NFS4_OK)

    # a courteous server may have kept the client around anyway - forcibly expire it
    env.serverhelper(b"expire %s_2" % env.testname(t))

    # close the file on the first client and see if the second client
    # gets a CB_NOTIFY_LOCK (it shouldn't!)
    res = close_file(sess1, fh1, stateid=stateid1)
    check(res)

    cb.wait(10)
    if cb.is_set():
        log.warning("Got CB_NOTIFY_LOCK on an expired client!")
        cb.clear()

    res = close_file(sess2, fh2, stateid=stateid2)
    check(res, NFS4ERR_BADSESSION)

    # open and write lock the test file again on the first client
    res = open_file(sess1, env.testname(t), access=OPEN4_SHARE_ACCESS_BOTH)
    check(res)
    fh1 = res.resarray[-1].object
    stateid1 = res.resarray[-2].stateid
    open_to_lock_owner = open_to_lock_owner4(0, stateid1, 0, lock_owner4(0, b"lock1"))
    locker = locker4(open_owner=open_to_lock_owner, new_lock_owner=True)
    lock_op = op.lock(WRITE_LT, False, 0, NFS4_UINT64_MAX, locker)
    res = sess1.compound([op.putfh(fh1), lock_op])
    check(res, NFS4_OK)

    # set up the second client again
    c2 = env.c1.new_client(b"%s_2" % env.testname(t))
    sess2 = c2.create_session()
    sess2.client.cb_pre_hook(OP_CB_NOTIFY_LOCK, pre_hook)
    sess2.client.cb_post_hook(OP_CB_NOTIFY_LOCK, post_hook)
    res = sess2.compound([op.reclaim_complete(FALSE)])
    check(res, [NFS4_OK, NFS4ERR_COMPLETE_ALREADY])

    # open the test file again on the second client and attempt to obtain a read lock
    res = open_file(sess2, env.testname(t))
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid
    open_to_lock_owner = open_to_lock_owner4(0, stateid2, 0, lock_owner4(0, b"lock2"))
    locker = locker4(open_owner=open_to_lock_owner, new_lock_owner=True)
    lock_op = op.lock(READW_LT, False, 0, NFS4_UINT64_MAX, locker)
    res = sess2.compound([op.putfh(fh2), lock_op])
    check(res, NFS4ERR_DENIED)

    # close the file on the first client and see if the second client
    # gets a CB_NOTIFY_LOCK.  If it does, try to obtain the lock.
    res = close_file(sess1, fh1, stateid=stateid1)
    check(res)

    cb.wait(10)
    if cb.is_set():
        res = sess2.compound([op.putfh(fh2), lock_op])
        check(res)
    else:
        fail("Did not receive CB_NOTIFY_LOCK")

    res = close_file(sess2, fh2, stateid=stateid2)
    check(res)
