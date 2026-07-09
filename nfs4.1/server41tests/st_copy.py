import time

from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file
from .environment import open_create_file_op, use_obj, write_file, read_file
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4
import nfs_ops
op = nfs_ops.NFS4ops()

def _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
             src_offset=0, dst_offset=0, count=0,
             consecutive=0, synchronous=1):
    ops = [op.putfh(src_fh), op.savefh(), op.putfh(dst_fh),
           op.copy(src_stateid, dst_stateid, src_offset, dst_offset,
                   count, consecutive, synchronous, [])]
    return sess.compound(ops)

def _poll_offload_status(sess, dst_fh, copy_stateid, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ops = [op.putfh(dst_fh), op.offload_status(copy_stateid)]
        res = sess.compound(ops)
        check(res)
        status_res = res.resarray[-1]
        if status_res.osr_complete:
            return status_res
        time.sleep(1)
    fail("OFFLOAD_STATUS did not complete within %d seconds" % timeout)

def _create_and_open(sess, name):
    res = create_file(sess, name)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    return fh, stateid

def _write_data(sess, fh, stateid, data, offset=0):
    """Write data in chunks bounded by the session's max request size."""
    chunk = sess.fore_channel.maxrequestsize - 1024
    pos = 0
    while pos < len(data):
        res = write_file(sess, fh, data[pos:pos + chunk], offset + pos, stateid)
        check(res, msg="WRITE at offset %d" % (offset + pos))
        pos += res.count

def _verify_data(sess, fh, stateid, data, offset=0):
    """Read back and compare data in chunks bounded by max response size."""
    chunk = sess.fore_channel.maxresponsesize - 1024
    pos = 0
    while pos < len(data):
        res = read_file(sess, fh, offset + pos, min(chunk, len(data) - pos),
                        stateid)
        check(res)
        if not res.data:
            fail("Short read at offset %d" % (offset + pos))
        if res.data != data[pos:pos + len(res.data)]:
            fail("Data mismatch at offset %d" % (offset + pos))
        pos += len(res.data)

def testSyncCopy(t, env):
    """synchronous copy of a file and verify contents

    FLAGS: copy
    CODE: COPY1
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    data = b"A" * 65536
    _write_data(sess, src_fh, src_stateid, data)

    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
                   count=len(data), synchronous=1)
    check(res)
    cr = res.resarray[-1]

    # A synchronous COPY was requested, but RFC 7862 permits the server to
    # perform the copy asynchronously anyway; cr_requirements.cr_synchronous
    # reports what actually happened.  Honor either, but verify the byte count.
    if cr.cr_resok4.cr_requirements.cr_synchronous:
        if cr.cr_response.wr_count != len(data):
            fail("Synchronous copy expected %d bytes, got %d" %
                 (len(data), cr.cr_response.wr_count))
    else:
        copy_stateid = cr.cr_response.wr_callback_id[0]
        status = _poll_offload_status(sess, dst_fh, copy_stateid)
        if status.osr_complete[0] != NFS4_OK:
            fail("Async copy completed with error: %d" % status.osr_complete[0])
        if status.osr_count != len(data):
            fail("Expected %d bytes copied, got %d" %
                 (len(data), status.osr_count))

    _verify_data(sess, dst_fh, dst_stateid, data)

def testCopyWithOffset(t, env):
    """copy with non-zero source and destination offsets

    FLAGS: copy
    CODE: COPY2
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    data = b"\x00" * 1024 + b"B" * 4096 + b"\x00" * 1024
    _write_data(sess, src_fh, src_stateid, data)

    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
                   src_offset=1024, dst_offset=512, count=4096, synchronous=1)
    check(res)
    cr = res.resarray[-1]
    if cr.cr_response.wr_count != 4096:
        fail("Expected to copy 4096 bytes, got %d" % cr.cr_response.wr_count)

    res = read_file(sess, dst_fh, 512, 4096, dst_stateid)
    check(res)
    if res.data != b"B" * 4096:
        fail("Destination data at offset 512 does not match expected content")

def testAsyncCopy(t, env):
    """request async copy, poll OFFLOAD_STATUS, verify data

    FLAGS: copy
    CODE: COPY3
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    data = b"C" * (1024 * 1024)
    _write_data(sess, src_fh, src_stateid, data)

    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
                   count=len(data), synchronous=0)
    check(res)
    cr = res.resarray[-1]

    if not cr.cr_resok4.cr_requirements.cr_synchronous:
        copy_stateid = cr.cr_response.wr_callback_id[0]
        status = _poll_offload_status(sess, dst_fh, copy_stateid)
        if status.osr_complete[0] != NFS4_OK:
            fail("Async copy completed with error: %d" % status.osr_complete[0])
        if status.osr_count != len(data):
            fail("Expected %d bytes copied, got %d" %
                 (len(data), status.osr_count))
    else:
        if cr.cr_response.wr_count != len(data):
            fail("Sync copy returned %d bytes, expected %d" %
                 (cr.cr_response.wr_count, len(data)))

    _verify_data(sess, dst_fh, dst_stateid, data)

def testZeroLengthCopy(t, env):
    """test that zero-length copy copies to EOF

    FLAGS: copy
    CODE: COPY5
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    data = b"write test data"
    res = write_file(sess1, fh, data, 0, stateid)
    res = create_file(sess1, env.testname(t)+b"_copy")
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid
    copy = [op.putfh(fh), op.savefh(), op.putfh(fh2),
            op.copy(stateid, stateid2, 0, 0, 0, 0, 1, [])]
    res = sess1.compound(copy)
    check(res)
    l = res.resarray[-1].cr_response.wr_count
    if l != len(data):
        fail("Copy to end of %d-byte file copied %d bytes" % (len(data), l))

def testAsyncCopyOffloadStatusAfterComplete(t, env):
    """verify OFFLOAD_STATUS works after async copy completes

    The server should keep copy state around for a TTL window after
    completion so clients can query final status.  This catches the
    inverted TTL check bug where the reaper destroys the state on
    the first tick instead of the last.

    FLAGS: copy
    CODE: COPY6
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    data = b"D" * (1024 * 1024)
    _write_data(sess, src_fh, src_stateid, data)

    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
                   count=len(data), synchronous=0)
    check(res)
    cr = res.resarray[-1]

    if cr.cr_resok4.cr_requirements.cr_synchronous:
        if cr.cr_response.wr_count != len(data):
            fail("Sync copy returned %d bytes, expected %d" %
                 (cr.cr_response.wr_count, len(data)))
        return

    copy_stateid = cr.cr_response.wr_callback_id[0]
    status = _poll_offload_status(sess, dst_fh, copy_stateid)
    if status.osr_complete[0] != NFS4_OK:
        fail("Async copy completed with error: %d" % status.osr_complete[0])

    # Copy is done. Wait a bit then re-query -- state should still be valid.
    time.sleep(5)

    ops = [op.putfh(dst_fh), op.offload_status(copy_stateid)]
    res = sess.compound(ops)
    check(res, msg="OFFLOAD_STATUS after completion should still succeed")
    recheck = res.resarray[-1]
    if not recheck.osr_complete:
        fail("OFFLOAD_STATUS lost completion status")
    if recheck.osr_complete[0] != NFS4_OK:
        fail("OFFLOAD_STATUS completion changed to error: %d" %
             recheck.osr_complete[0])
