import socket
import time

from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, create_file, open_file, close_file
from .environment import open_create_file_op, use_obj, write_file, read_file
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4, netloc4, netaddr4
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

def _bad_stateid():
    # A fabricated, non-special stateid (not the all-zero anonymous or
    # all-one READ-bypass special stateids) the server cannot recognize.
    return stateid4(1, b'\xde\xad\xbe\xef' * 3)

def _server_netloc(env):
    """netloc4 (NL4_NETADDR) naming the server under test.

    The Linux server only accepts the NL4_NETADDR form of netloc4 and
    rejects NL4_NAME / NL4_URL at decode time with NFS4ERR_BADXDR, so build
    a universal address (RFC 1833: h.h.h.h.p1.p2) from the server address
    and port.  For single-server COPY_NOTIFY tests this names the server
    itself; we only need a netloc4 the source server will accept and record.
    """
    host, port = env.opts.server, env.opts.port
    family, _, _, _, sockaddr = socket.getaddrinfo(
        host, port, type=socket.SOCK_STREAM)[0]
    ip = sockaddr[0]
    uaddr = "%s.%d.%d" % (ip, (port >> 8) & 0xff, port & 0xff)
    netid = b'tcp6' if family == socket.AF_INET6 else b'tcp'
    return netloc4(NL4_NETADDR, nl_addr=netaddr4(netid, uaddr.encode('ascii')))

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

def testOffloadCancel(t, env):
    """start an async copy and cancel it with OFFLOAD_CANCEL

    FLAGS: copy
    CODE: COPY7
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    data = b"E" * (1024 * 1024)
    _write_data(sess, src_fh, src_stateid, data)

    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, dst_stateid,
                   count=len(data), synchronous=0)
    check(res)
    cr = res.resarray[-1]

    if cr.cr_resok4.cr_requirements.cr_synchronous:
        return

    copy_stateid = cr.cr_response.wr_callback_id[0]

    ops = [op.putfh(dst_fh), op.offload_cancel(copy_stateid)]
    res = sess.compound(ops)
    check(res, [NFS4_OK, NFS4ERR_NOTSUPP, NFS4ERR_COMPLETE_ALREADY],
          msg="OFFLOAD_CANCEL")

def testCopyBadSourceStateid(t, env):
    """COPY with an invalid source stateid should fail

    FLAGS: copy
    CODE: COPY8
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, _src_stateid = _create_and_open(sess, env.testname(t))
    dst_fh, dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, _bad_stateid(), dst_fh, dst_stateid,
                   count=1024, synchronous=1)
    check(res, NFS4ERR_BAD_STATEID, msg="COPY with bad source stateid")

def testCopyBadDestStateid(t, env):
    """COPY with an invalid destination stateid should fail

    FLAGS: copy
    CODE: COPY9
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    write_file(sess, src_fh, b"data", 0, src_stateid)
    dst_fh, _dst_stateid = _create_and_open(sess, env.testname(t) + b"_dst")

    res = _do_copy(sess, src_fh, src_stateid, dst_fh, _bad_stateid(),
                   count=4, synchronous=1)
    check(res, NFS4ERR_BAD_STATEID, msg="COPY with bad dest stateid")

def testOffloadStatusNoState(t, env):
    """OFFLOAD_STATUS with a fabricated stateid should fail

    FLAGS: copy
    CODE: COPY10
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, _stateid = _create_and_open(sess, env.testname(t))

    ops = [op.putfh(src_fh), op.offload_status(_bad_stateid())]
    res = sess.compound(ops)
    check(res, NFS4ERR_BAD_STATEID, msg="OFFLOAD_STATUS with bad stateid")

def testCopyToSameFile(t, env):
    """copy within the same file to non-overlapping region

    FLAGS: copy
    CODE: COPY11
    """
    sess = env.c1.new_client_session(env.testname(t))
    fh, stateid = _create_and_open(sess, env.testname(t))
    data = b"F" * 4096
    write_file(sess, fh, data, 0, stateid)

    res = _do_copy(sess, fh, stateid, fh, stateid,
                   src_offset=0, dst_offset=8192, count=4096, synchronous=1)
    check(res)
    cr = res.resarray[-1]
    if cr.cr_response.wr_count != 4096:
        fail("Expected to copy 4096 bytes, got %d" % cr.cr_response.wr_count)

    res = read_file(sess, fh, 8192, 4096, stateid)
    check(res)
    if res.data != data:
        fail("Same-file copy: data at offset 8192 does not match source")

def testCopyNotify(t, env):
    """COPY_NOTIFY authorizes a destination server to copy from the source

    A client wanting an inter-server copy first sends COPY_NOTIFY to the
    source server (CURRENT_FH = source file) naming the destination server.
    The source returns a stateid and a list of netlocs the destination
    should use to reach it; the client then hands these to the destination
    server's COPY.  This exercises the source-server half against a single
    server.

    FLAGS: copy
    CODE: CPNOTIFY1
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))
    _write_data(sess, src_fh, src_stateid, b"copy notify test data")

    ops = [op.putfh(src_fh),
           op.copy_notify(src_stateid, _server_netloc(env))]
    res = sess.compound(ops)
    check(res, [NFS4_OK, NFS4ERR_NOTSUPP], msg="COPY_NOTIFY")
    if res.status == NFS4ERR_NOTSUPP:
        t.fail_support("Server does not support COPY_NOTIFY "
                       "(inter-server copy source)")

    cnr = res.resarray[-1]
    # The client needs a source stateid to give to the destination's COPY.
    if cnr.cnr_stateid is None:
        fail("COPY_NOTIFY did not return a source stateid")
    # And at least one netloc telling the destination how to reach the source.
    if not cnr.cnr_source_server:
        fail("COPY_NOTIFY returned an empty cnr_source_server list")

def testCopyNotifyBadStateid(t, env):
    """COPY_NOTIFY with an invalid source stateid should fail

    FLAGS: copy
    CODE: CPNOTIFY2
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, _src_stateid = _create_and_open(sess, env.testname(t))

    ops = [op.putfh(src_fh),
           op.copy_notify(_bad_stateid(), _server_netloc(env))]
    res = sess.compound(ops)
    if res.status == NFS4ERR_NOTSUPP:
        t.fail_support("Server does not support COPY_NOTIFY "
                       "(inter-server copy source)")
    check(res, NFS4ERR_BAD_STATEID, msg="COPY_NOTIFY with bad source stateid")

def testCopyNotifyUnsupportedNetloc(t, env):
    """COPY_NOTIFY with a name or URL netloc must not return NFS4ERR_BADXDR

    NL4_NAME and NL4_URL are well-formed XDR, so a server that does not
    support them must reject the operation with NFS4ERR_NOTSUPP, not
    NFS4ERR_BADXDR (which is reserved for XDR that cannot be decoded).  A
    server that does support them may return NFS4_OK.

    FLAGS: copy
    CODE: CPNOTIFY4
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))
    src_fh, src_stateid = _create_and_open(sess, env.testname(t))

    for name, nl in [("NL4_NAME", netloc4(NL4_NAME, nl_name=b"nfs.example.org")),
                     ("NL4_URL", netloc4(NL4_URL,
                                         nl_url=b"nfs://nfs.example.org/"))]:
        res = sess.compound([op.putfh(src_fh),
                             op.copy_notify(src_stateid, nl)])
        if res.status == NFS4ERR_BADXDR:
            fail("COPY_NOTIFY with a %s netloc returned NFS4ERR_BADXDR; a "
                 "well-formed but unsupported netloc should return "
                 "NFS4ERR_NOTSUPP" % name)
        check(res, [NFS4_OK, NFS4ERR_NOTSUPP],
              msg="COPY_NOTIFY with a %s netloc" % name)

def testCopyNotifyNoFh(t, env):
    """COPY_NOTIFY without a current filehandle should fail

    FLAGS: copy
    CODE: CPNOTIFY3
    VERS: 2-
    """
    sess = env.c1.new_client_session(env.testname(t))

    ops = [op.copy_notify(env.stateid0, _server_netloc(env))]
    res = sess.compound(ops)
    if res.status == NFS4ERR_NOTSUPP:
        t.fail_support("Server does not support COPY_NOTIFY "
                       "(inter-server copy source)")
    check(res, NFS4ERR_NOFILEHANDLE, msg="COPY_NOTIFY with no filehandle")

def _inter_copy_ops(src_fh, src_stateid, dst_fh, dst_stateid, source_server,
                    src_offset=0, dst_offset=0, count=0,
                    consecutive=0, synchronous=1):
    """COMPOUND for an inter-server COPY, sent to the destination server.

    SAVED_FH is the source file's filehandle as known to the source server;
    the destination server treats it as opaque and forwards it to the source
    named by source_server (a non-empty ca_source_server list is what marks
    the copy as inter-server).
    """
    return [op.putfh(src_fh), op.savefh(), op.putfh(dst_fh),
            op.copy(src_stateid, dst_stateid, src_offset, dst_offset,
                    count, consecutive, synchronous, source_server)]

def testInterServerCopy(t, env):
    """server-to-server (inter-server) COPY across two servers

    Requires a second server: pass --server2 SERVER:/PATH.  The source file
    is created on the second server (env.c2, the copy source) and the
    destination file on the primary server (env.c1, the copy destination).
    The client issues COPY_NOTIFY to the source to authorize the destination,
    then COPY to the destination naming the source via ca_source_server.

    FLAGS: copy
    CODE: INTERCOPY1
    VERS: 2-
    """
    if env.c2 is None:
        t.fail_support("No second server configured "
                       "(pass --server2 SERVER:/PATH to enable)")

    # Source file on the second server (the copy source).
    src_sess = env.c2.new_client_session(env.testname(t) + b"_src")
    src_fh, src_stateid = _create_and_open(src_sess, env.testname(t))
    data = b"inter-server copy payload " * 4096
    _write_data(src_sess, src_fh, src_stateid, data)

    # Ask the source to authorize the primary server as the copy destination.
    dest_netloc = _server_netloc(env)   # names the primary server (env.c1)
    res = src_sess.compound([op.putfh(src_fh),
                             op.copy_notify(src_stateid, dest_netloc)])
    check(res, [NFS4_OK, NFS4ERR_NOTSUPP], msg="COPY_NOTIFY on source server")
    if res.status == NFS4ERR_NOTSUPP:
        t.fail_support("Source server does not support COPY_NOTIFY")
    cnr = res.resarray[-1]
    copy_src_stateid = cnr.cnr_stateid
    source_server = cnr.cnr_source_server
    if not source_server:
        fail("COPY_NOTIFY returned an empty cnr_source_server list")

    # Destination file on the primary server (the copy destination).
    dst_sess = env.c1.new_client_session(env.testname(t) + b"_dst")
    dst_fh, dst_stateid = _create_and_open(dst_sess, env.testname(t))

    # COPY to the destination, naming the source via ca_source_server.
    # Inter-server copy is asynchronous on the Linux server (a synchronous
    # request returns NFS4ERR_NOTSUPP), so ask for async and poll below.
    ops = _inter_copy_ops(src_fh, copy_src_stateid, dst_fh, dst_stateid,
                          source_server, count=len(data), synchronous=0)
    res = dst_sess.compound(ops)
    check(res, [NFS4_OK, NFS4ERR_NOTSUPP], msg="inter-server COPY")
    if res.status == NFS4ERR_NOTSUPP:
        t.fail_support("Destination server does not support inter-server COPY")
    cr = res.resarray[-1]

    if cr.cr_resok4.cr_requirements.cr_synchronous:
        if cr.cr_response.wr_count != len(data):
            fail("Inter-server copy expected %d bytes, got %d" %
                 (len(data), cr.cr_response.wr_count))
    else:
        copy_stateid = cr.cr_response.wr_callback_id[0]
        status = _poll_offload_status(dst_sess, dst_fh, copy_stateid)
        if status.osr_complete[0] != NFS4_OK:
            fail("Async inter-server copy error: %d" % status.osr_complete[0])
        if status.osr_count != len(data):
            fail("Expected %d bytes copied, got %d" %
                 (len(data), status.osr_count))

    _verify_data(dst_sess, dst_fh, dst_stateid, data)
