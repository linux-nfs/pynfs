from .st_create_session import create_session
from xdrdef.nfs4_const import *

from .environment import check, fail, unsupported, create_file, open_file, close_file, write_file, read_file
from .environment import open_create_file_op, do_getattrdict
from xdrdef.nfs4_type import open_owner4, openflag4, createhow4, open_claim4
from xdrdef.nfs4_type import creatverfattr, fattr4, stateid4, locker4, lock_owner4
from xdrdef.nfs4_type import open_to_lock_owner4, nfsace4
import nfs_ops
op = nfs_ops.NFS4ops()
import threading
import nfs4lib
import nfs4acl

def expect(res, seqid):
    """Verify that open result has expected stateid.seqid"""
    got = res.resarray[-2].stateid.seqid
    if got != seqid:
        fail("Expected open_stateid.seqid == %i, got %i" % (seqid, got))

def testSupported(t, env):
    """Do a simple OPEN create

    FLAGS: open all
    CODE: OPEN1
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    # See 8.1.3.1 of draft-10:
    # the server MUST provide an "seqid" value starting at one...
    expect(res, seqid=1)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # STUB - need to check  open_res.delegation.delegation_type
    # see draft-10 line 19445
    # QUESTION - what does "If the server supports the new _WANT_ flags" mean?
    #    will the server return INVAL? NOTSUPP? or just silently ignore?

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testServerStateSeqid(t, env):
    """Do multiple OPENs of a file, check that server bumps stateid.seqid

    FLAGS: open all
    CODE: OPEN2
    """
    name = env.testname(t)
    sess1 = env.c1.new_client_session(name)
    owner = b"owner_%s" % name
    path = sess1.c.homedir + [name]
    res = create_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_WRITE)
    check(res)
    expect(res, seqid=1)
    res = open_file(sess1, owner, path, access=OPEN4_SHARE_ACCESS_READ)
    check(res)
    expect(res, seqid=2)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # STUB - need to check no delegation return

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testReadWrite(t, env):
    """Do a simple READ and WRITE

    FLAGS: open all
    CODE: OPEN30
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    owner = open_owner4(0, b"My Open Owner")
    res = create_file(sess1, env.testname(t))
    check(res)
    expect(res, seqid=1)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    stateid.seqid = 0
    data = b"write test data"
    res = write_file(sess1, fh, data, 5, stateid)
    check(res)
    res = read_file(sess1, fh, 0, 1000, stateid)
    check(res)
    if not res.eof:
        fail("EOF not set on read")
    desired = b"\0"*5 + data
    if res.data != desired:
        fail("Expected %r, got %r" % (desired, res.data))

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testAnonReadWrite(t, env):
    """Do a simple READ and WRITE using anonymous stateid

    FLAGS: open all
    CODE: OPEN31
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    owner = open_owner4(0, b"My Open Owner")
    res = create_file(sess1, env.testname(t))
    check(res)
    expect(res, seqid=1)
    fh = res.resarray[-1].object
    data = b"write test data"
    stateid = res.resarray[-2].stateid
    res = close_file(sess1, fh, stateid=stateid)
    check(res)
    res = write_file(sess1, fh, data, 5, nfs4lib.state00)
    check(res)
    res = read_file(sess1, fh, 0, 1000, nfs4lib.state00)
    check(res)
    if not res.eof:
        fail("EOF not set on read")
    desired = b"\0"*5 + data
    if res.data != desired:
        fail("Expected %r, got %r" % (desired, res.data))

def testEXCLUSIVE4AtNameAttribute(t, env):
    """If the file does exist,but the stored verifier does not match,
       then an error of NFS4ERR_EXIST is returned from server.
       rfc5661 18.16.3

    FLAGS: open all
    CODE: OPEN6
    """
    sess1 = env.c1.new_client_session(env.testname(t))

    res = create_file(sess1, env.testname(t), mode=EXCLUSIVE4_1)
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    res = create_file(sess1, env.testname(t), mode=EXCLUSIVE4_1,
                        verifier = b"Justtest")
    check(res, NFS4ERR_EXIST)

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testOPENClaimFH(t, env):
    """OPEN file with claim_type is CLAIM_FH

    FLAGS: open all
    CODE: OPEN7
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t), want_deleg=False)
    check(res)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

    claim = open_claim4(CLAIM_FH)
    how = openflag4(OPEN4_NOCREATE)
    oowner = open_owner4(0, b"My Open Owner 2")
    access = OPEN4_SHARE_ACCESS_BOTH|OPEN4_SHARE_ACCESS_WANT_NO_DELEG

    open_op = op.open(0, access, OPEN4_SHARE_DENY_NONE,
                      oowner, how, claim)
    res = sess1.compound([op.putfh(fh), open_op])
    check(res)

    stateid = res.resarray[-1].stateid
    stateid.seqid = 0
    data = b"write test data"
    res = sess1.compound([op.putfh(fh), op.write(stateid, 5, FILE_SYNC4, data)])
    check(res)
    res = sess1.compound([op.putfh(fh), op.read(stateid, 0, 1000)])
    check(res)
    if not res.resarray[-1].eof:
        fail("EOF not set on read")
    desired = b"\0"*5 + data
    if res.resarray[-1].data != desired:
        fail("Expected %r, got %r" % (desired, res.resarray[-1].data))

    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testCloseWithZeroSeqid(t, env):
    """OPEN followed by CLOSE with stateid.seq = 0

    FLAGS: open all
    CODE: OPEN8
    """
    sess1 = env.c1.new_client_session(env.testname(t))
    res = create_file(sess1, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid
    stateid.seqid = 0
    res = close_file(sess1, fh, stateid=stateid)
    check(res)

def testSuppattrExclcreat(t, env):
    """Check that FATTR4_SUPPATTR_EXCLCREAT is supported and valid

    FLAGS: open all
    CODE: OPEN12
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = sess.compound([op.putrootfh(),
                        op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS,
                                                         FATTR4_SUPPATTR_EXCLCREAT]))])
    check(res)
    attrs_info = res.resarray[-1].obj_attributes

    if FATTR4_SUPPORTED_ATTRS not in attrs_info:
        fail("Server did not return FATTR4_SUPPORTED_ATTRS")

    # Check if SUPPATTR_EXCLCREAT is in the supported attributes
    supported = attrs_info[FATTR4_SUPPORTED_ATTRS]
    if not (supported & (1 << FATTR4_SUPPATTR_EXCLCREAT)):
        unsupported("Server does not support FATTR4_SUPPATTR_EXCLCREAT")

    # If supported, check that it was returned
    if FATTR4_SUPPATTR_EXCLCREAT not in attrs_info:
        fail("FATTR4_SUPPATTR_EXCLCREAT not returned even though it "
             "appears in FATTR4_SUPPORTED_ATTRS")

def testSuppattrExclcreatSubset(t, env):
    """FATTR4_SUPPATTR_EXCLCREAT must be subset of SUPPORTED_ATTRS

    FLAGS: open all
    CODE: OPEN13
    DEPEND: OPEN12
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = sess.compound([op.putrootfh(),
                        op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS,
                                                         FATTR4_SUPPATTR_EXCLCREAT]))])
    check(res)
    attrs_info = res.resarray[-1].obj_attributes

    supported = attrs_info[FATTR4_SUPPORTED_ATTRS]
    excl_supported = attrs_info[FATTR4_SUPPATTR_EXCLCREAT]

    # SUPPATTR_EXCLCREAT must be a subset of SUPPORTED_ATTRS
    # i.e., every bit set in excl_supported must also be set in supported
    invalid = excl_supported & ~supported
    if invalid != 0:
        fail("FATTR4_SUPPATTR_EXCLCREAT contains attributes not in "
             "FATTR4_SUPPORTED_ATTRS:\n"
             "  Invalid attributes: %s" % nfs4lib.attr_bitmap_to_str(invalid))

def testACLSupported(t, env):
    """Check that server supports FATTR4_ACL attribute

    FLAGS: open acl all
    CODE: OPEN8a
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = sess.compound([op.putrootfh(),
                        op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPORTED_ATTRS]))])
    check(res)
    attrs_info = res.resarray[-1].obj_attributes
    if FATTR4_SUPPORTED_ATTRS not in attrs_info:
        fail("Server did not return FATTR4_SUPPORTED_ATTRS")
    supported = attrs_info[FATTR4_SUPPORTED_ATTRS]
    if not (supported & (1 << FATTR4_ACL)):
        unsupported("Server does not support FATTR4_ACL attribute")

def testACLExclusiveSupported(t, env):
    """Check that server supports setting ACL during EXCLUSIVE4_1 create

    FLAGS: open acl all
    CODE: OPEN8b
    """
    sess = env.c1.new_client_session(env.testname(t))
    res = sess.compound([op.putrootfh(),
                        op.getattr(nfs4lib.list2bitmap([FATTR4_SUPPATTR_EXCLCREAT]))])
    check(res)
    attrs_info = res.resarray[-1].obj_attributes
    if FATTR4_SUPPATTR_EXCLCREAT not in attrs_info:
        unsupported("Server does not support FATTR4_SUPPATTR_EXCLCREAT")
    excl_supported = attrs_info[FATTR4_SUPPATTR_EXCLCREAT]
    if not (excl_supported & (1 << FATTR4_ACL)):
        unsupported("Server does not support setting FATTR4_ACL during "
                    "EXCLUSIVE4_1 create")

def testOpenCreateWithACLUnchecked(t, env):
    """OPEN with UNCHECKED4 CREATE setting NFSv4 ACL attribute

    FLAGS: open acl all
    CODE: OPEN9
    DEPEND: OPEN8a
    """
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()

    # Create file with ACL attribute using UNCHECKED4 mode
    attrs = {FATTR4_MODE: 0o644, FATTR4_ACL: acl}
    res = create_file(sess, env.testname(t), attrs=attrs, mode=UNCHECKED4)
    check(res)
    expect(res, seqid=1)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Verify the ACL was set correctly by reading it back
    attrs_dict = do_getattrdict(sess, fh, [FATTR4_ACL])
    if FATTR4_ACL not in attrs_dict:
        fail("ACL attribute not returned after OPEN with CREATE")

    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenCreateWithACLGuarded(t, env):
    """OPEN with GUARDED4 CREATE setting NFSv4 ACL attribute

    FLAGS: open acl all
    CODE: OPEN10
    DEPEND: OPEN8a
    """
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()

    # Create file with ACL attribute using GUARDED4 mode
    attrs = {FATTR4_MODE: 0o644, FATTR4_ACL: acl}
    res = create_file(sess, env.testname(t), attrs=attrs, mode=GUARDED4)
    check(res)
    expect(res, seqid=1)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Verify the ACL was set correctly by reading it back
    attrs_dict = do_getattrdict(sess, fh, [FATTR4_ACL])
    if FATTR4_ACL not in attrs_dict:
        fail("ACL attribute not returned after OPEN with CREATE")

    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenCreateWithACLExclusive(t, env):
    """OPEN with EXCLUSIVE4_1 CREATE setting NFSv4 ACL attribute

    FLAGS: open acl all
    CODE: OPEN11
    DEPEND: OPEN8b
    """
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()

    # Create file with ACL attribute using EXCLUSIVE4_1 mode
    # EXCLUSIVE4_1 allows attributes to be set atomically with create
    # Don't set MODE with ACL - let the ACL determine permissions
    attrs = {FATTR4_ACL: acl}
    verifier = b"testverif"
    res = create_file(sess, env.testname(t), attrs=attrs,
                      mode=EXCLUSIVE4_1, verifier=verifier)
    check(res)
    expect(res, seqid=1)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Verify the ACL was set correctly by reading it back
    attrs_dict = do_getattrdict(sess, fh, [FATTR4_ACL])
    if FATTR4_ACL not in attrs_dict:
        fail("ACL attribute not returned after OPEN with CREATE")

    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenCreateModeWithACLExclusive(t, env):
    """OPEN with EXCLUSIVE4_1 setting both MODE and ACL

    FLAGS: open acl all
    CODE: OPEN14
    DEPEND: OPEN8b
    """
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()

    # Create file with both MODE and ACL using EXCLUSIVE4_1
    # This tests that server can handle both attributes together
    attrs = {FATTR4_MODE: 0o640, FATTR4_ACL: acl}
    verifier = b"testverif"
    res = create_file(sess, env.testname(t), attrs=attrs,
                      mode=EXCLUSIVE4_1, verifier=verifier)
    check(res)
    expect(res, seqid=1)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Verify both ACL and MODE were set correctly
    attrs_dict = do_getattrdict(sess, fh, [FATTR4_ACL, FATTR4_MODE])
    if FATTR4_ACL not in attrs_dict:
        fail("ACL attribute not returned after OPEN with CREATE")
    if FATTR4_MODE not in attrs_dict:
        fail("MODE attribute not returned after OPEN with CREATE")

    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenCreateModePreservedUnchecked(t, env):
    """Verify MODE derivation with ACL in UNCHECKED4 create

    Per RFC 8881 Section 6.4.1.3, when both MODE and ACL are set together,
    both are processed, but the final mode is derived from the ACL and may
    differ from the requested MODE.

    FLAGS: open acl all
    CODE: OPEN15
    DEPEND: OPEN8a
    """
    from nfs4acl import acl2mode_rfc8881
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()
    mode = 0o600

    # Create file with both MODE and ACL
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    res = create_file(sess, env.testname(t), attrs=attrs, mode=UNCHECKED4)
    check(res)
    expect(res, seqid=1)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Check which attributes were actually set by examining the reply bitmask
    attrset = nfs4lib.bitmap2list(res.resarray[-2].attrset)

    # Verify both MODE and ACL were set (processed)
    if FATTR4_MODE not in attrset:
        fail("MODE not in attrset, but MODE was requested")
    if FATTR4_ACL not in attrset:
        fail("ACL not in attrset, but ACL was requested")

    # Verify ACL was set correctly
    attrs_dict = do_getattrdict(sess, fh, [FATTR4_ACL, FATTR4_MODE])
    try:
        nfs4acl.verify_mode_and_acl(attrs_dict, acl, "OPEN with CREATE")
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenCreateModePreservedGuarded(t, env):
    """Verify MODE derivation with ACL in GUARDED4 create

    Per RFC 8881 Section 6.4.1.3, when both MODE and ACL are set together,
    both are processed, but the final mode is derived from the ACL and may
    differ from the requested MODE.

    FLAGS: open acl all
    CODE: OPEN16
    DEPEND: OPEN8a
    """
    from nfs4acl import acl2mode_rfc8881
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()
    mode = 0o640

    # Create file with both MODE and ACL
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    res = create_file(sess, env.testname(t), attrs=attrs, mode=GUARDED4)
    check(res)
    expect(res, seqid=1)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Check which attributes were actually set by examining the reply bitmask
    attrset = nfs4lib.bitmap2list(res.resarray[-2].attrset)

    # Verify both MODE and ACL were set (processed)
    if FATTR4_MODE not in attrset:
        fail("MODE not in attrset, but MODE was requested")
    if FATTR4_ACL not in attrset:
        fail("ACL not in attrset, but ACL was requested")

    # Verify ACL was set correctly
    attrs_dict = do_getattrdict(sess, fh, [FATTR4_ACL, FATTR4_MODE])
    try:
        nfs4acl.verify_mode_and_acl(attrs_dict, acl, "OPEN with CREATE")
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenCreateModePreservedExclusive(t, env):
    """Verify MODE derivation with ACL in EXCLUSIVE4_1 create

    Per RFC 8881 Section 6.4.1.3, when both MODE and ACL are set together,
    both are processed, but the final mode is derived from the ACL and may
    differ from the requested MODE.

    FLAGS: open acl all
    CODE: OPEN17
    DEPEND: OPEN8b
    """
    from nfs4acl import acl2mode_rfc8881
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()
    mode = 0o600

    # Create file with both MODE and ACL using EXCLUSIVE4_1
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    verifier = b"testverif"
    res = create_file(sess, env.testname(t), attrs=attrs,
                      mode=EXCLUSIVE4_1, verifier=verifier)
    check(res)
    expect(res, seqid=1)

    fh = res.resarray[-1].object
    stateid = res.resarray[-2].stateid

    # Check which attributes were actually set by examining the reply bitmask
    attrset = nfs4lib.bitmap2list(res.resarray[-2].attrset)

    # Verify both MODE and ACL were set (processed)
    if FATTR4_MODE not in attrset:
        fail("MODE not in attrset, but MODE was requested")
    if FATTR4_ACL not in attrset:
        fail("ACL not in attrset, but ACL was requested")

    # Verify ACL was set correctly
    attrs_dict = do_getattrdict(sess, fh, [FATTR4_ACL, FATTR4_MODE])
    try:
        nfs4acl.verify_mode_and_acl(attrs_dict, acl, "OPEN with CREATE")
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh, stateid=stateid)
    check(res)

def testOpenCreateRestrictiveModeWithACL(t, env):
    """Test OPEN CREATE with restrictive MODE and ACL together

    Test all three create modes with a restrictive MODE (0o400) and ACL
    to ensure the server handles the interaction correctly. The MODE
    being more restrictive than the ACL is an interesting edge case.

    FLAGS: open acl all
    CODE: OPEN18
    DEPEND: OPEN8a OPEN8b
    """
    sess = env.c1.new_client_session(env.testname(t))
    acl = nfs4acl.make_test_acl()
    mode = 0o400  # Read-only for owner

    # Test UNCHECKED4
    name1 = env.testname(t) + b"_unchecked"
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    res = create_file(sess, name1, attrs=attrs, mode=UNCHECKED4)
    check(res)
    fh1 = res.resarray[-1].object
    stateid1 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh1, [FATTR4_ACL, FATTR4_MODE])
    if FATTR4_ACL not in attrs_dict or FATTR4_MODE not in attrs_dict:
        fail("ACL or MODE not returned after UNCHECKED4 CREATE")
    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh1, stateid=stateid1)
    check(res)

    # Test GUARDED4
    name2 = env.testname(t) + b"_guarded"
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    res = create_file(sess, name2, attrs=attrs, mode=GUARDED4)
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh2, [FATTR4_ACL, FATTR4_MODE])
    if FATTR4_ACL not in attrs_dict or FATTR4_MODE not in attrs_dict:
        fail("ACL or MODE not returned after GUARDED4 CREATE")
    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh2, stateid=stateid2)
    check(res)

    # Test EXCLUSIVE4_1
    name3 = env.testname(t) + b"_exclusive"
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    verifier = b"testverif"
    res = create_file(sess, name3, attrs=attrs,
                      mode=EXCLUSIVE4_1, verifier=verifier)
    check(res)
    fh3 = res.resarray[-1].object
    stateid3 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh3, [FATTR4_ACL, FATTR4_MODE])
    if FATTR4_ACL not in attrs_dict or FATTR4_MODE not in attrs_dict:
        fail("ACL or MODE not returned after EXCLUSIVE4_1 CREATE")
    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        fail(str(e))

    res = close_file(sess, fh3, stateid=stateid3)
    check(res)

#
# Tests for OPEN CREATE with MODE and ACL per RFC 8881 §6.4.3
#

def testOpenCreateModeDerivation(t, env):
    """OPEN CREATE with MODE should derive ACL from mode

    Per RFC 8881 §6.4.3: If just mode is given, the mode MUST be
    applied to the inherited/created ACL per §6.4.1.1. Test with
    UNCHECKED4, GUARDED4, and EXCLUSIVE4_1.

    FLAGS: open acl all
    CODE: OPEN38
    DEPEND: OPEN8a OPEN8b
    """
    from nfs4acl import acl2mode_rfc8881

    sess = env.c1.new_client_session(env.testname(t))

    # Test with UNCHECKED4
    mode = 0o640
    attrs = {FATTR4_MODE: mode}
    name1 = env.testname(t) + b"_unchecked"
    res = create_file(sess, name1, attrs=attrs, mode=UNCHECKED4)
    check(res)
    fh1 = res.resarray[-1].object
    stateid1 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh1, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    if result_mode != mode:
        fail("UNCHECKED4: mode (0%o) doesn't match requested (0%o)" %
             (result_mode, mode))

    acl_derived_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])
    if result_mode != acl_derived_mode:
        fail("UNCHECKED4: mode (0%o) doesn't match ACL derivation (0%o)" %
             (result_mode, acl_derived_mode))

    res = close_file(sess, fh1, stateid=stateid1)
    check(res)

    # Test with GUARDED4
    mode = 0o750
    attrs = {FATTR4_MODE: mode}
    name2 = env.testname(t) + b"_guarded"
    res = create_file(sess, name2, attrs=attrs, mode=GUARDED4)
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh2, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    if result_mode != mode:
        fail("GUARDED4: mode (0%o) doesn't match requested (0%o)" %
             (result_mode, mode))

    acl_derived_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])
    if result_mode != acl_derived_mode:
        fail("GUARDED4: mode (0%o) doesn't match ACL derivation (0%o)" %
             (result_mode, acl_derived_mode))

    res = close_file(sess, fh2, stateid=stateid2)
    check(res)

    # Test with EXCLUSIVE4_1
    mode = 0o755
    attrs = {FATTR4_MODE: mode}
    name3 = env.testname(t) + b"_exclusive"
    verifier = b"testverif"
    res = create_file(sess, name3, attrs=attrs,
                      mode=EXCLUSIVE4_1, verifier=verifier)
    check(res)
    fh3 = res.resarray[-1].object
    stateid3 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh3, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    if result_mode != mode:
        fail("EXCLUSIVE4_1: mode (0%o) doesn't match requested (0%o)" %
             (result_mode, mode))

    acl_derived_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])
    if result_mode != acl_derived_mode:
        fail("EXCLUSIVE4_1: mode (0%o) doesn't match ACL derivation (0%o)" %
             (result_mode, acl_derived_mode))

    res = close_file(sess, fh3, stateid=stateid3)
    check(res)

def testOpenCreateACLDerivation(t, env):
    """OPEN CREATE with ACL should derive mode from ACL

    Per RFC 8881 §6.4.3: If just ACL is given, inheritance SHOULD NOT
    take place, ACL should be set as given, and mode modified per §6.4.1.2.

    FLAGS: open acl all
    CODE: OPEN39
    DEPEND: OPEN8a OPEN8b
    """
    from nfs4acl import acl2mode_rfc8881

    sess = env.c1.new_client_session(env.testname(t))

    # Test with UNCHECKED4
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"GROUP@")
    ]
    attrs = {FATTR4_ACL: acl}
    name1 = env.testname(t) + b"_unchecked"
    res = create_file(sess, name1, attrs=attrs, mode=UNCHECKED4)
    check(res)
    fh1 = res.resarray[-1].object
    stateid1 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh1, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if result_mode != expected_mode:
        fail("UNCHECKED4: mode (0%o) doesn't match ACL derivation (0%o)" %
             (result_mode, expected_mode))

    res = close_file(sess, fh1, stateid=stateid1)
    check(res)

    # Test with GUARDED4
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_EXECUTE,
                b"OWNER@")
    ]
    attrs = {FATTR4_ACL: acl}
    name2 = env.testname(t) + b"_guarded"
    res = create_file(sess, name2, attrs=attrs, mode=GUARDED4)
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh2, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if result_mode != expected_mode:
        fail("GUARDED4: mode (0%o) doesn't match ACL derivation (0%o)" %
             (result_mode, expected_mode))

    res = close_file(sess, fh2, stateid=stateid2)
    check(res)

    # Test with EXCLUSIVE4_1
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_EXECUTE,
                b"GROUP@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"EVERYONE@")
    ]
    attrs = {FATTR4_ACL: acl}
    name3 = env.testname(t) + b"_exclusive"
    verifier = b"testverif"
    res = create_file(sess, name3, attrs=attrs,
                      mode=EXCLUSIVE4_1, verifier=verifier)
    check(res)
    fh3 = res.resarray[-1].object
    stateid3 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh3, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if result_mode != expected_mode:
        fail("EXCLUSIVE4_1: mode (0%o) doesn't match ACL derivation (0%o)" %
             (result_mode, expected_mode))

    res = close_file(sess, fh3, stateid=stateid3)
    check(res)

def testOpenCreateModeACLConflict(t, env):
    """OPEN CREATE with both MODE and ACL - ACL should win

    Per RFC 8881 §6.4.3: If both mode and ACL are given, both attributes
    will be set per §6.4.1.3 (MODE first, then ACL, with ACL modifying
    the final mode).

    FLAGS: open acl all
    CODE: OPEN40
    DEPEND: OPEN8a OPEN8b
    """
    from nfs4acl import acl2mode_rfc8881

    sess = env.c1.new_client_session(env.testname(t))

    # Test with UNCHECKED4: ACL would derive to 0754, request MODE 0640
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_EXECUTE,
                b"GROUP@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"EVERYONE@")
    ]
    mode = 0o640
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    name1 = env.testname(t) + b"_unchecked"
    res = create_file(sess, name1, attrs=attrs, mode=UNCHECKED4)
    check(res)
    fh1 = res.resarray[-1].object
    stateid1 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh1, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if result_mode != expected_mode:
        fail("UNCHECKED4: mode (0%o) doesn't match ACL derivation (0%o). "
             "Per §6.4.3, should follow §6.4.1.3 (ACL wins)" %
             (result_mode, expected_mode))

    res = close_file(sess, fh1, stateid=stateid1)
    check(res)

    # Test with GUARDED4
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA,
                b"OWNER@")
    ]
    mode = 0o755
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    name2 = env.testname(t) + b"_guarded"
    res = create_file(sess, name2, attrs=attrs, mode=GUARDED4)
    check(res)
    fh2 = res.resarray[-1].object
    stateid2 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh2, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if result_mode != expected_mode:
        fail("GUARDED4: mode (0%o) doesn't match ACL derivation (0%o). "
             "Per §6.4.3, should follow §6.4.1.3" %
             (result_mode, expected_mode))

    res = close_file(sess, fh2, stateid=stateid2)
    check(res)

    # Test with EXCLUSIVE4_1
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_EXECUTE,
                b"OWNER@")
    ]
    mode = 0o644
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    name3 = env.testname(t) + b"_exclusive"
    verifier = b"testverif"
    res = create_file(sess, name3, attrs=attrs,
                      mode=EXCLUSIVE4_1, verifier=verifier)
    check(res)
    fh3 = res.resarray[-1].object
    stateid3 = res.resarray[-2].stateid

    attrs_dict = do_getattrdict(sess, fh3, [FATTR4_MODE, FATTR4_ACL])
    result_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if result_mode != expected_mode:
        fail("EXCLUSIVE4_1: mode (0%o) doesn't match ACL derivation (0%o). "
             "Per §6.4.3, should follow §6.4.1.3" %
             (result_mode, expected_mode))

    res = close_file(sess, fh3, stateid=stateid3)
    check(res)
