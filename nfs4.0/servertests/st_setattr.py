from xdrdef.nfs4_const import *
from .environment import check, get_invalid_utf8strings
from nfs4lib import bitmap2list, dict2fattr
from xdrdef.nfs4_type import nfstime4, settime4, nfsace4
import nfs_ops
op = nfs_ops.NFS4ops()
import nfs4acl

def _set_mode(t, c, file, stateid=None, msg=" using stateid=0",
              warnlist=[]):
    mode = 0o740
    dict = {FATTR4_MODE: mode}
    ops = c.use_obj(file) + [c.setattr(dict, stateid)]
    res = c.compound(ops)
    check(res, msg="Setting mode to 0%o%s" % (mode, msg), warnlist=warnlist)
    check_res(t, c, res, file, dict)

def _set_size(t, c, file, stateid=None, msg=" using stateid=0"):
    startsize = c.do_getattr(FATTR4_SIZE, file)
    newsize = startsize + 10
    dict = {FATTR4_SIZE: newsize}
    ops = c.use_obj(file) + [c.setattr(dict, stateid)]
    res = c.compound(ops)
    check(res, msg="Changing size from %i to %i%s" % (startsize, newsize, msg),
          warnlist=[NFS4ERR_BAD_STATEID])
    check_res(t, c, res, file, dict)
    dict = {FATTR4_SIZE: 0}
    ops = c.use_obj(file) + [c.setattr(dict, stateid)]
    res = c.compound(ops)
    check(res, msg="Changing size from %i to 0" % newsize)
    check_res(t, c, res, file, dict)

#
# Mix size and non-size attributes in a single SETATTR.  Some Linux file
# systems aren't happy with this mix, and a server passing this on 1:1
# will trigger warnings or incorrect results.
#
def _set_mixed(t, c, file, stateid=None, msg=" using stateid=0"):
    startsize = c.do_getattr(FATTR4_SIZE, file)
    newsize = startsize + 10
    owner = b"65534" # nobody

    dict = {FATTR4_SIZE: newsize, FATTR4_OWNER: owner}
    ops = c.use_obj(file) + [c.setattr(dict, stateid)]
    res = c.compound(ops)
    check(res, msg="Changing size from %i to %i and owner to %s%s" %
          (startsize, newsize, owner, msg), warnlist=[NFS4ERR_BAD_STATEID])
    check_res(t, c, res, file, dict)

def _try_readonly(t, env, path):
    c = env.c1
    baseops = c.use_obj(path)
    supported = c.supportedAttrs(path)
    attrlist = [attr for attr in env.attr_info if attr.readonly]
    for attr in attrlist:
        ops = baseops + [c.setattr({attr.bitnum: attr.sample})]
        res = c.compound(ops)
        if supported & attr.mask:
            check(res, NFS4ERR_INVAL,
                  "SETATTR the supported read-only attribute %s" % attr.name)
        else:
            check(res, [NFS4ERR_INVAL, NFS4ERR_ATTRNOTSUPP],
                  "SETATTR the unsupported read-only attribute %s" % attr.name)

def _try_unsupported(t, env, path):
    c = env.c1
    baseops = c.use_obj(path)
    supported = c.supportedAttrs(path)
    attrlist = [ attr for attr in env.attr_info
                 if attr.writable and not supported & attr.mask ]
    for attr in attrlist:
        ops = baseops + [c.setattr({attr.bitnum: attr.sample})]
        res = c.compound(ops)
        check(res, NFS4ERR_ATTRNOTSUPP, 
              "SETATTR with unsupported attr %s" % attr.name)

def check_res(t, c, res, file, dict):
    modified = bitmap2list(res.resarray[-1].attrsset)
    for attr in modified:
        if attr not in dict:
            t.fail("attrsset contained %s, which was not requested" %
                   get_bitnumattr_dict()[attr])
    newdict = c.do_getattrdict(file, dict.keys())
    if newdict != dict:
        t.fail("Set attrs %s not equal to got attrs %s" % (dict, newdict))

########################################

def testMode(t, env):
    """See if FATTR4_MODE is supported

    FLAGS: all
    CODE: MODE
    """
    if not FATTR4_MODE & env.c1.supportedAttrs():
        t.fail_support("Server does not support FATTR4_MODE")


def testFile(t, env):
    """SETATTR(FATTR4_MODE) on regular file

    FLAGS: setattr file all
    DEPEND: MODE MKFILE
    CODE: SATT1r
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    _set_mode(t, c, fh)

def testDir(t, env):
    """SETATTR(FATTR4_MODE) on directory

    FLAGS: setattr dir all
    DEPEND: MODE MKDIR
    CODE: SATT1d
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path)
    _set_mode(t, c, path)

def testLink(t, env):
    """SETATTR(FATTR4_MODE) on symlink

    FLAGS:
    DEPEND: MODE MKLINK
    CODE: SATT1a
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4LNK)
    _set_mode(t, c, path)

def testBlock(t, env):
    """SETATTR(FATTR4_MODE) on block device

    FLAGS: setattr block all
    DEPEND: MODE MKBLK
    CODE: SATT1b
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4BLK)
    _set_mode(t, c, path)

def testChar(t, env):
    """SETATTR(FATTR4_MODE) on character device

    FLAGS: setattr char all
    DEPEND: MODE MKCHAR
    CODE: SATT1c
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4CHR)
    _set_mode(t, c, path)

def testFifo(t, env):
    """SETATTR(FATTR4_MODE) on fifo

    FLAGS: setattr fifo all
    DEPEND: MODE MKFIFO
    CODE: SATT1f
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4FIFO)
    _set_mode(t, c, path)

def testSocket(t, env):
    """SETATTR(FATTR4_MODE) on socket

    FLAGS: setattr socketall ganesha
    DEPEND: MODE MKSOCK
    CODE: SATT1s
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4SOCK)
    _set_mode(t, c, path)

def testUselessStateid1(t, env):
    """SETATTR(FATTR4_MODE) on file with stateid = ones

    FLAGS: setattr file all
    DEPEND: MODE MKFILE
    CODE: SATT2a
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    _set_mode(t, c, fh, env.stateid1, " using stateid=1")

def testUselessStateid2(t, env):
    """SETATTR(FATTR4_MODE) on file with openstateid

    FLAGS: setattr file all
    DEPEND: MODE MKFILE
    CODE: SATT2b
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    _set_mode(t, c, fh, stateid, " using openstateid")

def testUselessStateid3(t, env):
    """SETATTR(FATTR4_MODE) on file with different file's openstateid

    FLAGS: setattr file all
    DEPEND: MODE MKFILE MKDIR
    CODE: SATT2c
    """
    c = env.c1
    c.init_connection()
    c.maketree([t.word(), b'file'])
    path = c.homedir + [t.word(), t.word()]
    fh, stateid = c.create_confirm(t.word(), path)
    _set_mode(t, c, c.homedir + [t.word(), b'file'], stateid,
              " using bad openstateid", [NFS4ERR_BAD_STATEID])

# FRED - redo first 2 tests with _DENY_WRITE
def testResizeFile0(t, env):
    """SETATTR(FATTR4_SIZE) on file with stateid = 0

    FLAGS: setattr file all
    DEPEND: MKFILE
    CODE: SATT3a
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word(), deny=OPEN4_SHARE_DENY_NONE)
    _set_size(t, c, fh)
    
def testResizeFile1(t, env):
    """SETATTR(FATTR4_SIZE) on file with stateid = 1

    FLAGS: setattr file all
    DEPEND: MKFILE
    CODE: SATT3b
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word(), deny=OPEN4_SHARE_DENY_NONE)
    _set_size(t, c, fh, env.stateid1, " using stateid=1")
    
def testResizeFile2(t, env):
    """SETATTR(FATTR4_SIZE) on file with openstateid

    FLAGS: setattr file all
    DEPEND: MKFILE
    CODE: SATT3c
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    _set_size(t, c, fh, stateid, " using openstateid")
    
def testResizeFile3(t, env):
    """SETATTR(FATTR4_SIZE) with wrong openstateid should return _BAD_STATEID

    FLAGS: setattr file all
    DEPEND: MKFILE MKDIR
    CODE: SATT3d
    """
    c = env.c1
    c.init_connection()
    c.maketree([t.word(), b'file'])
    path = c.homedir + [t.word(), t.word()]
    fh, stateid = c.create_confirm(t.word(), path)
    ops = c.use_obj(c.homedir + [t.word(), b'file'])
    ops += [c.setattr({FATTR4_SIZE: 10}, stateid)]
    res = c.compound(ops)
    check(res, NFS4ERR_BAD_STATEID, "SETATTR(_SIZE) with wrong openstateid")

def testOpenModeResize(t, env):
    """SETATTR(_SIZE) on file with _ACCESS_READ should return NFS4ERR_OPENMODE

    FLAGS: setattr file all
    DEPEND: MKFILE
    CODE: SATT4
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word(), access=OPEN4_SHARE_ACCESS_READ)
    ops = c.use_obj(fh) + [c.setattr({FATTR4_SIZE: 10}, stateid)]
    res = c.compound(ops)
    check(res, NFS4ERR_OPENMODE, "SETATTR(_SIZE) on file with _ACCESS_READ")

def testNoFh(t, env):
    """SETATTR with no (cfh) should return NFS4ERR_NOFILEHANDLE

    FLAGS: setattr emptyfh all
    CODE: SATT5
    """
    c = env.c1
    res = c.compound([c.setattr({FATTR4_SIZE:0})])
    check(res, NFS4ERR_NOFILEHANDLE, "SETATTR with no <cfh>")

def testReadonlyFile(t, env):
    """SETATTR on read-only attrs should return NFS4ERR_INVAL

    FLAGS: setattr file all
    DEPEND: MKFILE
    CODE: SATT6r
    """
    c = env.c1
    c.init_connection()
    c.create_confirm(t.word())
    _try_readonly(t, env, c.homedir + [t.word()])

def testReadonlyDir(t, env):
    """SETATTR on read-only attrs should return NFS4ERR_INVAL

    FLAGS: setattr dir all
    DEPEND: MKDIR
    CODE: SATT6d
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path)
    check(res)
    _try_readonly(t, env, path)

def testReadonlyLink(t, env):
    """SETATTR on read-only attrs should return NFS4ERR_INVAL

    FLAGS: setattr symlink all
    DEPEND: MKLINK SATT6d
    CODE: SATT6a
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4LNK)
    check(res)
    _try_readonly(t, env, path)

def testReadonlyBlock(t, env):
    """SETATTR on read-only attrs should return NFS4ERR_INVAL

    FLAGS: setattr block all
    DEPEND: MKBLK SATT6d
    CODE: SATT6b
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4BLK)
    check(res)
    _try_readonly(t, env, path)

def testReadonlyChar(t, env):
    """SETATTR on read-only attrs should return NFS4ERR_INVAL

    FLAGS: setattr char all
    DEPEND: MKCHAR SATT6d
    CODE: SATT6c
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4CHR)
    check(res)
    _try_readonly(t, env, path)

def testReadonlyFifo(t, env):
    """SETATTR on read-only attrs should return NFS4ERR_INVAL

    FLAGS: setattr fifo all
    DEPEND: MKFIFO SATT6d
    CODE: SATT6f
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4FIFO)
    check(res)
    _try_readonly(t, env, path)

def testReadonlySocket(t, env):
    """SETATTR on read-only attrs should return NFS4ERR_INVAL

    FLAGS: setattr socket all
    DEPEND: MKSOCK SATT6d
    CODE: SATT6s
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4SOCK)
    check(res)
    _try_readonly(t, env, path)

def testInvalidAttr1(t, env):
    """SETATTR with invalid attribute data should return NFS4ERR_BADXDR

    This testcase try to set FATTR4_MODE but does not send any mode data.

    FLAGS: setattr all
    DEPEND: MODE MKDIR
    CODE: SATT7
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path)
    check(res)
    badattr = dict2fattr({FATTR4_MODE: 0o644})
    badattr.attr_vals = b''
    res = c.compound(c.use_obj(path) + [op.setattr(env.stateid0, badattr)])
    check(res, NFS4ERR_BADXDR, "SETATTR(FATTR4_MODE) with no data")

def testInvalidAttr2(t, env):
    """SETATTR with extraneous attribute data should return NFS4ERR_BADXDR

    This testcase try to set FATTR4_MODE with extraneous attribute data
    appended

    FLAGS: setattr all
    DEPEND: MODE MKDIR
    CODE: SATT8
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path)
    check(res)
    badattr = dict2fattr({FATTR4_MODE: 0o644})
    badattr.attr_vals += b'Garbage data'
    res = c.compound(c.use_obj(path) + [op.setattr(env.stateid0, badattr)])
    check(res, NFS4ERR_BADXDR,
          "SETATTR(FATTR4_MODE) with extraneous attribute data appended")

def testNonUTF8(t, env):
    """SETATTR(_MIMETYPE) with non-utf8 string should return NFS4ERR_INVAL

    The only attributes that use utf8 are MIMETYPE, OWNER, GROUP, and ACL.
    OWNER and GROUP are subject to too many restrictions to use.
    Similarly for ACL.

    FLAGS: setattr utf8 ganesha
    DEPEND: MKFILE
    CODE: SATT9
    """
    c = env.c1
    c.create_confirm(t.word())
    supported = c.supportedAttrs()
    if not (supported & 2**FATTR4_MIMETYPE):
        t.fail_support("FATTR4_MIMETYPE not supported")
    baseops = c.use_obj(c.homedir + [t.word()])
    for name in get_invalid_utf8strings():
        ops = baseops + [c.setattr({FATTR4_MIMETYPE: name})]
        res = c.compound(ops)
        check(res, NFS4ERR_INVAL,
              "SETATTR(_MIMETYPE) with non-utf8 string %s" % repr(name))

def testInvalidTime(t, env):
    """SETATTR(FATTR4_TIME_MODIFY_SET) with invalid nseconds

    nseconds larger than 999999999 are considered invalid.
    SETATTR(FATTR4_TIME_MODIFY_SET) should return NFS4ERR_INVAL on
    such values. 

    FLAGS: setattr all
    DEPEND: MKDIR
    CODE: SATT10
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path)
    check(res)
    supported = c.supportedAttrs()
    if not (supported & 2**FATTR4_TIME_MODIFY_SET):
        t.fail_support("FATTR4_TIME_MODIFY_SET not supported")
    time = nfstime4(seconds=500000000, nseconds=int(1E9))
    settime = settime4(set_it=SET_TO_CLIENT_TIME4, time=time)
    ops = c.use_obj(path) + [c.setattr({FATTR4_TIME_MODIFY_SET: settime})]
    res = c.compound(ops)
    check(res, NFS4ERR_INVAL,
          "SETATTR(FATTR4_TIME_MODIFY_SET) with nseconds=1E9")

def testUnsupportedFile(t, env):
    """SETATTR with unsupported attr should return NFS4ERR_ATTRNOTSUPP

    FLAGS: setattr file all
    DEPEND: MKFILE
    CODE: SATT11r
    """
    c = env.c1
    c.init_connection()
    c.create_confirm(t.word())
    _try_unsupported(t, env, c.homedir + [t.word()])

def testUnsupportedDir(t, env):
    """SETATTR with unsupported attr should return NFS4ERR_ATTRNOTSUPP

    FLAGS: setattr dir all
    DEPEND: MKDIR
    CODE: SATT11d
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path)
    check(res)
    _try_unsupported(t, env, path)

def testUnsupportedLink(t, env):
    """SETATTR with unsupported attr should return NFS4ERR_ATTRNOTSUPP

    FLAGS: setattr symlink all
    DEPEND: MKLINK
    CODE: SATT11a
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4LNK)
    check(res)
    _try_unsupported(t, env, path)

def testUnsupportedBlock(t, env):
    """SETATTR with unsupported attr should return NFS4ERR_ATTRNOTSUPP

    FLAGS: setattr block all
    DEPEND: MKBLK
    CODE: SATT11b
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4BLK)
    check(res)
    _try_unsupported(t, env, path)

def testUnsupportedChar(t, env):
    """SETATTR with unsupported attr should return NFS4ERR_ATTRNOTSUPP

    FLAGS: setattr char all
    DEPEND: MKCHAR
    CODE: SATT11c
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4CHR)
    check(res)
    _try_unsupported(t, env, path)

def testUnsupportedFifo(t, env):
    """SETATTR with unsupported attr should return NFS4ERR_ATTRNOTSUPP

    FLAGS: setattr fifo all
    DEPEND: MKFIFO
    CODE: SATT11f
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4FIFO)
    check(res)
    _try_unsupported(t, env, path)

def testUnsupportedSocket(t, env):
    """SETATTR with unsupported attr should return NFS4ERR_ATTRNOTSUPP

    FLAGS: setattr socket all
    DEPEND: MKSOCK
    CODE: SATT11s
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4SOCK)
    check(res)
    _try_unsupported(t, env, path)

def testMaxSizeFile(t, env):
    """SETATTR(U64_MAX) of a file should return NFS4_OK or NFS4ERR_FBIG

    FLAGS: setattr all
    DEPEND: INIT
    CODE: SATT12x
    """
    maxsize = 0xffffffffffffffff
    c = env.c1
    fh, stateid = c.create_confirm(t.word(), deny=OPEN4_SHARE_DENY_NONE)
    dict = {FATTR4_SIZE: maxsize}
    ops = c.use_obj(fh) + [c.setattr(dict, stateid)]
    res = c.compound(ops)
    check(res, [NFS4_OK, NFS4ERR_FBIG], "SETATTR(U64_MAX) of a file")
    newsize = c.do_getattr(FATTR4_SIZE, fh)
    if newsize != maxsize:
        check(res, [NFS4ERR_INVAL, NFS4ERR_FBIG],
                "File size is %i; SETATTR" % newsize)

def testSizeDir(t, env):
    """SETATTR(_SIZE) of a directory should return NFS4ERR_ISDIR or NFS4ERR_BAD_STATEID

    FLAGS: setattr dir all
    DEPEND: MKDIR
    CODE: SATT12d
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_SIZE: 0})]
    res = c.compound(ops)
    check(res, [NFS4ERR_ISDIR, NFS4ERR_BAD_STATEID], "SETATTR(_SIZE) of a directory")
    
def testSizeLink(t, env):
    """SETATTR(FATTR4_SIZE) of a non-file object should return NFS4ERR_INVAL or NFS4ERR_BAD_STATEID

    FLAGS: setattr symlink all
    DEPEND: MKLINK
    CODE: SATT12a
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4LNK)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_SIZE: 0})]
    res = c.compound(ops)
    check(res, [NFS4ERR_INVAL, NFS4ERR_SYMLINK, NFS4ERR_BAD_STATEID],
            "SETATTR(FATTR4_SIZE) of a symlink")
    
def testSizeBlock(t, env):
    """SETATTR(FATTR4_SIZE) of a non-file object should return NFS4ERR_INVAL or NFS4ERR_BAD_STATEID

    FLAGS: setattr block all
    DEPEND: MKBLK
    CODE: SATT12b
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4BLK)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_SIZE: 0})]
    res = c.compound(ops)
    check(res, [NFS4ERR_INVAL, NFS4ERR_BAD_STATEID], "SETATTR(FATTR4_SIZE) of a block device")
    
def testSizeChar(t, env):
    """SETATTR(FATTR4_SIZE) of a non-file object should return NFS4ERR_INVAL or NFS4ERR_BAD_STATEID

    FLAGS: setattr char all
    DEPEND: MKCHAR
    CODE: SATT12c
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4CHR)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_SIZE: 0})]
    res = c.compound(ops)
    check(res, [NFS4ERR_INVAL, NFS4ERR_BAD_STATEID], "SETATTR(FATTR4_SIZE) of a character device")
    
def testSizeFifo(t, env):
    """SETATTR(FATTR4_SIZE) of a non-file object should return NFS4ERR_INVAL or NFS4ERR_BAD_STATEID

    FLAGS: setattr fifo all
    DEPEND: MKFIFO
    CODE: SATT12f
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4FIFO)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_SIZE: 0})]
    res = c.compound(ops)
    check(res, [NFS4ERR_INVAL, NFS4ERR_BAD_STATEID], "SETATTR(FATTR4_SIZE) of a fifo")

def testSizeSocket(t, env):
    """SETATTR(FATTR4_SIZE) of a non-file object should return NFS4ERR_INVAL or NFS4ERR_BAD_STATEID

    FLAGS: setattr socket all
    DEPEND: MKSOCK
    CODE: SATT12s
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4SOCK)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_SIZE: 0})]
    res = c.compound(ops)
    check(res, [NFS4ERR_INVAL, NFS4ERR_BAD_STATEID], "SETATTR(FATTR4_SIZE) of a socket")

def testInodeLocking(t, env):
    """SETATTR: This causes printk message due to inode locking bug

    log shows - nfsd: inode locked twice during operation.
    Sporadic system crashes can occur after running this test

    FLAGS: setattr all
    DEPEND: MODE MKDIR MKFILE
    CODE: SATT13
    """
    #t.fail("Test set to fail without running.  Currently causes "
    #       "inode corruption leading to sporadic system crashes.")
    c = env.c1
    c.init_connection()
    basedir = c.homedir + [t.word()]
    res = c.create_obj(basedir)
    check(res)
    fh, stateid = c.create_confirm(t.word(), basedir + [b'file'])
    
    # In a single compound statement, setattr on dir and then
    # do a state operation on a file in dir (like write or remove)
    ops = c.use_obj(basedir) + [c.setattr({FATTR4_MODE:0o754})]
    ops += [op.lookup(b'file'), op.write(stateid, 0, 0, b'blahblah')]
    res = c.compound(ops)
    check(res, msg="SETATTR on dir and state operation on file in dir")

def testChange(t, env):
    """SETATTR(MODE) should change changeattr

    FLAGS: setattr all
    DEPEND: MODE MKFILE
    CODE: SATT14
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    change = c.do_getattr(FATTR4_CHANGE, fh)
    ops = c.use_obj(fh) + [c.setattr({FATTR4_MODE: 0o740})]
    res = c.compound(ops)
    check(res)
    change2 = c.do_getattr(FATTR4_CHANGE, fh)
    if change == change2:
        t.fail("change attribute not affected by SETATTR(mode)")

def testChangeGranularity(t, env):
    """Rapidly repeated SETATTR(MODE) should change changeattr

    FLAGS: setattr all
    DEPEND: MODE MKFILE
    CODE: SATT15
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())
    ops = c.use_obj(fh) + [c.getattr([FATTR4_CHANGE])] \
        + [c.setattr({FATTR4_MODE: 0o740})] + [c.getattr([FATTR4_CHANGE])] \
        + [c.setattr({FATTR4_MODE: 0o741})] + [c.getattr([FATTR4_CHANGE])] \
        + [c.setattr({FATTR4_MODE: 0o742})] + [c.getattr([FATTR4_CHANGE])] \
        + [c.setattr({FATTR4_MODE: 0o743})] + [c.getattr([FATTR4_CHANGE])]
    res = c.compound(ops)
    check(res)
    chattr1 = res.resarray[1].obj_attributes
    chattr2 = res.resarray[3].obj_attributes
    chattr3 = res.resarray[5].obj_attributes
    chattr4 = res.resarray[7].obj_attributes
    if chattr1 == chattr2 or chattr2 == chattr3 or chattr3 == chattr4:
        t.fail("consecutive SETATTR(mode)'s don't all change change attribute")

def testEmptyPrincipal(t, env):
    """Setting owner with zero length principal must fail

    FLAGS: setattr all
    DEPEND: MKFILE
    CODE: SATT16
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4SOCK)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_OWNER: b''})]
    res = c.compound(ops)
    check(res, NFS4ERR_INVAL, "Setting empty owner")


def testEmptyGroupPrincipal(t, env):
    """Setting owner group with zero length principal must fail

    FLAGS: setattr all
    DEPEND: MKFILE
    CODE: SATT17
    """
    c = env.c1
    path = c.homedir + [t.word()]
    res = c.create_obj(path, NF4SOCK)
    check(res)
    ops = c.use_obj(path) + [c.setattr({FATTR4_OWNER_GROUP: b''})]
    res = c.compound(ops)
    check(res, NFS4ERR_INVAL, "Setting empty owner_group")


def testMixed(t, env):
    """SETATTR(FATTR4_SIZE + FATTR4_OWNER) on file with stateid = 0

    FLAGS: setattr file all
    DEPEND: MKFILE
    CODE: SATT18
    """
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word(), deny=OPEN4_SHARE_DENY_NONE)
    _set_mixed(t, c, fh)

def testSetattrModeWithACL(t, env):
    """SETATTR with both MODE and ACL attributes

    Per RFC 8881 Section 6.4.1.3, when both MODE and ACL are set together,
    both are processed, but the final mode is derived from the ACL and may
    differ from the requested MODE.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT19
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())

    acl = nfs4acl.make_test_acl()
    mode = 0o640

    # Set both MODE and ACL in a single SETATTR
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    ops = c.use_obj(fh) + [c.setattr(attrs)]
    res = c.compound(ops)
    check(res, msg="SETATTR with both MODE and ACL")

    # Check which attributes were actually set by examining the reply bitmask
    attrsset = bitmap2list(res.resarray[-1].attrsset)

    # Verify both MODE and ACL were set (processed)
    if FATTR4_MODE not in attrsset:
        t.fail("MODE not in attrsset, but MODE was requested")
    if FATTR4_ACL not in attrsset:
        t.fail("ACL not in attrsset, but ACL was requested")

    # Verify ACL was set correctly
    attrs_dict = c.do_getattrdict(fh, [FATTR4_ACL, FATTR4_MODE])
    try:
        returned_mode, expected_mode = nfs4acl.verify_mode_and_acl(
            attrs_dict, acl, "SETATTR")
    except AssertionError as e:
        t.fail(str(e))

    # Display informational message about mode derivation
    if returned_mode != mode:
        t.pass_warn("MODE+ACL: requested 0%o, final 0%o (derived from ACL per RFC 8881 §6.3.2)"
                    % (mode, returned_mode))

def testSetattrModePreservedWithACL(t, env):
    """Verify MODE derivation when SETATTR sets both MODE and ACL

    Per RFC 8881 Section 6.4.1.3, when both MODE and ACL are set together,
    both are processed, but the final mode is derived from the ACL and may
    differ from the requested MODE.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT20
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())

    acl = nfs4acl.make_test_acl()
    mode = 0o600

    # Set both MODE and ACL
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    ops = c.use_obj(fh) + [c.setattr(attrs)]
    res = c.compound(ops)
    check(res, msg="SETATTR with MODE and ACL")

    # Check which attributes were actually set by examining the reply bitmask
    attrsset = bitmap2list(res.resarray[-1].attrsset)

    # Verify both MODE and ACL were set (processed)
    if FATTR4_MODE not in attrsset:
        t.fail("MODE not in attrsset, but MODE was requested")
    if FATTR4_ACL not in attrsset:
        t.fail("ACL not in attrsset, but ACL was requested")

    # Verify ACL was set correctly
    attrs_dict = c.do_getattrdict(fh, [FATTR4_ACL, FATTR4_MODE])
    try:
        returned_mode, expected_mode = nfs4acl.verify_mode_and_acl(
            attrs_dict, acl, "SETATTR")
    except AssertionError as e:
        t.fail(str(e))

    # Display informational message about mode derivation
    if returned_mode != mode:
        t.pass_warn("MODE+ACL: requested 0%o, final 0%o (derived from ACL per RFC 8881 §6.3.2)"
                    % (mode, returned_mode))

def testSetattrRestrictiveModeWithACL(t, env):
    """SETATTR with restrictive MODE (0o400) and ACL together

    Per RFC 8881 Section 6.4.1.3, when both MODE and ACL are set together,
    both are processed, but the final mode is derived from the ACL and may
    differ from the requested MODE. This tests the case where the requested
    MODE is more restrictive than what the ACL would grant.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT21
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()
    fh, stateid = c.create_confirm(t.word())

    acl = nfs4acl.make_test_acl()
    mode = 0o400  # Read-only for owner

    # Set restrictive MODE with ACL
    attrs = {FATTR4_MODE: mode, FATTR4_ACL: acl}
    ops = c.use_obj(fh) + [c.setattr(attrs)]
    res = c.compound(ops)
    check(res, msg="SETATTR with restrictive MODE and ACL")

    # Check which attributes were actually set by examining the reply bitmask
    attrsset = bitmap2list(res.resarray[-1].attrsset)

    # Verify both MODE and ACL were set (processed)
    if FATTR4_MODE not in attrsset:
        t.fail("MODE not in attrsset, but MODE was requested")
    if FATTR4_ACL not in attrsset:
        t.fail("ACL not in attrsset, but ACL was requested")

    # Verify ACL was set correctly
    attrs_dict = c.do_getattrdict(fh, [FATTR4_ACL, FATTR4_MODE])
    if FATTR4_ACL not in attrs_dict or FATTR4_MODE not in attrs_dict:
        t.fail("ACL or MODE not returned after SETATTR")

    try:
        nfs4acl.verify_acl(attrs_dict[FATTR4_ACL], acl)
    except AssertionError as e:
        t.fail(str(e))

    # Per RFC 8881 §6.4.1.3, when both MODE and ACL are set, the final mode
    # is derived from the ACL per §6.3.2, and may differ from requested MODE
    returned_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if returned_mode != expected_mode:
        t.fail("MODE (0%o) does not match RFC 8881 §6.3.2 derivation "
               "from ACL (expected 0%o)" % (returned_mode, expected_mode))

    # Display informational message about mode derivation
    if returned_mode != mode:
        t.pass_warn("MODE+ACL: requested 0%o, final 0%o (derived from ACL per RFC 8881 §6.3.2)"
                    % (mode, returned_mode))

def testSetattrACLThenMode(t, env):
    """SETATTR MODE+ACL together vs ACL then MODE separately

    Per RFC 8881 sections 6.4.1.1-6.4.1.3, when MODE and ACL are set
    together in a single SETATTR, the server computes the final mode
    from the ACL (the MODE attribute is effectively ignored). When
    ACL is set first and MODE is set in a separate operation, the
    final mode is the explicitly-set MODE value.

    This test verifies this difference by using a MODE (0o755) that
    differs from the ACL-derived mode (0o644).

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT22
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    # Create two test files
    fh1, stateid1 = c.create_confirm(t.word() + b"_1")
    fh2, stateid2 = c.create_confirm(t.word() + b"_2")

    # make_test_acl() derives to mode 0o644 (rw-r--r--)
    acl = nfs4acl.make_test_acl()
    acl_derived_mode = acl2mode_rfc8881(acl)

    # Use a different mode to demonstrate the RFC-defined difference
    explicit_mode = 0o755

    # File 1: Set MODE and ACL together
    # Per RFC 8881 §6.4.1.2, mode is derived from ACL (MODE ignored)
    attrs = {FATTR4_MODE: explicit_mode, FATTR4_ACL: acl}
    ops = c.use_obj(fh1) + [c.setattr(attrs)]
    res = c.compound(ops)
    check(res, msg="SETATTR with MODE and ACL together")

    # File 2: Set ACL first, then MODE separately
    # Per RFC 8881 §6.4.1.1, final mode is the explicit MODE value
    ops = c.use_obj(fh2) + [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res, msg="SETATTR with ACL")

    ops = c.use_obj(fh2) + [c.setattr({FATTR4_MODE: explicit_mode})]
    res = c.compound(ops)
    check(res, msg="SETATTR with MODE after ACL")

    # Verify the modes differ as expected per RFC 8881
    attrs1 = c.do_getattrdict(fh1, [FATTR4_MODE, FATTR4_ACL])
    attrs2 = c.do_getattrdict(fh2, [FATTR4_MODE, FATTR4_ACL])

    mode1 = attrs1[FATTR4_MODE] & 0o7777
    mode2 = attrs2[FATTR4_MODE] & 0o7777

    # File 1 (MODE+ACL together): mode should be derived from ACL
    if mode1 != acl_derived_mode:
        t.fail("MODE+ACL together: expected ACL-derived mode 0%o, got 0%o"
               % (acl_derived_mode, mode1))

    # File 2 (ACL then MODE): mode should be explicit MODE value
    if mode2 != explicit_mode:
        t.fail("ACL then MODE: expected explicit mode 0%o, got 0%o"
               % (explicit_mode, mode2))

def testSetattrACLModeDeriveBasic(t, env):
    """SETATTR(ACL) should derive mode per RFC 8881 Section 6.3.2

    Test basic mode derivation from ACL when setting ACL alone.
    The mode's permission bits should match what is computed from the ACL.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT23
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    fh, stateid = c.create_confirm(t.word())

    # Create ACL: OWNER@ gets read+write+execute, others get nothing
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                b"GROUP@"),
        nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                b"EVERYONE@")
    ]

    # Set ACL only (not MODE)
    ops = c.use_obj(fh) + [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res, msg="SETATTR with ACL only")

    # Get resulting mode
    attrs = c.do_getattrdict(fh, [FATTR4_MODE, FATTR4_ACL])
    returned_mode = attrs[FATTR4_MODE] & 0o777
    returned_acl = attrs[FATTR4_ACL]

    # Compute expected mode from returned ACL per RFC 8881 §6.3.2
    expected_mode = acl2mode_rfc8881(returned_acl)

    if returned_mode != expected_mode:
        t.fail("Mode (0%o) does not match RFC 8881 §6.3.2 derivation "
               "from ACL (expected 0%o)" % (returned_mode, expected_mode))

def testSetattrACLModeDeriveWriteBits(t, env):
    """SETATTR(ACL) write bit requires BOTH WRITE_DATA and APPEND_DATA

    Per RFC 8881 §6.3.2, the write mode bit should only be set if BOTH
    ACE4_WRITE_DATA and ACE4_APPEND_DATA are present in the ACL.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT24
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    # Test 1: Only WRITE_DATA (no APPEND_DATA) - write bit should NOT be set
    fh1, stateid1 = c.create_confirm(t.word() + b"_1")
    acl1 = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_WRITE_DATA,  # Missing APPEND_DATA
                b"OWNER@")
    ]
    ops = c.use_obj(fh1) + [c.setattr({FATTR4_ACL: acl1})]
    res = c.compound(ops)
    check(res, msg="SETATTR ACL with only WRITE_DATA")

    attrs1 = c.do_getattrdict(fh1, [FATTR4_MODE, FATTR4_ACL])
    mode1 = attrs1[FATTR4_MODE] & 0o777
    expected_mode1 = acl2mode_rfc8881(attrs1[FATTR4_ACL])

    if mode1 != expected_mode1:
        t.fail("Mode (0%o) with only WRITE_DATA does not match expected (0%o). "
               "Write bit should NOT be set without APPEND_DATA." %
               (mode1, expected_mode1))

    # Test 2: Only APPEND_DATA (no WRITE_DATA) - write bit should NOT be set
    fh2, stateid2 = c.create_confirm(t.word() + b"_2")
    acl2 = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_APPEND_DATA,  # Missing WRITE_DATA
                b"OWNER@")
    ]
    ops = c.use_obj(fh2) + [c.setattr({FATTR4_ACL: acl2})]
    res = c.compound(ops)
    check(res, msg="SETATTR ACL with only APPEND_DATA")

    attrs2 = c.do_getattrdict(fh2, [FATTR4_MODE, FATTR4_ACL])
    mode2 = attrs2[FATTR4_MODE] & 0o777
    expected_mode2 = acl2mode_rfc8881(attrs2[FATTR4_ACL])

    if mode2 != expected_mode2:
        t.fail("Mode (0%o) with only APPEND_DATA does not match expected (0%o). "
               "Write bit should NOT be set without WRITE_DATA." %
               (mode2, expected_mode2))

    # Test 3: Both WRITE_DATA and APPEND_DATA - write bit SHOULD be set
    fh3, stateid3 = c.create_confirm(t.word() + b"_3")
    acl3 = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_WRITE_DATA | ACE4_APPEND_DATA,  # Both present
                b"OWNER@")
    ]
    ops = c.use_obj(fh3) + [c.setattr({FATTR4_ACL: acl3})]
    res = c.compound(ops)
    check(res, msg="SETATTR ACL with both WRITE_DATA and APPEND_DATA")

    attrs3 = c.do_getattrdict(fh3, [FATTR4_MODE, FATTR4_ACL])
    mode3 = attrs3[FATTR4_MODE] & 0o777
    expected_mode3 = acl2mode_rfc8881(attrs3[FATTR4_ACL])

    if mode3 != expected_mode3:
        t.fail("Mode (0%o) with WRITE_DATA+APPEND_DATA does not match "
               "expected (0%o)" % (mode3, expected_mode3))

def testSetattrACLModeDeriveAllowDeny(t, env):
    """SETATTR(ACL) with ALLOW/DENY interaction

    Test that ACL evaluation order is correct when mixing ALLOW and DENY ACEs.
    Per RFC 8881 §6.3.2, evaluate ACEs in order, with earlier ACEs taking
    precedence.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT25
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    # Test: ALLOW first, then DENY - the ALLOW should win
    fh, stateid = c.create_confirm(t.word())
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_DENIED_ACE_TYPE, 0,
                ACE4_READ_DATA,  # This should be ignored (already allowed)
                b"OWNER@")
    ]

    ops = c.use_obj(fh) + [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res, msg="SETATTR ACL with ALLOW then DENY")

    attrs = c.do_getattrdict(fh, [FATTR4_MODE, FATTR4_ACL])
    returned_mode = attrs[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs[FATTR4_ACL])

    if returned_mode != expected_mode:
        t.fail("Mode (0%o) with ALLOW/DENY does not match expected (0%o). "
               "First ACE should take precedence." % (returned_mode, expected_mode))

def testSetattrACLModeDeriveEveryone(t, env):
    """SETATTR(ACL) with EVERYONE@ affecting all identifiers

    Test that EVERYONE@ ACEs are considered when evaluating permissions
    for OWNER@ and GROUP@ per RFC 8881 §6.3.2.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT26
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    # EVERYONE@ gets read, specific OWNER@ gets nothing extra
    # Final result: OWNER@ should have read (from EVERYONE@)
    fh, stateid = c.create_confirm(t.word())
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"EVERYONE@")
    ]

    ops = c.use_obj(fh) + [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res, msg="SETATTR ACL with only EVERYONE@")

    attrs = c.do_getattrdict(fh, [FATTR4_MODE, FATTR4_ACL])
    returned_mode = attrs[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs[FATTR4_ACL])

    if returned_mode != expected_mode:
        t.fail("Mode (0%o) does not match expected (0%o). "
               "EVERYONE@ should affect all mode bits." %
               (returned_mode, expected_mode))

def testSetattrACLModeDeriveComplex(t, env):
    """SETATTR(ACL) with complex ACL including multiple identifiers

    Test mode derivation with a more realistic ACL including OWNER@,
    GROUP@, and EVERYONE@ with various permissions.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT27
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    fh, stateid = c.create_confirm(t.word())

    # Create a complex ACL:
    # OWNER@: read + write + execute
    # GROUP@: read + execute (no write)
    # EVERYONE@: read only
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

    ops = c.use_obj(fh) + [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res, msg="SETATTR with complex ACL")

    attrs = c.do_getattrdict(fh, [FATTR4_MODE, FATTR4_ACL])
    returned_mode = attrs[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs[FATTR4_ACL])

    if returned_mode != expected_mode:
        t.fail("Mode (0%o) does not match RFC 8881 §6.3.2 derivation "
               "from complex ACL (expected 0%o)" %
               (returned_mode, expected_mode))

def testSetattrACLIndependentOfMode(t, env):
    """SETATTR(ACL) outcome should not depend on existing mode bits

    Per RFC 8881 §6.4.1.2, when setting ACL without mode, the ACL should
    be set as given. The existing mode should not affect the ACL that gets
    stored. This test verifies that setting the same ACL on files with
    different initial modes results in identical ACLs being stored.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT28
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    # Create the same ACL to use for all files
    # OWNER@: read + write, GROUP@: read, EVERYONE@: nothing
    test_acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"GROUP@")
    ]

    # Test with various initial mode values
    initial_modes = [0o600, 0o644, 0o755, 0o777, 0o400, 0o000]
    files = []

    # Create files with different initial modes
    for initial_mode in initial_modes:
        fh, stateid = c.create_confirm(t.word() + (b"_%o" % initial_mode))

        # Set initial mode
        ops = c.use_obj(fh) + [c.setattr({FATTR4_MODE: initial_mode})]
        res = c.compound(ops)
        check(res, msg="Setting initial mode to 0%o" % initial_mode)

        files.append((fh, initial_mode))

    # Now set the same ACL on all files
    for fh, initial_mode in files:
        ops = c.use_obj(fh) + [c.setattr({FATTR4_ACL: test_acl})]
        res = c.compound(ops)
        check(res, msg="SETATTR ACL on file with initial mode 0%o" % initial_mode)

    # Retrieve the ACLs that were actually stored
    acls = []
    for fh, initial_mode in files:
        attrs = c.do_getattrdict(fh, [FATTR4_ACL])
        acls.append((initial_mode, attrs[FATTR4_ACL]))

    # Helper function to compare ACLs (comparing ACE lists)
    def acl_equal(acl1, acl2):
        """Compare two ACLs for equality"""
        if len(acl1) != len(acl2):
            return False
        for ace1, ace2 in zip(acl1, acl2):
            if (ace1.type != ace2.type or
                ace1.flag != ace2.flag or
                ace1.access_mask != ace2.access_mask or
                ace1.who != ace2.who):
                return False
        return True

    def acl_to_string(acl):
        """Convert ACL to readable string for error messages"""
        aces = []
        for ace in acl:
            type_str = "ALLOW" if ace.type == ACE4_ACCESS_ALLOWED_ACE_TYPE else "DENY"
            aces.append("<%s:%s:0x%x:0x%x>" %
                       (type_str, ace.who.decode(), ace.access_mask, ace.flag))
        return "[" + ", ".join(aces) + "]"

    # Compare all ACLs - they should all be identical
    reference_mode, reference_acl = acls[0]
    for initial_mode, acl in acls[1:]:
        if not acl_equal(reference_acl, acl):
            t.fail("ACLs differ based on initial mode! "
                   "File with mode 0%o has ACL %s, "
                   "but file with mode 0%o has ACL %s. "
                   "RFC 8881 §6.4.1.2: ACL should be set as given, "
                   "independent of existing mode." %
                   (reference_mode, acl_to_string(reference_acl),
                    initial_mode, acl_to_string(acl)))

    # Also verify that the mode derived from the ACL is consistent
    modes = []
    for initial_mode, acl in acls:
        derived_mode = acl2mode_rfc8881(acl)
        modes.append(derived_mode)

    if len(set(modes)) != 1:
        mode_str = ", ".join("0%o (from initial 0%o)" % (m, acls[i][0])
                             for i, m in enumerate(modes))
        t.fail("ACLs derive to different modes: %s. "
               "This suggests ACLs were stored differently based on initial mode." %
               mode_str)

def testSetattrACLIndependentModeHighBits(t, env):
    """SETATTR(ACL) should preserve high-order mode bits (SUID/SGID/SVTX)

    Per RFC 8881 §6.4.1.2, when setting ACL without mode, the three
    high-order bits of mode (SUID, SGID, SVTX) SHOULD remain unchanged.
    Only the low-order nine permission bits should be modified.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT29
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    # Create ACL to set
    test_acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"GROUP@")
    ]

    # Test with different high-order bits set
    test_cases = [
        (0o4755, "SUID"),      # Set-user-ID
        (0o2755, "SGID"),      # Set-group-ID
        (0o1755, "SVTX"),      # Sticky bit
        (0o6755, "SUID+SGID"), # Both SUID and SGID
        (0o7755, "ALL"),       # All three bits
    ]

    for initial_mode, description in test_cases:
        fh, stateid = c.create_confirm(t.word() + (b"_%s" % description.encode()))

        # Set initial mode with high-order bits
        ops = c.use_obj(fh) + [c.setattr({FATTR4_MODE: initial_mode})]
        res = c.compound(ops)
        check(res, msg="Setting initial mode 0%o (%s)" % (initial_mode, description))

        # Verify the mode was set
        before_attrs = c.do_getattrdict(fh, [FATTR4_MODE])
        before_mode = before_attrs[FATTR4_MODE] & 0o7777

        # Set ACL only (not mode)
        ops = c.use_obj(fh) + [c.setattr({FATTR4_ACL: test_acl})]
        res = c.compound(ops)
        check(res, msg="SETATTR ACL on file with %s" % description)

        # Check that high-order bits are preserved
        after_attrs = c.do_getattrdict(fh, [FATTR4_MODE, FATTR4_ACL])
        after_mode = after_attrs[FATTR4_MODE] & 0o7777

        # Extract high-order bits (SUID, SGID, SVTX)
        before_high = before_mode & 0o7000
        after_high = after_mode & 0o7000

        if before_high != after_high:
            t.fail("High-order mode bits not preserved for %s: "
                   "before=0%o, after=0%o. RFC 8881 §6.4.1.2 says "
                   "high-order bits SHOULD remain unchanged." %
                   (description, before_mode, after_mode))

        # Verify low-order bits match ACL derivation
        after_low = after_mode & 0o777
        expected_low = acl2mode_rfc8881(after_attrs[FATTR4_ACL])

        if after_low != expected_low:
            t.fail("Low-order mode bits (0%o) don't match RFC 8881 §6.3.2 "
                   "derivation (expected 0%o) for %s" %
                   (after_low, expected_low, description))

def testSetattrModeACLattrsset(t, env):
    """SETATTR(MODE+ACL) should indicate which attributes were actually set

    Per RFC 8881 §6.4.1.3, when both MODE and ACL are set together, the
    server processes MODE first, then ACL (which may modify the mode).
    The attrsset bitmap indicates which attributes were actually set.
    This test verifies the attrsset bitmap and final mode consistency.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT30
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    fh, stateid = c.create_confirm(t.word())

    # Create an ACL that will derive to a specific mode (0754)
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

    # Request a different mode (0640)
    requested_mode = 0o640

    # Set both MODE and ACL together
    attrs = {FATTR4_MODE: requested_mode, FATTR4_ACL: acl}
    ops = c.use_obj(fh) + [c.setattr(attrs)]
    res = c.compound(ops)
    check(res, msg="SETATTR with MODE and ACL together")

    # Check the attrsset bitmap
    attrsset = bitmap2list(res.resarray[-1].attrsset)

    # Get the final attributes
    final_attrs = c.do_getattrdict(fh, [FATTR4_MODE, FATTR4_ACL])
    final_mode = final_attrs[FATTR4_MODE] & 0o7777
    final_acl = final_attrs[FATTR4_ACL]

    # ACL should always be set
    if FATTR4_ACL not in attrsset:
        t.fail("FATTR4_ACL not in attrsset, but ACL was requested")

    # Compute what mode should be derived from the ACL
    acl_derived_mode = acl2mode_rfc8881(final_acl)

    if FATTR4_MODE in attrsset:
        # Server claims it set MODE - but per §6.4.1.3, the ACL processing
        # will modify the mode. The final mode should match ACL derivation,
        # not necessarily the requested mode.
        if final_mode != acl_derived_mode:
            t.fail("Server set MODE in attrsset, but final mode (0%o) "
                   "doesn't match ACL-derived mode (0%o). "
                   "Per RFC 8881 §6.4.1.3, ACL processing modifies mode." %
                   (final_mode, acl_derived_mode))
    else:
        # Server did not include MODE in attrsset - this means it recognized
        # that the ACL processing would override the requested mode.
        # Final mode should still match ACL derivation.
        if final_mode != acl_derived_mode:
            t.fail("MODE not in attrsset (expected behavior), but final mode "
                   "(0%o) doesn't match ACL-derived mode (0%o). "
                   "Per RFC 8881 §6.4.1.2, mode should be derived from ACL." %
                   (final_mode, acl_derived_mode))

def testSetattrModeACLConflict(t, env):
    """SETATTR(MODE+ACL) when MODE and ACL would produce different permissions

    Test the interaction when the requested MODE differs significantly from
    what the ACL would derive. Per RFC 8881 §6.4.1.3, MODE is applied first,
    then ACL is applied (possibly changing the final mode).

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT31
    """
    from nfs4acl import acl2mode_rfc8881
    c = env.c1
    c.init_connection()

    # Test multiple conflict scenarios
    test_cases = [
        # (requested_mode, ACL, description)
        (0o777, [  # Request all permissions
            nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                    ACE4_READ_DATA,  # But ACL only grants read
                    b"OWNER@")
        ], "MODE=0777 but ACL grants only read"),

        (0o000, [  # Request no permissions
            nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                    ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                    b"OWNER@")  # But ACL grants everything
        ], "MODE=0000 but ACL grants rwx"),

        (0o644, [  # Request read for all, write for owner
            nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                    ACE4_EXECUTE,  # But ACL only grants execute
                    b"OWNER@")
        ], "MODE=0644 but ACL grants only execute"),
    ]

    for requested_mode, acl, description in test_cases:
        fh, stateid = c.create_confirm(t.word() + ("_%o" % requested_mode).encode())

        # Set both MODE and ACL together
        attrs = {FATTR4_MODE: requested_mode, FATTR4_ACL: acl}
        ops = c.use_obj(fh) + [c.setattr(attrs)]
        res = c.compound(ops)
        check(res, msg="SETATTR MODE+ACL: %s" % description)

        # Get final attributes
        final_attrs = c.do_getattrdict(fh, [FATTR4_MODE, FATTR4_ACL])
        final_mode = final_attrs[FATTR4_MODE] & 0o777
        final_acl = final_attrs[FATTR4_ACL]

        # Verify final mode matches ACL derivation
        expected_mode = acl2mode_rfc8881(final_acl)

        if final_mode != expected_mode:
            t.fail("Test case '%s': final mode (0%o) doesn't match "
                   "ACL-derived mode (0%o). Per RFC 8881 §6.4.1.3, "
                   "ACL should be set as given and mode derived from it." %
                   (description, final_mode, expected_mode))

def testSetattrACLNamedPrincipals(t, env):
    """SETATTR(ACL) with named principals should preserve them

    Per RFC 8881 §6.4.1.3: "the ACL attribute is set as given."
    When an ACL contains named principals (not OWNER@/GROUP@/EVERYONE@),
    the server must preserve those exact principals in the stored ACL,
    not convert them to special identifiers.

    FLAGS: setattr acl all
    DEPEND: MODE ACL0
    CODE: SATT32
    """
    c = env.c1
    c.init_connection()

    # First create a file and get its owner and group
    temp_fh, temp_stateid = c.create_confirm(t.word() + b"_temp")
    attrs = c.do_getattrdict(temp_fh, [FATTR4_OWNER, FATTR4_OWNER_GROUP])
    current_owner = attrs[FATTR4_OWNER]
    current_group = attrs[FATTR4_OWNER_GROUP]

    # Test 1: SETATTR(ACL) with named principals only
    fh1, stateid1 = c.create_confirm(t.word() + b"_acl_only")

    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA,
                current_owner),  # Named principal, not OWNER@
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                current_group)  # Named principal, not GROUP@
    ]

    ops = c.use_obj(fh1) + [c.setattr({FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res, msg="SETATTR ACL with named principals")

    # Verify ACL was preserved with named principals
    returned_attrs = c.do_getattrdict(fh1, [FATTR4_ACL])
    returned_acl = returned_attrs[FATTR4_ACL]

    if len(returned_acl) < len(acl):
        t.fail("Returned ACL has fewer entries than requested: "
               "expected at least %d, got %d" % (len(acl), len(returned_acl)))

    for i, expected_ace in enumerate(acl):
        if i >= len(returned_acl):
            t.fail("Missing ACE %d in returned ACL" % i)
        returned_ace = returned_acl[i]

        if returned_ace.who != expected_ace.who:
            t.fail("ACE %d who mismatch: expected %s, got %s. "
                   "Server converted named principal to special identifier, "
                   "violating RFC 8881 §6.4.1.3 'ACL attribute is set as given'" %
                   (i, expected_ace.who, returned_ace.who))

    # Test 2: SETATTR(MODE+ACL) with named principals
    fh2, stateid2 = c.create_confirm(t.word() + b"_mode_acl")

    mode = 0o755
    acl = [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_EXECUTE,
                current_owner),  # Named principal
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_EXECUTE,
                current_group),  # Named principal
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"EVERYONE@")  # Special identifier is fine
    ]

    ops = c.use_obj(fh2) + [c.setattr({FATTR4_MODE: mode, FATTR4_ACL: acl})]
    res = c.compound(ops)
    check(res, msg="SETATTR MODE+ACL with named principals")

    # Verify ACL was preserved
    returned_attrs = c.do_getattrdict(fh2, [FATTR4_ACL])
    returned_acl = returned_attrs[FATTR4_ACL]

    if len(returned_acl) < len(acl):
        t.fail("Returned ACL has fewer entries than requested: "
               "expected at least %d, got %d" % (len(acl), len(returned_acl)))

    for i, expected_ace in enumerate(acl):
        if i >= len(returned_acl):
            t.fail("Missing ACE %d in returned ACL" % i)
        returned_ace = returned_acl[i]

        if returned_ace.who != expected_ace.who:
            t.fail("ACE %d who mismatch: expected %s, got %s. "
                   "Server converted named principal to special identifier, "
                   "violating RFC 8881 §6.4.1.3" %
                   (i, expected_ace.who, returned_ace.who))
