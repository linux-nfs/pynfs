from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *
import nfs_ops
op = nfs_ops.NFS4ops()
from .environment import check, fail, create_file, use_obj, \
    get_blocksize
from block import Packer as BlockPacker, Unpacker as BlockUnpacker, \
    PNFS_BLOCK_READWRITE_DATA, PNFS_BLOCK_READ_DATA, \
    pnfs_block_layoutupdate4, pnfs_block_extent4
from nfs4lib import FancyNFS4Packer, get_nfstime


def testStateid1(t, env):
    """Check for proper sequence handling in layout stateids.

    FLAGS: block
    CODE: BLOCK1
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid = res.resarray[-1].logr_stateid
    print(lo_stateid)
    if lo_stateid.seqid != 1:
        # From draft23 12.5.2 "The first successful LAYOUTGET processed by
        # the server using a non-layout stateid as an argument MUST have the
        # "seqid" field of the layout stateid in the response set to one."
        fail("Expected stateid.seqid==1, got %i" % lo_stateid.seqid)
    for i in range(6):
        # Get subsequent layouts
        ops = [op.putfh(fh),
               op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                            (i+1)*8192, 8192, 8192, lo_stateid, 0xffff)]
        res = sess.compound(ops)
        check(res)
        lo_stateid = res.resarray[-1].logr_stateid
        print(lo_stateid)
        if lo_stateid.seqid != i + 2:
            # From draft23 12.5.3 "After the layout stateid is established,
            # the server increments by one the value of the "seqid" in each
            # subsequent LAYOUTGET and LAYOUTRETURN response,
            fail("Expected stateid.seqid==%i, got %i" % (i+2, lo_stateid.seqid))

def testStateid2(t, env):
    """Check for proper sequence handling in layout stateids.

    FLAGS: block
    CODE: BLOCK2
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Get layout 2
    lo_stateid1 = res.resarray[-1].logr_stateid
    print(lo_stateid1)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        8192, 8192, 8192, lo_stateid1, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Get layout 3 (merge of prior two)
    lo_stateid2 = res.resarray[-1].logr_stateid
    print(lo_stateid2)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 2*8192, 2*8192, lo_stateid2, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid3 = res.resarray[-1].logr_stateid
    print(lo_stateid3)
    # lo_stateid3.seqid = 3 # BUG - work around emc problem
    # Parse opaque to get info for commit
    # STUB not very general
    layout = res.resarray[-1].logr_layout[-1]
    p = BlockUnpacker(layout.loc_body)
    opaque = p.unpack_pnfs_block_layout4()
    p.done()
    extent = opaque.blo_extents[-1]
    extent.bex_state = PNFS_BLOCK_READWRITE_DATA
    p = BlockPacker()
    p.pack_pnfs_block_layoutupdate4(pnfs_block_layoutupdate4([extent]))
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(extent.bex_file_offset,
                           extent.bex_length,
                           False, lo_stateid3,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, p.get_buffer()))]
    res = sess.compound(ops)
    check(res)

def testEmptyCommit(t, env):
    """Check for proper handling of empty LAYOUTCOMMIT.

    FLAGS: block
    CODE: BLOCK3
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 8192, 8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    # Get layout 2
    lo_stateid1 = res.resarray[-1].logr_stateid
    print(lo_stateid1)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        8192, 8192, 8192, lo_stateid1, 0xffff)]
    res = sess.compound(ops)
    check(res)
    lo_stateid2 = res.resarray[-1].logr_stateid
    print(lo_stateid2)
    # Parse opaque to get info for commit
    # STUB not very general
    layout = res.resarray[-1].logr_layout[-1]
    p = BlockUnpacker(layout.loc_body)
    opaque = p.unpack_pnfs_block_layout4()
    p.done()
    extent = opaque.blo_extents[-1]
    extent.bex_state = PNFS_BLOCK_READWRITE_DATA
    p = BlockPacker()
    p.pack_pnfs_block_layoutupdate4(pnfs_block_layoutupdate4([extent]))
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(extent.bex_file_offset,
                           extent.bex_length,
                           False, lo_stateid2,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, p.get_buffer()))]
    res = sess.compound(ops)
    check(res)
    # Send another LAYOUTCOMMIT, with an empty opaque
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(extent.bex_file_offset,
                           extent.bex_length,
                           False, lo_stateid2,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, ""))]
    res = sess.compound(ops)
    check(res)

def testSplitCommit(t, env):
    """Check for proper handling of disjoint LAYOUTCOMMIT.opaque

    FLAGS: block
    CODE: BLOCK4
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    # Create the file
    res = create_file(sess, env.testname(t))
    check(res)
    # Get layout 1
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    print(open_stateid)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 2*8192, 2*8192, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)

    lo_stateid1 = res.resarray[-1].logr_stateid
    print(lo_stateid1)
    # Parse opaque to get info for commit
    # STUB not very general
    layout = res.resarray[-1].logr_layout[-1]
    p = BlockUnpacker(layout.loc_body)
    opaque = p.unpack_pnfs_block_layout4()
    p.done()
    dev = opaque.blo_extents[-1].bex_vol_id
    extent1 = pnfs_block_extent4(dev, 0, 8192, 0, PNFS_BLOCK_READWRITE_DATA)
    extent2 = pnfs_block_extent4(dev, 8192, 8192, 0, PNFS_BLOCK_READWRITE_DATA)

    p = BlockPacker()
    p.pack_pnfs_block_layoutupdate4(pnfs_block_layoutupdate4([extent1,
                                                              extent2]))
    time = newtime4(True, get_nfstime())
    ops = [op.putfh(fh),
           op.layoutcommit(0,
                           2*8192,
                           False, lo_stateid1,
                           newoffset4(True, 2 * 8192 - 1),
                           time,
                           layoutupdate4(LAYOUT4_BLOCK_VOLUME, p.get_buffer()))]
    res = sess.compound(ops)
    check(res)

def testRWExtentsContiguous(t, env):
    """RW layout over a hole between allocated blocks has contiguous extents

    The server allocates the hole for the layout.  Check three of the
    rules in RFC 5663 section 2.3.1: the extents are ordered by offset,
    the writable extents (all but PNFS_BLOCK_READ_DATA) are logically
    contiguous, and the first extent contains the requested offset.  A
    server that maps each extent in full can return the extent that the
    allocation merges with the ones before it, overlapping them.  The
    minimum length is one block, so that a server that returns one
    extent per LAYOUTGET does not have to refuse the request.  Warn if
    the layout does not cover the three blocks or they are not contiguous
    on the volume, as then no merge could be seen.

    FLAGS: block
    CODE: BLOCK5
    VERS: 2-
    """
    sess = env.c1.new_pnfs_client_session(env.testname(t))
    bs = get_blocksize(sess, use_obj(env.opts.path))
    res = create_file(sess, env.testname(t))
    check(res)
    fh = res.resarray[-1].object
    open_stateid = res.resarray[-2].stateid
    # Allocate three blocks, then deallocate the middle one: the block
    # the server allocates for the hole is likely to be that one, and to
    # merge with both neighbours.  (On Linux nfsd over XFS the freed block
    # can be reused at once on a sync export, where DEALLOCATE commits.)
    res = sess.compound([op.putfh(fh), op.allocate(open_stateid, 0, 3*bs)])
    if res.status == NFS4ERR_NOTSUPP:
        t.fail_support("ALLOCATE is not supported")
    check(res)
    res = sess.compound([op.putfh(fh), op.deallocate(open_stateid, bs, bs)])
    if res.status == NFS4ERR_NOTSUPP:
        t.fail_support("DEALLOCATE is not supported")
    check(res)
    ops = [op.putfh(fh),
           op.layoutget(False, LAYOUT4_BLOCK_VOLUME, LAYOUTIOMODE4_RW,
                        0, 3*bs, bs, open_stateid, 0xffff)]
    res = sess.compound(ops)
    check(res)
    found = False
    blocks = {}
    for layout in res.resarray[-1].logr_layout:
        p = BlockUnpacker(layout.loc_body)
        opaque = p.unpack_pnfs_block_layout4()
        p.done()
        ext = [(e.bex_file_offset, e.bex_length, e.bex_state)
               for e in opaque.blo_extents]
        if not ext:
            fail("No extents in layout %d+%d" %
                 (layout.lo_offset, layout.lo_length))
        for a, b in zip(ext, ext[1:]):
            if b[0] < a[0] or (b[0] == a[0] and
                               a[2] != PNFS_BLOCK_READ_DATA and
                               b[2] == PNFS_BLOCK_READ_DATA):
                fail("Extents %s and %s are not in order" % (a, b))
        writable = [e for e in ext if e[2] != PNFS_BLOCK_READ_DATA]
        for a, b in zip(writable, writable[1:]):
            if b[0] != a[0] + a[1]:
                fail("Writable extents %s and %s are not logically "
                     "contiguous" % (a, b))
        if layout.lo_offset <= 0 < layout.lo_offset + layout.lo_length:
            found = True
            if not ext[0][0] <= 0 < ext[0][0] + ext[0][1]:
                fail("First extent %s does not contain offset 0" %
                     (ext[0],))
        for e in opaque.blo_extents:
            if e.bex_state == PNFS_BLOCK_READ_DATA:
                continue
            off = e.bex_file_offset
            for i in range(3):
                if off <= i*bs < off + e.bex_length:
                    blocks[i] = (e.bex_vol_id,
                                 e.bex_storage_offset + i*bs - off)
    if not found:
        fail("No layout contains offset 0")
    if len(blocks) < 3:
        t.pass_warn("The layout does not cover all three blocks, so a "
                    "merge could not be seen")
    if blocks[0][0] != blocks[1][0] or blocks[1][0] != blocks[2][0] or \
       blocks[1][1] != blocks[0][1] + bs or blocks[2][1] != blocks[1][1] + bs:
        t.pass_warn("The three blocks are not contiguous on the volume, "
                    "so there were no extents to merge")
