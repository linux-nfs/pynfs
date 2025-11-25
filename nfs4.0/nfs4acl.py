#
# nfs4acl.py - some useful acl code
#
# Written by Fred Isaman <iisaman@citi.umich.edu>
# Copyright (C) 2004 University of Michigan, Center for
#                    Information Technology Integration
#


# Taken from mapping description at
# http://www.citi.umich.edu/projects/nfsv4/rfc/draft-ietf-nfsv4-acl-mapping-02.txt

from xdrdef.nfs4_const import *
from xdrdef.nfs4_type import *

# Taken from mapping
MODE_R = ACE4_READ_DATA | ACE4_READ_NAMED_ATTRS
MODE_W = ACE4_WRITE_DATA | ACE4_WRITE_NAMED_ATTRS | ACE4_APPEND_DATA
MODE_X = ACE4_EXECUTE

DMODE_R = ACE4_LIST_DIRECTORY | ACE4_READ_NAMED_ATTRS
DMODE_W = ACE4_ADD_FILE | ACE4_WRITE_NAMED_ATTRS | \
          ACE4_ADD_SUBDIRECTORY | ACE4_DELETE_CHILD
DMODE_X = ACE4_EXECUTE

FLAG_ALL = ACE4_READ_ACL | ACE4_READ_ATTRIBUTES | ACE4_SYNCHRONIZE
FLAG_OWN = ACE4_WRITE_ACL | ACE4_READ_ACL | ACE4_WRITE_ATTRIBUTES
FLAG_NONE = ACE4_DELETE

DDEFAULT = ACE4_INHERIT_ONLY_ACE | ACE4_DIRECTORY_INHERIT_ACE | \
           ACE4_FILE_INHERIT_ACE

# Where is this required?
USED_BITS = 0x1f01ff

# Useful abbreviations
ALLOWED = ACE4_ACCESS_ALLOWED_ACE_TYPE
DENIED = ACE4_ACCESS_DENIED_ACE_TYPE
GROUP = ACE4_IDENTIFIER_GROUP
GROUP_OBJ = ACE4_IDENTIFIER_GROUP # Or is it 0? RFC and map are unclear

MODES = [ 0, MODE_X, MODE_W, MODE_X | MODE_W,
          MODE_R, MODE_R | MODE_X, MODE_R | MODE_W,
          MODE_R | MODE_X | MODE_W ]
DMODES = [ 0, DMODE_X, DMODE_W, DMODE_X | DMODE_W,
           DMODE_R, DMODE_R | DMODE_X, DMODE_R | DMODE_W,
           DMODE_R | DMODE_X | DMODE_W ]

class ACLError(Exception):
    def __init__(self, msg=None):
        if msg is None:
            self.msg = "ACL error"
        else:
            self.msg = str(msg)

    def __str__(self):
        return self.msg

def negate(flags):
    """Return the opposite flags"""
    if flags & ~USED_BITS:
        raise ACLError("Flag %x contains unused bits" % flags)
    return ~flags & USED_BITS & ~FLAG_NONE

def mode2acl(mode, dir=False):
    """Translate a 3-digit octal mode into a posix compatible acl"""
    if dir: modes = DMODES
    else:   modes = MODES
    owner = modes[(mode & 0o700)//0o100] | FLAG_ALL | FLAG_OWN
    group = modes[(mode & 0o070)//0o10] | FLAG_ALL
    other = modes[(mode & 0o007)] | FLAG_ALL

    return [ nfsace4(ALLOWED, 0, owner, "OWNER@"),
             nfsace4(DENIED, 0, negate(owner), "OWNER@"),
             nfsace4(ALLOWED, GROUP_OBJ, group, "GROUP@"),
             nfsace4(DENIED, GROUP_OBJ, negate(group), "GROUP@"),
             nfsace4(ALLOWED, 0, other, "EVERYONE@"),
             nfsace4(DENIED, 0, negate(other), "EVERYONE@")
             ]

def make_test_acl():
    """Create a test ACL that maps cleanly to POSIX ACLs

    Uses OWNER@, GROUP@, and EVERYONE@ to match POSIX user/group/other
    structure, which helps servers that map NFSv4 ACLs to POSIX ACLs.

    Includes both WRITE_DATA and APPEND_DATA for write permission, since
    Linux NFS server's conservative NFSv4-to-POSIX mapping requires both
    to grant POSIX write permission.
    """
    return [
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA | ACE4_WRITE_DATA | ACE4_APPEND_DATA | ACE4_READ_ACL,
                b"OWNER@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"GROUP@"),
        nfsace4(ACE4_ACCESS_ALLOWED_ACE_TYPE, 0,
                ACE4_READ_DATA,
                b"EVERYONE@")
    ]

def acl2mode(acl):
    """Translate an acl into a 3-digit octal mode"""
    names = ["OWNER@", "GROUP@", "EVERYONE@"]
    short = [ace for ace in acl if ace.who in names]
    perms = dict.fromkeys(names, None)
    modes = [[MODE_R, 4], [MODE_W, 2], [MODE_X, 1]]
    for ace in short:
        if perms[ace.who] is not None: continue
        if ace.type == ALLOWED:
            bits = 0
            for mode, bit in modes:
                if mode & ace.access_mask == mode:
                    bits |= bit
            perms[ace.who] = bits
        elif ace.type == DENIED:
            bits = 7
            for mode, bit in modes:
                if mode & ace.access_mask:
                    bits &= ~bit
            perms[ace.who] = bits
    # If it wasn't mentioned, assume the worse
    for key in perms:
        if perms[key] is None:
            perm[keys] = 0
    return perms["OWNER@"]*0o100 + perms["GROUP@"]*0o10 + perms["EVERYONE@"]

def maps_to_posix(acl):
    """Raises ACLError if acl does not map to posix """

    """ FRED - there are all sorts of things this does not yet check for.
    1 - the mapping allows only certain sets of access_mask
    2 - Only 4 different flags values are allowed
    3 - How to handle mixed default/active on a directory?
    """
    len_acl = len(acl)
    if len_acl < 6:
        raise ACLError("Acl length %i is too short" % len_acl)
    if len_acl > 7 and len_acl%3 != 1:
        raise ACLError("Acl length %i does not equal 1 mod 3" % len_acl)
    flags = acl[0].flag
    if flags != 0: # FIXME and flags != DDEFAULT:
        raise ACLError("Illegal flag value %x" % flags)
    list = acl[:]
    not_mask = chk_owners(list, flags)
    chk_groups(list, flags, not_mask)
    chk_everyone(list, flags)

def chk_pair(allow, deny, who, flags):
    """Checks consistancy of allow/deny pair, forcing it to have given args"""
    if allow.type != ALLOWED or deny.type != DENIED:
        raise ACLError("Wrong type in allow/deny pair")
    if not (flags == allow.flag == deny.flag):
        raise ACLError("Pair does not have required flags %x" % flags)
    if negate(allow.access_mask) != deny.access_mask:
        raise ACLError("Pair access masks %x and %x are not complementary.\n"
                       "Expected inverse of %x is %x." %
                       (allow.access_mask, deny.access_mask,
                        allow.access_mask, negate(allow.access_mask)))
    if not (who == allow.who == deny.who):
        raise ACLError("Pair does not have required who %s" % who)

def chk_triple(mask, allow, deny, flags, not_mask):
    chk_pair(allow, deny, mask.who, flags)
    if mask.type != DENIED:
        raise ACLError("Triple mask does not have type DENIED")
    if flags != mask.flag:
        raise ACLError("Triple mask does not have required flags  %x" % flags)
    if not_mask != mask.access_mask:
        raise ACLError("Triple mask is not same as a previous mask")

def chk_everyone(acl, flags):
    if len(acl) != 2:
        raise ACLError("Had %i ACEs left when called chk_everyone" % len(acl))
    chk_pair(acl[0], acl[1], "EVERYONE@", flags)

def chk_owners(acl, flags):
    chk_pair(acl[0], acl[1], "OWNER@", flags)
    del acl[:2]
    used = []
    not_mask = None
    while True:
        if len(acl) < 3:
            raise ACLError("Ran out of ACEs in chk_owners")
        mask = acl[0]
        if mask.who.endswith("@") or mask.flag & GROUP:
            return not_mask
        if not_mask is None:
            if mask.access_mask & ~USED_BITS:
                raise ACLError("Mask %x contains unused bits" %
                               mask.access_mask)
            not_mask = mask.access_mask
        allow = acl[1]
        deny = acl[2]
        if mask.who in used:
            raise ACLError("Owner name %s duplicated" % mask.who)
        chk_triple(mask, allow, deny, flags, not_mask)
        used.append(mask.who)
        del acl[:3]

def chk_groups(acl, flags, not_mask):
    mask = acl[0]
    if mask.who != "GROUP@":
        raise ACLError("Expected GROUP@, got %s" % mask.who)
    if mask.type == ALLOWED and not_mask is None:
        # Special case of no mask
        chk_pair(acl[0], acl[1], "GROUP@", flags | GROUP_OBJ)
        del acl[:2]
        return
    if not_mask is None:
        if mask.access_mask & ~USED_BITS:
            raise ACLError("Mask %x contains unused bits" % mask.access_mask)
        not_mask = mask.access_mask
    used = ["EVERYONE@"]
    pairs = []
    while mask.who not in used:
        if len(acl) < 3:
            raise ACLError("Ran out of ACEs in chk_groups")
        used.append(mask.who)
        pairs.append([mask, acl[1]])
        del acl[:2]
        mask = acl[0]
    if len(acl) < len(used):
        raise ACLError("Ran out of ACEs in chk_groups")
    for mask, allow in pairs:
        if mask.who == "GROUP@":
            chk_triple(mask, allow, acl[0], flags | GROUP_OBJ, not_mask)
        else:
            chk_triple(mask, allow, acl[0], flags | GROUP, not_mask)
        del acl[:1]

def acl2mode_rfc8881(acl):
    """
    Compute mode from ACL according to RFC 8881 Section 6.3.2.

    For each special identifier (OWNER@, GROUP@, EVERYONE@), evaluate the
    ACL in order considering only ALLOW and DENY ACEs for EVERYONE@ and
    the identifier under consideration. Then translate to mode bits:
    - Read bit: Set if ACE4_READ_DATA is permitted
    - Write bit: Set if BOTH ACE4_WRITE_DATA AND ACE4_APPEND_DATA are permitted
    - Execute bit: Set if ACE4_EXECUTE is permitted

    Returns the low-order 9 bits of the mode (user/group/other permissions).
    """
    identifiers = [
        (b"OWNER@", MODE4_RUSR, MODE4_WUSR, MODE4_XUSR),
        (b"GROUP@", MODE4_RGRP, MODE4_WGRP, MODE4_XGRP),
        (b"EVERYONE@", MODE4_ROTH, MODE4_WOTH, MODE4_XOTH)
    ]

    mode = 0

    for who, read_bit, write_bit, exec_bit in identifiers:
        # Start with no permissions
        allowed_mask = 0
        denied_mask = 0

        # Evaluate ACL in order, considering only ALLOW/DENY for this
        # identifier and EVERYONE@
        for ace in acl:
            # Skip non-relevant ACEs
            if ace.who not in (who, b"EVERYONE@"):
                continue
            if ace.type not in (ALLOWED, DENIED):
                continue
            # Skip inherit-only ACEs (they don't affect current permissions)
            if ace.flag & ACE4_INHERIT_ONLY_ACE:
                continue

            if ace.type == ALLOWED:
                # Add allowed permissions not already denied
                allowed_mask |= (ace.access_mask & ~denied_mask)
            elif ace.type == DENIED:
                # Add denied permissions not already allowed
                denied_mask |= (ace.access_mask & ~allowed_mask)

        # Translate permitted mask to mode bits per RFC 8881 §6.3.2
        # Read bit: ACE4_READ_DATA must be set
        if allowed_mask & ACE4_READ_DATA:
            mode |= read_bit

        # Write bit: BOTH ACE4_WRITE_DATA and ACE4_APPEND_DATA must be set
        if (allowed_mask & ACE4_WRITE_DATA) and (allowed_mask & ACE4_APPEND_DATA):
            mode |= write_bit

        # Execute bit: ACE4_EXECUTE must be set
        if allowed_mask & ACE4_EXECUTE:
            mode |= exec_bit

    return mode

def access_mask_to_str(mask):
    """Convert an ACE access_mask to a symbolic string representation"""
    perms = [
        (ACE4_READ_DATA, "READ_DATA"),
        (ACE4_WRITE_DATA, "WRITE_DATA"),
        (ACE4_APPEND_DATA, "APPEND_DATA"),
        (ACE4_READ_NAMED_ATTRS, "READ_NAMED_ATTRS"),
        (ACE4_WRITE_NAMED_ATTRS, "WRITE_NAMED_ATTRS"),
        (ACE4_EXECUTE, "EXECUTE"),
        (ACE4_DELETE_CHILD, "DELETE_CHILD"),
        (ACE4_READ_ATTRIBUTES, "READ_ATTRIBUTES"),
        (ACE4_WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"),
        (ACE4_DELETE, "DELETE"),
        (ACE4_READ_ACL, "READ_ACL"),
        (ACE4_WRITE_ACL, "WRITE_ACL"),
        (ACE4_WRITE_OWNER, "WRITE_OWNER"),
        (ACE4_SYNCHRONIZE, "SYNCHRONIZE"),
    ]
    return " | ".join(name for bit, name in perms if mask & bit) or "(none)"

def verify_acl(returned_acl, expected_acl):
    """Verify that returned ACL contains expected ACEs

    Server may add additional ACEs, but the requested ones must be present
    with at least the requested permissions.

    Raises AssertionError if verification fails.
    """
    if len(returned_acl) < len(expected_acl):
        raise AssertionError(
            "Returned ACL has fewer entries than requested: "
            "expected at least %d, got %d" % (len(expected_acl), len(returned_acl)))

    # Verify the ACEs we set are present (server may add additional ACEs)
    for i, expected_ace in enumerate(expected_acl):
        if i >= len(returned_acl):
            raise AssertionError("Missing ACE %d in returned ACL" % i)
        returned_ace = returned_acl[i]
        if returned_ace.type != expected_ace.type:
            raise AssertionError(
                "ACE %d type mismatch: expected %d, got %d" %
                (i, expected_ace.type, returned_ace.type))
        if returned_ace.who != expected_ace.who:
            raise AssertionError(
                "ACE %d who mismatch: expected %s, got %s" %
                (i, expected_ace.who, returned_ace.who))
        # Check that requested permissions are present (server may add more)
        if (returned_ace.access_mask & expected_ace.access_mask) != expected_ace.access_mask:
            missing = expected_ace.access_mask & ~returned_ace.access_mask
            raise AssertionError(
                "ACE %d access_mask mismatch:\n"
                "  Expected: %s\n"
                "  Got:      %s\n"
                "  Missing:  %s" %
                (i,
                 access_mask_to_str(expected_ace.access_mask),
                 access_mask_to_str(returned_ace.access_mask),
                 access_mask_to_str(missing)))

def verify_mode_and_acl(attrs_dict, expected_acl, operation="operation"):
    """Verify that MODE and ACL attributes match expectations

    This helper encapsulates the common pattern of verifying both ACL
    and mode derivation per RFC 8881 Section 6.3.2.

    Args:
        attrs_dict: Dictionary of attributes (must contain FATTR4_ACL and FATTR4_MODE)
        expected_acl: The ACL that should be present
        operation: Name of operation for error messages (default: "operation")

    Returns:
        tuple: (returned_mode, expected_mode) - both as integers with low 9 bits

    Raises:
        AssertionError: If verification fails
    """
    # Check that both attributes are present
    if FATTR4_ACL not in attrs_dict:
        raise AssertionError(
            "ACL attribute not returned after %s" % operation)
    if FATTR4_MODE not in attrs_dict:
        raise AssertionError(
            "MODE attribute not returned after %s" % operation)

    # Verify ACL matches expected
    verify_acl(attrs_dict[FATTR4_ACL], expected_acl)

    # Verify mode matches RFC 8881 derivation from ACL
    returned_mode = attrs_dict[FATTR4_MODE] & 0o777
    expected_mode = acl2mode_rfc8881(attrs_dict[FATTR4_ACL])

    if returned_mode != expected_mode:
        raise AssertionError(
            "MODE (0%o) does not match RFC 8881 §6.3.2 derivation "
            "from ACL (expected 0%o)" % (returned_mode, expected_mode))

    return returned_mode, expected_mode

def printableacl(acl):
    type_str = ["ACCESS", "DENY"]
    out = ""
    for ace in acl:
        out += "<type=%6s, flag=%2x, access=%8x, who=%s>\n" % \
               (type_str[ace.type], ace.flag, ace.access_mask, ace.who)
    #print("leaving printableacl with out = %s" % out)
    return out
