# get symbol table include name, addr, size
# if no symbol table exists, just get info from IDA

from idautils import *
from idc import *
from idaapi import *

g_segment = {}


def in_segment(addr, seg_name):
    if seg_name in g_segment:
        start, end = g_segment.get(seg_name)
        return start <= addr <= end
    return False


def get_segment():
    """
    save into global
    :return:
    """
    if g_segment:
        return g_segment

    seg = Segments()
    for s in seg:
        name = SegName(s)
        start, end = s, SegEnd(s)
        g_segment[name] = (start, end)

    print g_segment
    return g_segment


def get_string_in_func(addr):
    print DataRefsFrom(addr)
    for i in DataRefsFrom(addr):
        print hex(i.frm)


def get_string_xrefs():
    # Get the strings so we can see what might have been passed in
    print "Getting string xrefs"
    sc = Strings(default_setup=False)
    # we want C & Unicode strings, and *only* existing strings.
    sc.setup(ignore_instructions=True,
             display_only_existing_strings=True)

    # Make a list of all string locations
    string_locs = []
    for s in sc:
        string_locs.append((s.ea, str(s)))
        print "%x: len=%d -> '%s'" % (s.ea, s.length, str(s))

    # Make a dict of all places strings are Xrefs
    string_xrefs = {}
    for loc in string_locs:
        # print "%08X  %s" % (loc[0], loc[1])
        for xref in XrefsTo(loc[0]):
            print "Xref @ %08X" % xref.frm
            string_xrefs[xref.frm] = loc

    return string_xrefs


def get_sym_table():
    """

    :return: symbol table [(),(name,addr,size)]
    """
    data = []
    addr = 0
    while 1:
        addr = NextFunction(addr)
        if addr == BADADDR:
            break

        name = Name(addr)
        end = GetFunctionAttr(addr, FUNCATTR_END)
        size = end - addr
        # print name, addr, size
        data.append((name, addr, size))

    return data


def write_sym_table(data, path="sym_table.txt"):
    with  open('sym_table.txt', 'w')as fd:
        for item in data:
            fd.write("{} {} {}\n".format(*item))


def filter_by_seg(data, seg_name):
    """

    :param data:
    :param seg_name:
    :return:
    """
    ans = []
    for item in data:
        if in_segment(item[1], seg_name):
            ans.append(item)
    return ans


def main():
    # print os.getcwd()
    # get_string_xrefs()
    print get_bytes(21236376, 382, 0)
    return

    get_segment()
    data = get_sym_table()
    data = filter_by_seg(data, ".text")
    write_sym_table(data)

    # get_string_in_func(412244)


if __name__ == '__main__':
    main()
