import sys
try:
    from mutil.colorstr import *
except:
    pass


def readable(i):
    if 32 <= i < 128:
        return True
    return False


def ascii():
    try:
        colors = [color.red, color.blue, color.green]
        dec_color, hex_color, chr_color = colors
        spec_chr_color = color.green_magenta
    except:
        colors = [str] * 3
        dec_color, hex_color, chr_color = colors
        spec_chr_color = str

    spec_chr = ['a', 'z', 'A', 'Z', '0', '9', '\x0a', '\x0b']

    table = []

    # prepare data
    for i in xrange(128):
        res = []
        s = "%3d" % i
        res.append(dec_color(s))
        s = "\\x%02x" % i
        res.append(hex_color(s))

        if readable(i):
            s = "%c" % i
        else:
            s = ' '

        if chr(i) in spec_chr:
            res.append(spec_chr_color(s))
        else:
            res.append(chr_color(s))

        table.append(res)

    # print
    TAB = "\t"
    for i in range(len(table)):
        res = TAB.join(table[i])
        if i % 4 == 0:
            print
        print res,


def main():
    ascii()


if __name__ == '__main__':
    main()
