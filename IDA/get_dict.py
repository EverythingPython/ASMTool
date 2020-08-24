from .idautils import *
from .idc import *


def process_spec_func(i, text):
    line = text[i]
    if "strcmp" in line:
        print(line)
        args = text[i - 2:i]
        for arg in args:
            if ';' in arg and '"' in arg:
                s = arg.split(';')[-1].strip()
                print(s)

def process_spec_ins(i, text):
    line = text[i]
    if ';' in line and '\'' in line:
        s = line.split(';')[-1].strip()
        print(s)


def get_dict(funcea):
    name = Name(funcea)
    text = []
    items = FuncItems(funcea)
    for ea in items:
        disasm = GetDisasm(ea)
        # print(disasm)
        comment = RptCmt(ea)
        # print(comment)

        text.append(disasm)

    # i = 1
    # while i < len(text):
    #     process_spec_func(i, text)
    #     process_spec_ins(i, text)
    #     i += 1

    return text


def main():
    with open('disasm.txt', 'wb') as fd:
        for segea in Segments():
            segname = SegName(segea)
            print(segname)
            if "text" not in segname:
                continue
            for funcea in Functions(segea, SegEnd(segea)):
                # get_dict(0x6002A - 1)
                text = get_dict(funcea)
                for line in text:
                    fd.write(line)
                    fd.write('\n')

                # for (startea, endea) in Chunks(funcea):
                #     for head in Heads(startea, endea):
                #         print functionName, ":", "0x%08x" % (head), ":", GetDisasm(head)


if __name__ == '__main__':
    main()
