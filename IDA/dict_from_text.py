import re


def process_spec_func(i, text):
    line = text[i]
    if "strcmp" in line:
        print(line)
        args = text[i - 2:i]
        for arg in args:
            if ';' in arg and '"' in arg:
                s = arg.split(';')[-1].strip()
                print(s)
                return s
    return None


def process_spec_ins(i, text):
    line = text[i]
    match = re.search(r'; (\'\w+\')', line)
    if match:
        s = match.groups()[0]
        print(s)
        return s

    match = re.search(r'cmp.*([0-9A-Ea-e]+)[h]?[;]?', line)
    if match:
        s = match.groups()[0]
        try:
            may_int = int(s, 16)
            print(may_int)
            return may_int
        except:
            pass

    return None


def analyse(text):
    datadict = set()
    i = 1
    while i < len(text):
        found = process_spec_func(i, text)
        if found:
            datadict.add(found)
        found = process_spec_ins(i, text)
        if found:
            datadict.add(found)
        i += 1
    return datadict


def main():
    filepath = 'disasm.txt'
    filepath = 'grep.txt'
    filepath = 'lighttpd.txt'
    datadict = set()

    with open(filepath) as fd:
        while 1:
            text = fd.readlines(100)
            if text:
                found = analyse(text)
                datadict.update(found)
            else:
                break
    print(datadict)


if __name__ == '__main__':
    main()
