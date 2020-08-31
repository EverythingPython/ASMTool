#!/usr/bin/env python  
# -*- coding: UTF-8 -*-
'''
script to search target in github.
mainly used to find oss from github which is found in a binary.
'''

import sys
import argparse


search_code_url = 'https://github.com/search?utf8=%%E2%%9C%%93&q={}&type=Code'

select_code = '#code_search_results > div.code-list'

def search_code():
    pass

def get_most():
    """
    词频分析
    """
    pass

def select_text(item):
    """
    get the text without html tag of search result
    """
    for i in 'abcdef':
        if i in item:
            return True
    return False



def save_res(item):
    """
    save all results, 
    including 
    each page output,
    the most found url.

    """
    item = item.lower()
    if '0x' in item:
        # 0x123
        n = int(item, 16)
    elif 'h' == item[-1]:
        # 123ah
        n = int(item[0:-1], 16)
    elif may_hex(item):
        # 12af
        n = int(item, 16)
    else:
        n = int(item, 10)

    return n






def main():
    args = sys.argv
    # if len(args) <= 1:
    #     print("at least 1 args")
    #     exit(0)

    args = parse_opt()
    print(args)

    # only accept one arg
    if args.string:
        for item in args.value:
            n = process_str(item)
            print_str(n)
    else:
        for item in args.value:
            # item = ''.join(args[1:])
            n = process_int(item)
            print_int(n)


if __name__ == '__main__':
    main()
