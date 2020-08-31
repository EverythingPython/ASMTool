#!/usr/bin/env python
#coding=utf-8
import sys,os
import yaml
import pprint
import json

pp=pprint.PrettyPrinter(indent=4)

with open('cheatsheet/sh.yaml')as fd:
    db = yaml.load(fd)
#print(db)

def print_res(data,key):
    content = data[key]
    
    key = key.encode('utf8')
    print("{}\n{}".format("- " * 40, key))

    if not content:
        pass
    elif isinstance(content,list):
        for item in content:
            item = item.encode('utf8')
            print("\t{}".format(item))
    elif isinstance(content,dict):
        # for key in content:
        #     print_res(content,key)
        content = json.dumps(content, 
        indent=4,
        ensure_ascii=False, encoding='UTF-8')  
        # content = content.decode('unicode-escape')
        try:
            print(content)
        except:
            pass
    else:
        content = content.encode('utf8')
        print("\t{}".format(content))

def print_all():
    content = json.dumps(db, 
        indent=4,
        ensure_ascii=False, encoding='UTF-8')  
    print(content)

def main():
    args = sys.argv
    if len(args) > 1:
        target = args[1]
    else:
        target = None
    print_all()

    if not target:
        for key in db:
            print_res(db,key)
    else:
        for key in db:
            if target in key:
                print_res(db,key)


if __name__ == '__main__':
    main()
