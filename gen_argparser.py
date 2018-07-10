import sys
import os
import argparse


def gen_handler(type_name, action='store',nargs=None):
    def handler(short, long,default=None, doc=None):
        statement = 'parser.add_argument({})'
        parameters = []

        dest = ''
        if short:
            parameters .append('"{}"'.format(short))
                    

        if long:
            # may use another dest but the long
            if '/' in long:
                items = long.split('/')
                long,dest = items
            else:
                dest = long[2:]
                
            parameters .append('"{}"'.format(long))

        s = 'help="{}", action="{}"'.format(doc if doc else '',action)
        parameters.append(s)

        if default:
            s = 'default={}'.format(default)
            parameters.append(s)

        if type_name:
            s = 'type={}'.format(type_name)
            parameters.append(s)
        
        if nargs:
            s = 'nargs="{}"'.format(nargs)
            parameters.append(s)

        if dest:
            s = 'dest="{}"'.format(dest)
            parameters.append(s)

        res = statement.format(', '.join(parameters))
        #s='parser.add_argument("-{}", "--{}", help="", actoin="", dest="{}", type={}, )'.format(short,long,long ,type_name)
        print(res)

    return handler


type_map = {
    'int': gen_handler('int'),
    'list': gen_handler(None,nargs='+'),
    't': gen_handler(None,'store_true'),
    'f': gen_handler(None,'store_false'),
    'str': gen_handler('str'),
    'bool': gen_handler('bool')
}


def process(cmd):
    cmds = cmd.split(',')
    cmds = [c.strip() for c in cmds if c.strip()]
    for c in cmds:
        pair = c.split('=')

        post  = pair[-1]
        if '(' in post:
            post = post.split('(')
            doc = '('.join(post[1:])[0:-1]
            pair[-1]=post[0]
        else:
            doc=None

        if len(pair) == 1:
            # default bool store_true           
            pair.extend([ 't', ''])
        elif len(pair) == 2:
            pair.append( '')
        opt, value, default = pair
        

        # may short or long
        opts = opt.split('--')
        short = None
        long = None
        for item in opts:
            if '-' in item:
                short = '{}'.format(item)
            else:
                long = '--{}'.format(item)
        # # if len(opts)==1
        # if not opts[0]:
        #     # no short
        #     short = None
        #     long = opts[-1]
        # elif len(opts) <= 1:
        #     # no long
        #     short = opts[0]
        #     long = None
        # else:
        #     short = opts[0]
        #     long = '-'.join(opts[1:])

        type_handler = type_map[value]
        type_handler(short, long,default, doc)
        # print(short, long, value)


def main():
    args = sys.argv
    if len(args) <= 1:
        s='''
        s-string=str(give string type)
        '''
        s='''
        v-visit=t,
        l-listen=t
        '''
        s='''
        e-eidoo=int=1(use eidoo website),
        u-update=int=0(update all),
        d-delay=int=1(process with delay),
        '''
        s='''
        F-split/splitor=str=' '(splitor),
        p-format=str=''(print data format),
        e-escape=t(include escape code),
        v-verbose=t
        '''
        s='''
        p-port=int=9001(port),
        t-time=int=0(timer(s))
        '''
        s='''
        s-setting=str="setting.json",
        d-data=str="cv.json",
        t-template=str="templates/default_html.mustache"
        '''
        s='''
        k-key=str='arm',n-num=int=0
        '''
        s="-s--sim=str='test',--key=int='heheh'"
        # how to use
        # s-split/split=str=' '(splitor)
        # each means: short, long, dest, type, default, help
        # many of them can be ignored
    else:
        s = args[1]

    print('import argparse')
    print('parser = argparse.ArgumentParser()')
    process(s)
    print('parser.add_argument(nargs=argparse.REMAINDER, dest="value")')
    print('args = parser.parse_args()')


if __name__ == '__main__':
    main()
