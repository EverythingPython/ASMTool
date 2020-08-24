#!/usr/bin/env python3
import os
import sys
import pprint
import logging
import configparser
import json

# logging.basicConfig(format='%(levelname)s: \t%(message)s')
logging.basicConfig(format='- %(message)s')
log = logging.getLogger('git-user')
log.level = logging.INFO
logging = log

path = sys.path[0]

with open("{}/gitconfig.json".format(path)) as fd:
    db = json.load(fd)


def edit_user(path, data):
    config = configparser.ConfigParser()
    config.read(path)
    config['user'] = data
    with open(path, 'w') as configfile:
        config.write(configfile)

    print_user(path)


def print_user(path):
    config = configparser.ConfigParser()
    config.read(path)

    logging.info('current most valid config: {} {}'.format(
        config['user']['name'], config['user']['email']))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--num", help="use id",
                        action="store", default=None, type=str, dest="num")
    parser.add_argument("-g",  help="global mode",
                        action="store_true", dest="glb")
    parser.add_argument("-l",  help="list",
                        action="store_true", dest="list")
    # parser.add_argument("value", nargs=argparse.REMAINDER, type=int)
    args = parser.parse_args()

    n = args.num
    data = db.get(n, None)

    s = pprint.pformat(db, indent=4)
    logging.info('valid git account in db: \n{}'.format(s))

    global_path = '{}/.gitconfig'.format(os.path.expanduser('~'))
    local_path = '.git/config'

    if args.glb:
        logging.warn('global mode')
        path= global_path
    else:
        args.local = True
        logging.warn('local mode')
        path=local_path

    logging.info('current config file: {}'.format(path))
    try:
        print_user(path)
    except:
        if args.local:
            logging.error('get local git config error, use global instead')
            print_user(global_path)
        else:
            logging.error('get global git config error !')

    if data:
        s = pprint.pformat(data, indent=4)
        logging.info('choose and use data bellow: \n{}'.format(s))
        logging.info('will set in: {}'.format(path))
        edit_user(path, data)


if __name__ == '__main__':
    main()
