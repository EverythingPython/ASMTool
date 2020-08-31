try:
    import sh
except:
    pass
import os, sys


def ls_cur(path, filter=lambda x: True):
    # output = sh.ls(path).stdout
    # output = str(output)
    # obj = output.split()
    # print obj
    objs = os.listdir(path)
    objs = []
    for item in os.listdir(path):
        if filter(item):
            objs.append(item)
            print(item)
    return objs


def main():
    ls_cur('.', filter=lambda x: str(x).endswith('.py'))


if __name__ == '__main__':
    main()
