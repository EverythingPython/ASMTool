import json

def combine(*args):
    res={}
    for dct in args:
        for key, value in dct.iteritems():
            res[key]=value
    return res

def load(path):
    with open(path) as fd:
        data = json.load(fd)
        print data
        print type(data)
        #data = json.loads(data)
    return data

def main():
    data1 = load('test1.json')
    data2 = load('test2.json')
    data = combine(data1,data2)
    print (data)
    with open('output.json','w+') as fd:
        json.dump(data,fd)

if __name__ == '__main__':
    main()