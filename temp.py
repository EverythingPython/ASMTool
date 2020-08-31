import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-e", "--eclipse-list", help="hehh", action="store", default=[123], nargs="+", dest="eclipse-list")
parser.add_argument("-a", "--a-str", help="", action="store",default=123, type=str, dest="a-str")
parser.add_argument("-b", "--be-int", help="", action="store", default='123', type=int, dest="be-int")
parser.add_argument("-c", help="", action="store_true")
parser.add_argument("--true", help="", action="store_true", dest="true")
args = parser.parse_args()

print args