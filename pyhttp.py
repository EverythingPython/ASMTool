#!/usr/bin/env python2
import sh
import sys
import os
import re
import SimpleHTTPServer
import SocketServer
import urllib
import urlparse
import argparse

DEFAULT_PORT = 9001

parser = argparse.ArgumentParser(description='python -m SimpleHTTPServer 8080')
parser.add_argument("-p", "--port", help="port", action="store",
                    default=DEFAULT_PORT, type=int, dest="port")
parser.add_argument("-t", "--time", help="timer(s)",
                    action="store", default=0, type=int, dest="time")
parser.add_argument("-n", "--num", help="number",
                    action="store", default=None, type=int, dest="num")
parser.add_argument(nargs=argparse.REMAINDER, dest="value")
args = parser.parse_args()


class LimitHTTPServer(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def send_head(self):
        """Common code for GET and HEAD commands.

        FF: Limit it is function

        This sends the response code and MIME headers.

        Return value is either a file object (which has to be copied
        to the outputfile by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.

        """
        path = self.translate_path(self.path)
        f = None

        # FF: a dir process
        # FF: limit function
        if not args.value:
            if os.path.isdir(path):
                parts = urlparse.urlsplit(self.path)

                # FF: return a file
                if not parts.path.endswith('/'):
                    # redirect browser - doing basically what apache does
                    self.send_response(301)
                    new_parts = (parts[0], parts[1], parts[2] + '/',
                                 parts[3], parts[4])
                    new_url = urlparse.urlunsplit(new_parts)
                    self.send_header("Location", new_url)
                    self.end_headers()
                    return None

                # FF: return the index or dir list
                for index in "index.html", "index.htm":
                    index = os.path.join(path, index)
                    if os.path.exists(index):
                        path = index
                        break
                else:
                    return self.list_directory(path)

        # FF: a file process
        ctype = self.guess_type(path)
        try:
            # FF: strict limit file here
            if args.value:
                valid = [os.path.join(os.getcwd(), f) for f in args.value]
                if path not in valid:
                    raise Exception('no privilege for these files')

            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None
        try:
            self.send_response(200)
            self.send_header("Content-type", ctype)
            fs = os.fstat(f.fileno())
            self.send_header("Content-Length", str(fs[6]))
            self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
            self.end_headers()
            return f
        except:
            f.close()
            raise


def get_ip():
    res = sh.ifconfig().stdout
    found = re.findall(r'inet ([0-9.]+[0-9]+)', res)
    for n, ip in enumerate(found):
        print('{} - {}'.format(n, ip))
        # print(m.groups())
        # print(m.group(1))
        # ip = m.group(1)
    if args.num is None:
        # give a default one
        ret = found[0]
        for ip in found:
            # ignore local
            if ip == '127.0.0.1':
                continue
            else:
                ret = ip
                break
    else:
        ret = found[args.num]

    return ret


def main():
    print('e.g. python -m SimpleHTTPServer 8080')

    port = args.port
    print('port {}'.format(port))

    ip = get_ip()
    print('start http server at:\n{}:{}'.format(ip, port))
    sys.stdout.flush()

    # set files
    if not args.value:
        print(os.listdir('.'))
    else:
        for i in args.value:
            print('may wish to visit:\n{}:{}/{}'.format(ip, port, i))
    sys.stdout.flush()

    # http server
    handler = LimitHTTPServer
    httpd = SocketServer.TCPServer(("", port), handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt as ki:
        httpd.shutdown()
        print('server shut down')
    except Exception as e:
        print('stop http server')


if __name__ == '__main__':
    main()
