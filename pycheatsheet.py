#coding=utf8
import os
import sys

db = {
    "": [
        """
        """
    ],
    "format": [
    """
    3.1415926	{:.2f}	3.14	保留小数点后两位
    3.1415926	{:+.2f}	+3.14	带符号保留小数点后两位
    -1	        {:+.2f}	-1.00	带符号保留小数点后两位
    2.71828	    {:.0f}	3	不带小数

    5	        {:0>2d}	05	数字补零 (填充左边, 宽度为2)
    5	        {:x<4d}	5xxx	数字补x (填充右边, 宽度为4)
    10	        {:x<4d}	10xx	数字补x (填充右边, 宽度为4)

    1000000	    {:,}	1,000,000	以逗号分隔的数字格式
    0.25	    {:.2%}	25.00%	百分比格式
    1000000000	{:.2e}	1.00e+09	指数记法
    13	        {:10d}	13	右对齐 (默认, 宽度为10)
    13	        {:<10d}	13	左对齐 (宽度为10)
    13	        {:^10d}	13	中间对齐 (宽度为10)
    
    11	
    '{:b}'.format(11)
    '{:d}'.format(11)
    '{:o}'.format(11)
    '{:x}'.format(11)
    '{:#x}'.format(11)
    '{:#X}'.format(11)	
        """
    ],
    "pack type": [
        """
        pack(fmt, v1, v2, ...) - return s include each bytes
        unpack(fmt, string) - return tuple fo each     
        calcsize(fmt) - memory check
        """,
        """
        x	pad byte	no value	 	 
        c	char	string of length 1	1	 
        b	signed char	integer	1	(3)
        B	unsigned char	integer	1	(3)
        ?	_Bool	bool	1	(1)
        h	short	integer	2	(3)
        H	unsigned short	integer	2	(3)
        i	int	integer	4	(3)
        I	unsigned int	integer	4	(3)
        l	long	integer	4	(3)
        L	unsigned long	integer	4	(3)
        q	long long	integer	8	(2), (3)
        Q	unsigned long long	integer	8	(2), (3)
        f	float	float	4	(4)
        d	double	float	8	(4)
        s	char[]	string	 	 
        p	char[]	string	 	 
        P	void *	integer	 	(5), (3)
        """,
        """    
        CHARACTER	BYTE ORDER	SIZE	ALIGNMENT
        @	native	native	native
        =	native	standard	none
        <	little-endian	standard	none
        >	big-endian	standard	none
        !	network (= big-endian)	standard	none
        """
    ],
    "convert": [
        '''
        ord(),
        chr(),
        int('0x11',16),
        float(),
        hex()
        oct()
        
        str(),
        bytes(),
        list()
        set
        repr
        unichr
        ''',

        "encode(''): a='\\n'; b=a.encode('unicode-escape');b=='\\\\n'",
        "decode(''): b='\\\\n'; a=b.decode('unicode-escape');a==u'\\n'",
    ],
    "magic-class special": [
        '''
        __new__(cls)
        __init__(self, args)
        __del__(self)
        __repr__(self)
        __str__(self)
        __cmp__(self, other)
        __index__(self)
        __hash__(self)
        __getattr__(self, name)
        __getattribute__(self, name)
        __setattr__(self, name, attr)
        __delattr__(self, name)
        __call__(self, args, kwargs)
        __lt__(self, other)
        __le__(self, other)
        __gt__(self, other)
        __ge__(self, other)
        __eq__(self, other)
        __ne__(self, other)
        __nonzero__(self)
        '''
    ]
}


def print_res(key):
    content = db[key]
    print("{}\ncontent of: {}".format("- " * 40, key))
    for item in content:
        print("\t{}".format(item))


def main():
    args = sys.argv
    if len(args) > 1:
        target = args[1]
    else:
        target = None

    if not target:
        for key in db:
            print_res(key)
    else:
        for key in db:
            if target in key:
                print_res(key)


if __name__ == '__main__':
    main()
