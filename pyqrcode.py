#!/usr/bin/env python3
import qrcode
import sys
import os
import qrcode
from PIL import Image
from pyzbar import pyzbar

if len(sys.argv):
    data =sys.argv[1]
else:
    exit()

img_file = '/tmp/qrcode.png'

def decode_qr_code(code_img_path):
    if not os.path.exists(code_img_path):
        raise FileExistsError(code_img_path)

    # Here, set only recognize QR Code and ignore other type of code
    return pyzbar.decode(Image.open(code_img_path), symbols=[pyzbar.ZBarSymbol.QRCODE])


if os.path.isfile(data):
    # decode
    d = decode_qr_code(data)[0]
    print('result: ', d.data)
else:
    # 实例化QRCode生成qr对象
    qr = qrcode.QRCode(
        # version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        # box_size=10,
        # border=4
    )
    # 传入数据
    qr.add_data(data)

    qr.make(fit=True)

    # 生成二维码
    img = qr.make_image()

    # 保存二维码
    # img.save(img_file)
    # 展示二维码
    img.show()