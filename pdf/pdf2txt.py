# -*- coding:utf-8 -*-
import sys

from pdfminer.converter import PDFPageAggregator
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfpage import PDFTextExtractionNotAllowed
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.pdfinterp import PDFPageInterpreter
from pdfminer.layout import *


def read_pdf_text(filename):
    """
    use pdfminer to get the valid area of each page.
    all results are relative position!
    """
    # 打开一个pdf文件
    with open(filename, 'rb') as fp:
        # 创建一个PDF文档解析器对象
        parser = PDFParser(fp)
        # 创建一个PDF文档对象存储文档结构
        # 提供密码初始化，没有就不用传该参数
        #document = PDFDocument(parser, password)
        document = PDFDocument(parser)
        # 检查文件是否允许文本提取
        if not document.is_extractable:
            raise PDFTextExtractionNotAllowed
        # 创建一个PDF资源管理器对象来存储共享资源
        # caching = False不缓存
        rsrcmgr = PDFResourceManager(caching=False)
        # 创建一个PDF设备对象
        laparams = LAParams()
        # 创建一个PDF页面聚合对象
        device = PDFPageAggregator(rsrcmgr, laparams=laparams)
        # 创建一个PDF解析器对象
        interpreter = PDFPageInterpreter(rsrcmgr, device)
        # 处理文档当中的每个页面

        pageboxlist = []
        text_list = []

        # doc.get_pages() 获取page列表
        # for i, page in enumerate(document.get_pages()):
        # PDFPage.create_pages(document) 获取page列表的另一种方式
        # 循环遍历列表，每次处理一个page的内容
        for page in PDFPage.create_pages(document):
            interpreter.process_page(page)
            # 接受该页面的LTPage对象
            layout = device.get_result()
            # 这里layout是一个LTPage对象 里面存放着 这个page解析出的各种对象
            # 一般包括LTTextBox, LTFigure, LTImage, LTTextBoxHorizontal 等等
            for item in layout:
                if isinstance(item, LTTextBox) or isinstance(item, LTTextLine):

                    # 如果x是水平文本对象的话
                    if (isinstance(item, LTTextBoxHorizontal)):
                        text = item.get_text()
                    else:
                        text = item.get_text()

                    text_list.append(text)
                    text = text.encode('utf-8')
                    # print('text:{}'.format(text))
                # elif isinstance(item, LTImage):
                # 	print('image:{}'.format(item))
                # elif isinstance(item, LTFigure):
                #     print('figure:{}'.format(item))
                # elif isinstance(item, LTAnno):
                #     print('anno:{}'.format(item))
                # elif isinstance(item, LTChar):
                #     print('char:{}'.format(item))
                # elif isinstance(item, LTLine):
                #     print('line:{}'.format(item))
                # elif isinstance(item, LTRect):
                #     print('rect:{}'.format(item))
                # elif isinstance(item, LTCurve):
                #     print('curve:{}'.format(item))

    return text_list


def save_txt(text_list):
    import codecs
    with codecs.open("istxt.txt", "w", 'utf-8') as f:
        for text in text_list:
            f.write(text)


text_list = read_pdf_text('test.pdf')
save_txt(text_list)
