# coding=utf-8
from colorama import init, Fore, Back, Style

init(autoreset=True)


class Colored(object):

    def red(self, s):
        #  前景色:红色  背景色:默认
        return Fore.RED + s + Fore.RESET

    def green(self, s):
        #  前景色:绿色  背景色:默认
        return Fore.GREEN + s + Fore.RESET

    def yellow(self, s):
        #  前景色:黄色  背景色:默认
        return Fore.YELLOW + s + Fore.RESET

    def blue(self, s):
        #  前景色:蓝色  背景色:默认
        return Fore.BLUE + s + Fore.RESET

    def magenta(self, s):
        #  前景色:洋红色  背景色:默认

        return Fore.MAGENTA + s + Fore.RESET

    def cyan(self, s):
        #  前景色:青色  背景色:默认

        return Fore.CYAN + s + Fore.RESET

    def white(self, s):
        #  前景色:白色  背景色:默认

        return Fore.WHITE + s + Fore.RESET

    def black(self, s):
        #  前景色:黑色  背景色:默认

        return Fore.BLACK + s + Fore.RESET

    def black_green(self, s):
        return Fore.BLACK + Back.GREEN + s + Fore.RESET + Back.RESET

    #  前景色:白色  背景色:绿色  
    def white_green(self, s):
        return Fore.WHITE + Back.GREEN + s + Fore.RESET + Back.RESET

    def green_magenta(self, s):
        return Fore.GREEN + Back.MAGENTA + s + Fore.RESET + Back.RESET


color = Colored()
