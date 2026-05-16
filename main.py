# -*- coding: utf-8 -*-
import os

def batch_apk():
    for f in os.listdir('apk'):
        if len(f) > 4:
            if f[-4:] == '.apk':
                os.system('python ApkTool.py -analyse -inapk apk/' + f)

if __name__ == '__main__':
    batch_apk()
