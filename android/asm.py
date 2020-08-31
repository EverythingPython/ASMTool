#!/usr/bin/env python  
# coding=utf-8  
import zipfile  
import os  
import sys

args = sys.argv
path = args[1]
  
so_path=args[1]
  
apklist=os.listdir(path)  
  
for APK in apklist:  
    if APK.endswith(".zip"):  
        portion = os.path.splitext(APK)  
        apkname = portion[0]  
        abs_so_path=os.path.join(so_path,apkname) #/so/apkname/  
        abs_zipAPK_path=os.path.join(path,APK)  
        z = zipfile.ZipFile(abs_zipAPK_path,'r')  
        solists=[]  
        for filename in z.namelist():  
            if filename.endswith(".so"):  
                sofileName = os.path.basename(filename)  
                soSource = os.path.basename(os.path.dirname(filename))  
                ''''' 
                make a dir with the source(arm?mips) 
                '''  
                storePath=os.path.join(abs_so_path,soSource) # e.g. /.../so/apkname/mips/  
                if not os.path.exists(storePath):  
                    os.makedirs(storePath)  
  
                ''''' 
                copy the xxx.so file to the object path 
                '''  
                newsofile=os.path.join(storePath,sofileName)  
                f = open(newsofile,'w')  
                f.write(z.read(filename))  