import os
import shelve
import sys
from subprocess import check_call
if sys.hexversion > 0x03000000:
    import winreg
else:
    import _winreg as winreg

#test file data for 
pathFile="path.dat"
runFile="runlist.dat"
testShelve='testShelve.dat'
sysKeyEnv="C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;"
splitChar='|'
backFile="backup.dat"

class Software(object):
	def __init__(self,name,path=""):
		self.name=name
		self.path=path
	def setPath(self,path):
		self.path=path
		print(self.path)

def get_software(db,name):
	return db[name];

#store the software path into file
def store_softwarepath(db,data):
	#if(isinstance(data,Software))
		pid=data.name;
		db[pid]=data
		print("stored software:%s with path:%s" %(data.name,data.path))

#read the software path from file
def read_softwareInfo():
	file=open(pathFile)
	rnt=""
	for eachLine in file:
		#print(eachLine)
		ch=eachLine[0]
		#end flag
		if ch=='#':
			break;
		strs=eachLine.split(splitChar)
		path=strs[1].strip()#remove the space char
		print(path)
		rnt=rnt+path+';'
		'''
		cnt=0
		for eachStr in strs:
			print(cnt),
			print(","),
			cnt=cnt+1
			print(eachStr)
		'''
	file.close()
	return rnt
	
#get the environ from os
def getEnv(s='PATH'):
	path=os.environ[s]
	return path
	'''
	#filename = os.environ.get(s)
	#print(filename)
	#if filename and os.path.isfile(filename):
	#	execfile(filename)
	'''
#set new environ of python(only run-time)
def setEnv(path="PATH",value=sysKeyEnv):
	os.environ[path]=value;
	print("%s=%s" %(path,value))


	
#write environ into system(using registry table)
def writeEnv(name='',value=''):
	if name=='' or value=='':
		return
	
	#global reg change
	#must be run as administrator
	root = winreg.HKEY_LOCAL_MACHINE
	subkey = 'SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment'
	key = winreg.OpenKey(root, subkey, 0, winreg.KEY_ALL_ACCESS)
	print key
	winreg.SetValueEx(key, name, 0, winreg.REG_EXPAND_SZ, value)
	winreg.CloseKey(key)
	
#get from internet
def otherEnv():
	print (os.environ["TEMP"])
	mydir = "c:\\mydir"
	os.environ["MYDIR"] = mydir
	print (os.environ["MYDIR"])
	pathV = os.environ["PATH"]
	print (pathV)
	os.environ["PATH"]= mydir + ";" + os.environ["PATH"]
	print (os.environ["PATH"])
		

END_PROGRAM=0
GEN_NEW=1
GEN_AND_RUN=2
WRITE_NEW=3
BACKUP=4
RECOVERY=5
choiceId=[GEN_NEW,GEN_AND_RUN,WRITE_NEW,BACKUP,RECOVERY]
choiceInfo=["generate new PATH environ(won't change the system environ)",\
"generate new PATH and run the Instruction in file",\
"write new PATH environ(will change the system environ",\
"back up the PATH environ",\
"recovery the PATH environ"
]
	
#print help info
def helpMe():
	print("This is a tool for program running under your own set environ.")
	print("You can add your own environ into the file:,one line for one path.")
	print("Please use a '|' to split the name(software) and value(path),and use the '#' in a line for end.")
	cnt=0
	for eachInfo in choiceInfo:
		print("%d.%s" %(choiceId[cnt],choiceInfo[cnt]))
		cnt=cnt+1
		
def genNewPath(path="PATH",value=sysKeyEnv):
	value=getEnv(path)#cur env path
	print(value)
	userDefEnv=read_softwareInfo()#user add env path
	print(userDefEnv)
	setEnv(path,userDefEnv+value)#set new env path
	return getEnv(path)
		
def main():
	while True:
		helpMe()
		choice=int(raw_input())
		if choice==END_PROGRAM:
			return
		if choice==GEN_NEW:
			genNewPath()
		elif choice==GEN_AND_RUN:
			genNewPath()
			file=open(runFile,"r")
			for eachLine in file:
				print(eachLine)
				os.system(eachLine)
			file.close()
		elif choice==WRITE_NEW:
			value=genNewPath()
			writeEnv('test',value)
			
		elif choice==BACKUP:
			path=getEnv("PATH")
			print(path)
			print("This behavior will backup your PATH environ"+\
			"but the last backup,you sure to do it?(y/n)")
			ch=raw_input()
			if ch=='y':
				file=open(backFile,"w+")#w+ create new file each time
				file.write(path)
				file.close()
				print("Backup successfully!")
		raw_input()
	#writeEnv()
	#s=shelve.open(testShelve)	
	#os.system('cmd')
	#print(s.size())
	#tt=Software(softname[0])
	#tt.setPath("path of java")
	#store_softwarepath(s,tt);
	#s.close()
	raw_input()

if __name__=='__main__':main()