import sys
import subprocess
import re
import os
import errno
import datetime
import requests
import pymongo
import hashlib

import time

#============= Global Variables ========================#
														#
PATH_LIST = "repos/%s/"									#
PATH_PACKAGE = "pool/"									#
URL_PPA = "http://ppa.launchpad.net/%s/ubuntu/dists/"	#
														#
BASH_ARIA = "aria2c -t 5 -d %s -o %s %s"				#
														#
DISTROS = ["lucid", "precise", "quantal", "raring"]		#
ARCHITECTURES = ["i386", "amd64"]						#
														#
#=======================================================#


#============= Database - MongoDB init =================#
#														#
# COLLECTION_NAMES = ["Versions", "Repos", "Packages"]	#
#														#
														#
DB = None												#
DATABASE_NAME = "proba1"								#
														#
def dbInit(reset = False):								#
	from pymongo import MongoClient						#
	global DB											#
	DB = MongoClient()[DATABASE_NAME]					#
	if reset:											#
		from pymongo import Connection					#
		c = Connection().drop_database(DATABASE_NAME)	#
		DB = MongoClient()[DATABASE_NAME]				#
														#
#=======================================================#


#====================== Logger =========================#
														#
LOG = True												#
LOG_FUNCS = ["providedSolver"]
														#
if LOG:													#
	import inspect										#
														#
def logger(toPrint):									#
	if not LOG:											#
		return											#
	cF = inspect.currentframe()							#
	fName = inspect.getouterframes(cF,2)[1][3]			#
	if fName in LOG_FUNCS:								#
		print(toPrint)									#
														#
#=======================================================#

#======================= Common Tools ==============================#

def execBashCMD(cmd):
	process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
	return process.communicate()[0].decode("utf8")
			
def silentRemove(filename):
	try:
		os.remove(filename)
	except OSError as e:
		if e.errno != errno.ENOENT:
			raise #raise if error is not "no such file or directory"

def silentMove(_from, _to):
	try:
		os.renames(_from, _to)
	except OSError as e:
		if e.errno != errno.ENOENT:
			raise #raise if error is not "no such file or directory"

#===================================================================#

#======================== Solvers ==================================#

def dependencieSolver(repo_id):
	return

def providedSolver(repo_id):
	pkgs = {} #speedUp
	for v_dict in DB.Versions.find({"repo_id": repo_id, "status": 1}):
		logger("SOLVING :: \n" + str(v_dict))
		solvingVersion = Version(**v_dict)
		for pName in solvingVersion.provides:
			logger(pName)
			if pName in pkgs:
				p = pkgs[pName]
			else:
				p = Package.searchDB(pName)
			
			if p is None:
				logger("\tCreating new package")
				newP = Package(pName)
				newP.repo_ids = [repo_id]
				newP._id = P.saveToDB()
				
				newV = Version(repo_id)
				newV.package_id = newP._id
				newV.architecture = solvingVersion.architecture
				newV.v = ""
				newV.releaseDate = datetime.datetime.now().timestamp()
				newV.depends = []
				newV.file_id = None
				newV.status = 0
				newV.provides = []
				v_id = newV.saveToDB
				
				newP.version_ids = [v_id]
				newP.saveToDB()
				continue
								
			finder = {
				"repo_id": repo_id, 
				"architecture": {"$in": [solvingVersion.architecture, "all"]},
				"package_id": p._id, 
				"distro": solvingVersion.distro
				}
				
			tmpV_dict = DB.Versions.find(finder)
			logger("DEPENDENCIE :: \n" + str(tmpV_dict))
			input()
			break
			
			
			# IF this package does not exists in DB:
			if p is None:
				#newV = Version(
				
				#newP = Package(pName)
				#newP.version_ids = []
				pkgs[pName] = None
			elif "providedBy" in p.__dict__:
				if p[_id] not in P.providedBy:
					P.providedBy.append(p[_id])
			else:
				return
				#for v in P.
		break


#########################################################################
############################### CLASSES #################################
#########################################################################

class Package:
	'''
	_id
	name
	repo_ids
	version_ids
	'''
	def __init__(self, *args, **kwargs):
		if args:
			self.name = args[0]
		elif kwargs:
			self.__dict__.update(kwargs)
	
	def listItemUpdate(showpkg, repo_id, distro):

		#shopkg string -> pkg dict
		prev = ""
		pkg = {}
		for line in iter(showpkg.splitlines()):			
			double = line.split(": ", 1)
			if (len(double) == 1) or (double[0][0] == " "):
				pkg[prev] += "".join(double)
			else:
				prev = double[0]
				pkg[double[0]] = double[1]
		
		#Search DB and add architecture
		P = Package.searchDB(pkg["Package"])
		if not P:
			P = Package(pkg["Package"])
			P.version_ids = []
			P.repo_ids = [repo_id]
			P._id = P.saveToDB()
		
		newV = Version(repo_id)
		newV.v = re.sub("[a-zA-Z].*$", "", pkg["Version"])
		newV.architecture = pkg["Architecture"]
		newV.sha256 = pkg["SHA256"]
		
		for oldV_id in P.version_ids:
			oldV = Version.getFromDB(oldV_id)
			
			#if architecture and repo fits, then we check matching hash
			if ( 
			    (oldV.repo_id == newV.repo_id) and
			    (distro == oldV.distro) and
			    (
			     oldV.architecture == newV.architecture or 
			     oldV.architecture == "all"
			    ) 
			   ):
				vMatch = (oldV.v==newV.v)
				hMatch = (oldV.sha256==newV.sha256)
				if vMatch ^ hMatch:
					print("version-hash mismatch :: " + str(P._id) + " in repo " + str(repo_id))

				if vMatch and hMatch:
					return
				else:
					oldV.status = 10 #version is old
					oldV.saveToDB()
					newV.prev = oldV_id
					break
		
		P.updated = True
		if repo_id not in P.repo_ids:
			P.repo_ids.append(repo_id)
				
		newV.fileLocation = pkg["Filename"]
		newV.size = int(pkg["Size"])
		newV.distro = distro
		newV.status = 1
		newV.package_id = P._id
		newV.releaseDate = datetime.datetime.now().timestamp()
		
		depends = []
		for deps in ["Suggests", "Depends", "Pre-Depends", "Recommends"]:
			if deps not in pkg:
				continue
			for d in pkg[deps].split(", "):
				ORs = d.split(" | ")
				for or_dependencie in ORs:
					depends.append(or_dependencie.split(" ",1)[0])
		newV.depends = list(set(depends))
		
		newV.provides = []
		if "Provides" in pkg:	
			for provided in pkg["Provides"].split(", "):
				newV.provides.append(provided)
			
		v_id = newV.saveToDB()
		P.version_ids.append(v_id)
		P.saveToDB()
		
	def solveDependencies(self, repo_id):
		for v_id in self.version_ids:
			myDependencies = []
			tmpV = Version.getFromDB(v_id)
			logger("solving version :: " + tmpV.distro + "." + tmpV.architecture)
			myDependencies.append(v_id)
			tmpV.dependencieHelper(repo_id, tmpV.architecture, myDependencies)
			tmpV.depends = myDependencies
			tmpV.saveToDB()
		
	def fillFromDB(self):
		return Package.searchDB(self.name)
		
	def getFromDB(_id):
		return DB.Packages.find_one({"_id": _id})
		
	def searchDB(name):
		pDict = DB.Packages.find_one({"name": name})
		
		if not pDict:
			return None
		return Package(**pDict)
	
	def saveToDB(self):
		return DB.Packages.save(self.__dict__)
	
class Version:
	'''
	_id
	repo_id
	architecture
	distro
	v (version)
	
	depends
	provides
	
	size
	fileLocation
	sha256
	downloaded
	'''
	def __init__(self, *args, **kwargs):
		if args:
			self.repo_id = args[0]
		elif kwargs:
			self.__dict__.update(kwargs)
			
	def dependencieHelper(self, repo_id, mainArch, mainDependencies):		
		for dep in self.depends:					
			depPkg = Package.searchDB(dep)
			if depPkg is None:
				logger("\t\tN :: " + dep)
				continue
			logger("\t\tP :: " + dep)
			
			depV = None
			for v_id in depPkg.version_ids:
				tmpV = Version.getFromDB(v_id)
				
				if not tmpV.distro == self.distro:
					logger("\t\t\txD\t%s.%s" % (tmpV.distro, self.distro))
					continue
				if not ((tmpV.architecture == mainArch) or ("all" in [mainArch, tmpV.architecture])):
					logger("\t\t\txA\t%s.%s" % (tmpV.architecture, mainArch))
					continue
				if not str(tmpV.repo_id) == str(repo_id):
					logger("\t\t\txA\t%s:%s" % (str(tmpV.repo_id), str(repo_id)))
					continue
				if tmpV._id in mainDependencies:
					logger("\t\t\txI")
					depV = None
					break
				
				depV = tmpV
				break
			
			if not depV:
				continue
			
			logger("\tRECURSION_START :: " + depPkg.name)
			#input()
			mainDependencies.append(depV._id)
			depV.dependencieHelper(repo_id, mainArch, mainDependencies)
			logger("\tRECURSION_STOP :: " + depPkg.name)
			

	
	def getFromDB(_id):
		vDict = DB.Versions.find_one({"_id": _id})
		#if not in DB, raise!
		if not vDict:
			raise
		return Version(**vDict)
		
	def saveToDB(self):
		return DB.Versions.save(self.__dict__)
	
	def setupFile():
		#  Download Filename, 
		#  check with hash, 
		#  store it for repackaging
		# make it a thread ?
		return None
	
class Repo:
	'''
	releases
	name
	disabled
	holdUpdate
	'''
	
	def __init__(self, *args, **kwargs):
		if args:
			self.name = args[0]
		elif kwargs:
			self.__dict__.update(kwargs)
		
	def addRepo(name):
		if Repo.checkInDB(name = name):
			return False
		R = Repo(name)
		R.releases = {}
		for d in DISTROS:
			for a in ARCHITECTURES:
				R.releases[d+"-"+a] = [-1, ""]
		R.releaseDate = 0
		R.disabled = False
		R._id = R.saveToDB()
		R.updateMe()	
		return R._id
		
	def updateMe(self):
		self.updateLists()
		self.updatePackages()
		self.saveToDB()
		
	def updateAll():
		for r in DB.Repos.find():
			if not r["disabled"]:
				R = Repo(**r)
				R.updateMe()
		
	def updateLists(self):
		urlStart = URL_PPA % self.name
		loc = PATH_LIST % re.sub("/","-", self.name)
				
		for distro in DISTROS:
			url = urlStart + distro + "/Release"
			name = "release-" + distro
			silentRemove(loc+name)
			r = requests.get(url)
			
			if r.status_code == 200:
				self.parseRelease(r.text, distro)
			else:
				for a in ARCHITECTURES:
					self.releases[distro + "-" + a] = [-1, "unavaliable"]
	
	def parseRelease(self, txt, distro):
		iterator = iter(txt.splitlines())
		for line in iterator:
			if line[0:4] == "Date":
				timeStamp = datetime.datetime.strptime(line[6:], "%a, %d %b %Y  %X %Z").timestamp()
				if timeStamp == self.releaseDate:
					return
				else:
					self.releaseDate = timeStamp
					break
		
		for line in iterator:	
			if line[0:6] == "SHA256":
				break
		
		arch = None
		for line in iterator:
			line = re.sub(" +", " ", line[1:]).split(" ")
			
			tmp = line[2].split("/")
			if tmp[1].find("-") < 0:
				continue
			arch = tmp[1].split("-")[1]
			
			if (arch in ["amd64","i386"]) and tmp[2] == "Packages":
				newHash = line[0]
				#if release list has no content, then release is "empty":
				if not (int(line[1]) and 1):
					self.releases[distro + "-" + arch] = [-1, "empty"]
				else:
					#Compare hashes to check has an update
					#  if different hashes enforce update (1)
					#  if no update hold information (if package hasn't yet been downloaded)
					update = int(self.releases[distro + "-" + arch][1] != newHash)
					update = update or self.releases[distro + "-" + arch][0]
					
					#Write back newHash and information on update:
					self.releases[distro + "-" + arch] = [update, newHash]

	def updatePackages(self):
		for k,v in self.releases.items():
			if v[0] != 1:
				if v[0] == 0:
					self.releases[k] = 0
				elif v[0] == -1:
					self.releases[k] = v[1]
				continue
			
			distro,arch = k.split("-")
			r = requests.get(URL_PPA%self.name + distro + "/main/binary-" + arch + "/Packages")
			
			#check hash:
			if v[1] != hashlib.sha256(r.text.encode(r.encoding)).hexdigest():
				self.releases[k] = "hashMismatch"
				continue
			
			for showpkg in r.text.split("\n\n"):
				if len(showpkg) <= 1:
					continue
				Package.listItemUpdate(showpkg, self._id, distro)

			self.releases[k] = 0
		
		self.saveToDB()
				
	def saveToDB(self):
		return DB.Repos.save(self.__dict__)

	def removeFromDB(self):
		if DB.Repos.remove(self._id)['err'] is not None:
			raise
			
	def checkInDB(**kwargs):
		return bool(DB.Repos.find_one(kwargs))
			
	def removeFromDBbyName(name):
		toFind = DB.Repos.find_one({"name": "otto-kesselgulasch/gimp"})
		DB.Repos.remove(toFind["_id"])
		
	def disableRepo(self):
		#add to disabled list
		return True

#########################################################################
#########################################################################
#########################################################################


########
# MAIN #
########

if __name__ == "__main__":
	
	dbInit(reset = True)
	r = Repo.addRepo("otto-kesselgulasch/gimp")
	providedSolver(r)
	exit(42)
	
	t = time.time()
	if(True):
		dbInit(reset = True)
		r = Repo.addRepo("libreoffice/ppa")
	
	else:
		dbInit(reset = False)
	
	Package.searchDB("libreoffice").solveDependencies(r)
	
	print("\n\n")
	p = Package.searchDB("libreoffice")
	for v_id in p.version_ids:
		for v in Version.getFromDB(v_id).depends:
			print(Version.getFromDB(v).fileLocation)
		break
		
	#Repo.updateAll()
	#Repo.addRepo("libreoffice/ppa")
	#Repo.addRepo("otto-kesselgulasch/gimp")
	
	print(time.time()-t)
