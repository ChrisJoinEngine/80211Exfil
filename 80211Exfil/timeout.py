import definitions
import random
from definitions import vprint
from time import sleep
from copy import deepcopy

import logging
import network
from time import sleep

#supress the scapy IPv6 warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

lastCopy={}
problemList=[]
s=None
'''
'This is just a wrapper for the timeout protocl. Yes there is a reason I did this.
'summary is that it is related to the multiprocess terminating if I call it with timers.
'''
def timeoutWrapper():
	global s
	s = conf.L2socket(iface=definitions.ifaceName)
	#print ('hello')
	try:
		while (True):
			try:
				sleep(definitions.TIMEOUT_CONSTANT)
				timeoutProtocol()
			except ValueError:
				print 'nothing being received' #occurs if the dictionary gets deleted mid loop
			except KeyboardInterrupt:
				os._exit(0)
	finally:
		s.close()

'''
'This periodically checks the state of dictionaries and looks for lack of change.
'If an in-consturction element hasn't been changed, then it is removed.
'@param ifaceName the curent wireless interface to use
'''
def timeoutProtocol():
	global lastCopy, problemList, s

	if not definitions.inProgressDictionary:
		vprint('nothing being received')
		lastCopy={}		 
		problemList=[]    
		return

	if lastCopy:
		for currentElement in definitions.inProgressDictionary.keys():
			
			if ((currentElement in lastCopy) and (definitions.inProgressDictionary.get(currentElement)==lastCopy.get(currentElement))):
				workingSet=deepcopy(lastCopy.get(currentElement))
				size=int(workingSet.get(definitions.SIZE_KEY)) 

				if (currentElement in problemList): #nested here so if there's a mistake it's not dropped
					vprint (currentElement, 'could not be completed! Removing it.')
					vprint (len(definitions.inProgressDictionary.get(currentElement)))
					definitions.inProgressDictionary.pop(currentElement)			#remove from inprogress	
					problemList.remove(currentElement)					#remove from problem list 
					if problemList==None:
						problemList=[]
					definitions.alreadyAssembledList.append(currentElement)		
					return
			
				beforeSize=len(definitions.inProgressDictionary.get(currentElement))
				
				for i in xrange (1, size):
					problemList.append(currentElement)
					if i not in workingSet:
						requestReplay(identifier=currentElement, seqNum=i)
						sleep(.5)		#needed to prevent socket from overflowing			
				afterSize=len(definitions.inProgressDictionary.get(currentElement))
				
				if (beforeSize != afterSize):
					problemList=problemList.remove(currentElement)	
					if problemList==None:
						problemList=[]

			else: #catch to pop from the list in the event 
				if problemList and currentElement in problemList:
					problemList=problemList.remove(currentElement)	
					if problemList==None:
						problemList=[]
				
	lastCopy=deepcopy(definitions.inProgressDictionary)


'''
'Missing some data, requesting a replay
'''
def requestReplay(identifier,  seqNum):
	vprint ('replay requested for',identifier,'at sequence',seqNum)
	macToUse=random.choice(definitions.macList)

	dot11 = Dot11(type=0, subtype=8, addr1=definitions.BROADCAST_ID, addr2=macToUse) #rand mac scares me a bit because of CAM table flooding #TODO
	beacon = Dot11Beacon(cap='ESS+privacy')
	information=Dot11Elt(ID=definitions.REPLAY_ID, info=identifier, len=len(str(identifier))) #should always be a string, but you never know
	seqnumber=Dot11Elt(ID=definitions.SQNUM_ID, info=seqNum, len=len(str(seqNum)))

	pkt=RadioTap()/dot11/beacon/information/seqnumber
	s.send(pkt)