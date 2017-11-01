'''
'@author JoinEngine
'''
import os
import platform
import subprocess
import time
import sys
import binascii
import math
import logging
import string
import definitions
from definitions import vprint, basePacket,  updateMemory, optimizedDelay
import random
import network
from time import sleep
from optparse import OptionParser

#supress the scapy IPv6 warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

'''
'Read in a binary file and return it as a hex string
'@param file the file to return as a hex encoded string'
'''
def getFileAsHex(file):
	with open(file, 'rb') as f:
		content=f.read()
	return (binascii.hexlify(content))

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
	outputFile = open(outputName, 'wb')
	binaryToRestore=getHexAsBinary(hexString)
	newFileByteArray = bytearray(binaryToRestore)
	outputFile.write(newFileByteArray)

'''
'This defines the base packet creation. It takes in data and appends it to a beacon frame
'really, any frames can be used, I chose beacons for now
'@param encodedData the core data to embed in a packet
'@param seqNum the sequence number of this packet when reassembly is done
'@param totalPieceCount the number of total pieces that are within a packet sequence
'@param timeToLive how many times this packet should be rebroadcast by receivers (how far it spreads)'
'''
def basePacket(encodedData, seqNum, totalPieceCount, timeToLive, srcMAC, packetID, transmitName):
	
	if (len(str(transmitName>definitions.NAME_MAX_LENGTH))):
		transmitName=transmitName[:definitions.NAME_MAX_LENGTH]

	dot11 = Dot11(type=0, subtype=8, addr1=definitions.BROADCAST_ID, addr2=srcMAC)
	beacon = Dot11Beacon(cap='ESS+privacy')
	information=Dot11Elt(ID=definitions.DATA_ID, info=encodedData, len=len(encodedData))
	seqNum=Dot11Elt(ID=definitions.SQNUM_ID, info=seqNum, len=len(str(seqNum)))
	totalPieces=Dot11Elt(ID=definitions.TOTAL_PIECE_ID, info=totalPieceCount, len=len(str(totalPieceCount)))
	uniqueIdentifier=Dot11Elt(ID=definitions.UNIQ_ID, info=packetID, len=len(packetID))
	ttlCounter=Dot11Elt(ID=definitions.TTL_ID, info=timeToLive, len=len(str(timeToLive)))
	name=Dot11Elt(ID=definitions.NAME_ID, info=transmitName, len=len(str(transmitName)))

	pkt=RadioTap()/dot11/beacon/information/seqNum/totalPieces/uniqueIdentifier/ttlCounter/name
	return pkt

'''
'This is the method that should be called. It splits a file into smaller bits
'of data and sends them out one at a time. If the file is small enough, it is 
'just sent
'@param forExfil the data that should be exfiltrated
'''
def createAndSendPacket(forExfil, TTL, srcMAC, packetID, transmitName):
	receivedDataDictionary={}

	fileLength=len(forExfil)

	totalCount=math.ceil(float(fileLength)/float(definitions.MAX_INFO_SIZE))
	totalCount=int(totalCount)
	
	sequenceNum=1

	s = conf.L2socket(iface=definitions.ifaceName)

	try:
		#Split it into packet sizes of the max info size and ship them out
		for i in xrange(0,fileLength, definitions.MAX_INFO_SIZE):
			endpoint=i+definitions.MAX_INFO_SIZE
			pkt=basePacket(encodedData=forExfil[i:endpoint], seqNum=sequenceNum, totalPieceCount=totalCount, timeToLive=TTL, srcMAC=srcMAC, packetID=packetID, transmitName=transmitName)
			s.send(pkt)
			optimizedDelay()
			
			receivedDataDictionary[int(sequenceNum)]=forExfil[i:endpoint]
			receivedDataDictionary[definitions.SIZE_KEY]=int(totalCount)
			sequenceNum=sequenceNum+1
			if (definitions.verbose): #possibly slightly faster to do this check first if verbose=false
				if (sequenceNum%definitions.PERCENT_COUNT_INTERVAL==0):
					vprint('transmitting', transmitName, ":", '{0:.1f}%'.format((float(sequenceNum)/float(totalCount))*100))
		
		updateMemory(reconstructedData=receivedDataDictionary, uniqueIdentifier=packetID)		

	finally:
		s.close()

	print ("sent %d packets" %totalCount)


'''
'This is the main function, the goal here is to read in a packet
'and distribute it in a way that can then be recovered
'@filename the file to transmit
'@transmitCount how many times the file should be transmited
'@packetTTL how many bounces a packet should make
'''
def transmit(filename):
	transmitName=os.path.basename(filename)

	dataToExfil=getFileAsHex(filename)
	random_ID="".join(random.choice(string.ascii_letters+string.digits) for _ in range(definitions.UNIQ_ID_LENGTH)) 
	definitions.alreadyAssembledList.append(random_ID)
	#print (definitions.alreadyAssembledList)
	#alreadyAssembled list vs in progress dictionary is the problem
		
	print 'transmitting your file %d times' % definitions.transmitCount
	for i in xrange(0,definitions.transmitCount):	
		createAndSendPacket(forExfil=dataToExfil, TTL=definitions.packetTTL, srcMAC=random.choice(definitions.macList), packetID=random_ID, transmitName=transmitName) #okay, so this should work for random macs unique to each client which makes ignoring own packets easier
	print ('transmission complete')