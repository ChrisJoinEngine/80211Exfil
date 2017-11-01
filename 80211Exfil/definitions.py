from multiprocessing import Process, Manager, Pool
from copy import deepcopy
from sys import getsizeof
from time import sleep
import logging
#supress the scapy IPv6 warning
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

#OS identification strings and miscellaneous
UNIQ_ID_LENGTH=10

#Identification codes and TTL
MAX_INFO_SIZE=245
MAX_SIZE_BYTES=500*10000 #500mb
SQNUM_ID=137
TOTAL_PIECE_ID=155
UNIQ_ID=156
DATA_ID=106
TTL_ID=109
REPLAY_ID=107
NAME_ID=108

OPTIMIZE_DELAY=0.05
NAME_MAX_LENGTH=2
NAME_IDENTIFIER_LENGTH=6

#src mac is randomized per payload. DEPRECATED..had some issues, hardcoded again
BROADCAST_ID='ff:ff:ff:ff:ff:ff'


#OS identification strings and miscellaneous
EXFIL_BASE='EXFIL_'
SCRIPT_KEYWORD='execute'
SCRIPT_ALTERNATE_KEYWORD='store'
SCRIPT_DELETE_KEYWORD='del'
PERCENT_COUNT_INTERVAL=100

#in seconds. Lowering this too low will trigger way early because of thread pool limits and collision. Don't go below 10
TIMEOUT_CONSTANT=10
MAC_LIST_COUNT=10

#keyword to be used for size identifier in dictionaries
SIZE_KEY='size'

#folder names
SCRIPTS_PATH='scripts'
OUTPUT_PATH='output'
ARCHIVE_PATH='archive'



#how often to process the output folder
OUTPUT_PROCESS_INTERVAL=3 

#variables that may be set with flags, however you may adjust their default values here
archiveOutput=False 
verbose=False
memory=True
singleFile=None
packetTTL=2
ifaceName='mon0' #could be useful to adjust per machine, saves you a flag on listening nodes
transmitCount=1
writeToDisk=True
noProcess=False
memorySize=3

memoryTestSet={}

#until I find a better place to put this, messy messy crap that should be reworked at some point
manager=Manager()
macList=manager.list()
alreadyAssembledList=manager.list()

inProgressDictionary=manager.dict()
memorySet=manager.dict()#collections.OrderedDict()

for i in xrange (0, MAC_LIST_COUNT):
	value=str(RandMAC())
	macList.append(value)

#verbose mode printT
def vprint(*args):
	if verbose:
		for arg in args:
			print arg,
		print ''


'''
'This defines the base packet creation. It takes in data and appends it to a beacon frame
'really, any frames can be used, I chose beacons for now
'@param encodedData the core data to embed in a packet
'@param seqNum the sequence number of this packet when reassembly is done
'@param totalPieceCount the number of total pieces that are within a packet sequence
'@param timeToLive how many times this packet should be rebroadcast by receivers (how far it spreads)'
'''
def basePacket(encodedData, seqNum, totalPieceCount, timeToLive, srcMAC, packetID, transmitName):
	
	if (len(str(transmitName>NAME_MAX_LENGTH))):
		transmitName=transmitName[:NAME_MAX_LENGTH]

	dot11 = Dot11(type=0, subtype=8, addr1=BROADCAST_ID, addr2=srcMAC)
	beacon = Dot11Beacon(cap='ESS+privacy')
	information=Dot11Elt(ID=DATA_ID, info=encodedData, len=len(encodedData))
	seqNum=Dot11Elt(ID=SQNUM_ID, info=seqNum, len=len(str(seqNum)))
	totalPieces=Dot11Elt(ID=TOTAL_PIECE_ID, info=totalPieceCount, len=len(str(totalPieceCount)))
	uniqueIdentifier=Dot11Elt(ID=UNIQ_ID, info=packetID, len=len(packetID))
	ttlCounter=Dot11Elt(ID=TTL_ID, info=timeToLive, len=len(str(timeToLive)))
	name=Dot11Elt(ID=NAME_ID, info=transmitName, len=len(str(transmitName)))

	pkt=RadioTap()/dot11/beacon/information/seqNum/totalPieces/uniqueIdentifier/ttlCounter/name
	return pkt

'''
'Some delay actually boosts reception performance
'''
def optimizedDelay():
	sleep(OPTIMIZE_DELAY)

'''
'Updates memory (or should) so that this node may better respond to replay requests
'''
def updateMemory(reconstructedData, uniqueIdentifier):
	if (memory):
		while (len(memorySet)>=memorySize):
			memorySet.popitem() #order is not guaranteed
		memorySet[uniqueIdentifier]=deepcopy(reconstructedData)
		#print (getsizeof(memorySet), "MEMORY SIZE CURRENTLY") #TODO implement memory control
	else:
		return
