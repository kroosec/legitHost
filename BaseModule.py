import json
from output import out

class BaseModule():
    def __init__(self, interface):
	self.interface = interface
	self.loadConfig()
	out.debug("Initialized " + self.getName() + " module", 2)

    def printDescription(self):
	out.moduleUsage(self.getName() + " has no description")

    def printUsage(self):
	out.moduleUsage(self.getName() + " has no usage documentation")

    def getName(self):
	return self.__class__.__name__

    def condition(self, packet):
	raise Exception("%s module should implement condition" % self.getName())

    def action(self, packet):
	raise Exception("%s module should implement action" % self.getName())
    
    def loadConfig(self):
	conf_path = './modules/' + self.getName() + '.cfg'
	with open(conf_path) as conf_file:
	    # Open json configuration file
	    self.config = json.load(conf_file)
