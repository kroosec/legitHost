import json

class BaseModule():

    def __init__(self):
	pass

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
