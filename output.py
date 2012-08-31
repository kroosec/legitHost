class legitOutput():
    def __init__(self, level=None):
	self.level = level or 0

    def setLevel(self, level):
	self.level = level

    def debug(self, message, level):
	if self.level >= level:
	    print "Debug: " + message

    def error(self, message):
	print "Error: " + message

    def verbose(self, message):
	print message

    def usage(self):
	print "./legithost.py -i <interface>"

out = legitOutput()
