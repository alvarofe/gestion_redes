class server(object):
        def __init__(self, hostname, port,active=False):
                self.active = active
                self.hostname = hostname
                self.port = port
                self.connection_handle = ""

        def details(self):
                print "Host: %s" % (self.hostname)
                print "Active: %r\n" % self.active