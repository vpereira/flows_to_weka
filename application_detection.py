from scapy.all import *
#from named_tuple import namedtuple
#enum :)
LOW_CONFIDENCE, MEDIUM_CONFIDENCE, HIGH_CONFIDENCE = range(3)

class ApplicationDetection(object):
    def __init__(self):
        self.protocols = [self.scapy_detected,self.http,self.smtp,self.ftp,self.ssh,self.telnet,self.imap,self.pop3]
        self.matched_protocols = []
        self.proto = "TCP"
        self.payload = None
    """
        supported apps
        return a tuple (protocol-name, confidence-level)
        for now its just returning the first match
    """
    def detect(self,payload):
       self.payload = payload
       for f in self.protocols:
            if f():
                return str(f.__name__)
       return "unknown"

       def scapy_detected(self):
        return False

    def http(self):
        if self.payload[0:4] in ["GET ", "POST", "HEAD"]:
            return (True,"http")
        return False

    def telnet(self):
        if self.payload[0:4].encode('hex')[0:2] == 'ff':
            hex_payload = self.payload[0:4].encode('hex')
            if hex_payload[2:4] in ('fb','fc','fd','fe'):
                #default command
                next_cmd = 3
                if len(self.payload) > 3 and self.payload[0:4].encode('hex')[0+next_cmd*2:2+next_cmd*2] == 'ff':
                    return True
        return False
    def ssh(self):
        if self.payload[0:4] in ["SSH-"]:
            return True
        return False
    def ftp(self):
        if self.payload[0:4] in ["220 ","220-","USER"]:
            return True
        return False
    def smtp(self):
        if self.payload[0:4] in ["220 ", "220-", "HELO", "EHLO",".\n\n"]:
            if self.sport != 21 and self.dport != 21:
                return True
        return False
    def imap(self):
        if self.payload[0:4] in ["* OK"]:
            return True
        return False
    def pop3(self):
        if self.payload[0:4] in ["USER","CAPA","AUTH","+OK "]:
            if self.sport not in (21,194,6667) and self.dport not in (21,194,6667):
                return True
        return False

               
