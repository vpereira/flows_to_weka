from scapy.all import *
#from named_tuple import namedtuple
#enum :)
LOW_CONFIDENCE, MEDIUM_CONFIDENCE, HIGH_CONFIDENCE = range(3)

class ApplicationDetection(object):
    def __init__(self):
        self.protocols = [self.scapy_detected,self.http,self.smtp,self.ftp,self.ssh,self.telnet,self.imap,self.pop3]
        self.matched_protocols = []
        self.payload = None
    """
        supported apps
        return a tuple (protocol-name, confidence-level)
        for now its just returning the first match
    """
    def detect(self,network_flow):
       self.network_flow = network_flow
       self.payload = network_flow.payload.lstrip("\x00")[0:4]
       for f in self.protocols:
           if f(): 
               return str(f.__name__)
       return "unknown"

    def scapy_detected(self):
        return False

    def http(self):
        if self.payload in ["GET ", "POST", "HEAD","HTTP","CONN"]: #XXX: add more methods
            return True
        return False

    def telnet(self):
        if self.payload.encode('hex')[0:2] == 'ff':
            hex_payload = self.payload.encode('hex')
            if hex_payload[2:4] in ('fb','fc','fd','fe'):
                #default command
                next_cmd = 3
                if len(self.payload) > 3 and self.payload.encode('hex')[0+next_cmd*2:2+next_cmd*2] == 'ff':
                    return True
        return False
    def ssh(self):
        if self.payload in ["SSH-"]:
            return True
        return False
    def ftp(self):
        if self.payload in ["220 ","220-","USER"]:
            return True
        return False
    def smtp(self):
        if self.payload in ["220 ", "220-", "HELO", "EHLO",".\n\n"]:
            if self.network_flow.sport != 21 and self.network_flow.dport != 21:
                return True
        return False
    def imap(self):
        if self.payload in ["* OK"]:
            return True
        return False
    def pop3(self):
        if self.payload in ["USER","CAPA","AUTH","+OK "]:
            if self.network_flow.sport not in (21,194,6667) and self.network_flow.dport not in (21,194,6667):
                return True
        return False

