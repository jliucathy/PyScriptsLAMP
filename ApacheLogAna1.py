import re
import datetime
class LogRe:
    def __init__(self, filename):
        self.logFile = open(filename,'r')
        self.logRe = re.compile(r'(?P<origin>\d+\.\d+\.\d+\.\d+) '+ r'(?P<identd>-|\w+) (?P<auth>-|\w+) '
                     +r'\[(?P<date>[^\[\]:]+):(?P<time>\d+:\d+:\d+) (?P<tz>[\-\+]?\d\d\d\d)\] '
                     +r'"(-|((?P<method>\w+) (?P<path>[\S]+) (?P<protocol>[^"]+))|[^"]+)" (?P<status>\d+) (?P<bytes>-|\d+)'
                     +r'( (?P<referrer>-|"[^"]*")( (?P<client>-|"[^"]*")( (?P<cookie>-|"[^"]*"))?)?)?\s*\Z')

class IP_Analy(LogRe):
    def __init__(self, filename):
        LogRe.__init__(self, filename)

    def get_ipdict(self):
        IP={}
        for i in self.logFile:
            m = self.logRe.search(i)
            IP[m.group('origin')] = IP.get(m.group('origin'), 0) + 1
        IP=sorted(IP.iteritems(), key=lambda c:c[1], reverse=True)
        return IP

    def get_errorip(self,status,sss):
        for i in self.logFile:
            m = self.logRe.search(i)
            if m.groupdict()[status] == sss :
                print i

    def retri_at_time(self, start, end):
        print datetime.datetime.now()
        m_format = '%Y%m%d%H%M%S'
        time_format = '%d/%b/%Y:%X'
        start = datetime.datetime.strptime(start,m_format)
        end = datetime.datetime.strptime(end,m_format)
        clickNum = 0
        for i in self.logFile:
            m = self.logRe.search(i)
            p = m.group('date') +':'+ m.group('time')
            ptime = datetime.datetime.strptime(p,time_format)
            if ptime >= start and ptime <= end:
                clickNum+=1

        print clickNum
        print datetime.datetime.now()