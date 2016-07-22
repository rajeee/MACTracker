import subprocess
import time
import re
import json
import datetime
import smtplib

#nmap result
nmap = """Starting Nmap 6.40 ( http://nmap.org ) at 2016-07-19 23:44 EDT
Nmap scan report for 192.168.0.1
Host is up (0.075s latency).
MAC Address: A4:2B:8C:2D:6E:9B (Unknown)
Nmap scan report for Hewlett-Packard (192.168.0.2)
Host is up (0.19s latency).
MAC Address: A8:E3:B5:FD:85:97 (Hewlett-Packard Company)
Nmap scan report for 192.168.0.3
Host is up (0.16s latency).
MAC Address: 50:C8:E5:BC:55:FA (Unknown)
Nmap scan report for 192.168.0.4"""

with open('email_info.txt','r') as f:
    account = json.load(f)

smtpObj = None

def email_login():
    global smtpObj
    smtpObj = smtplib.SMTP('smtp.gmail.com', 587)
    smtpObj.starttls()
    smtpObj.login(account['username'],account['password'])

email_login()

email_from = account['from']
email_to = account['to']
email_subject = account['subject']

def sendEmail(text):
    email_text = 'From: '+email_from+'\nTo: '+email_to+'\nSubject: '+email_subject+'\n\n'+text
    print 'sending email with text:\n'+email_text
    try:
        smtpObj.sendmail(email_from,email_to,email_text)
    except smtplib.SMTPServerDisconnected as error:
        print "Email timed out. Relogin"
        email_login()
        smtpObj.sendmail(email_from,email_to,email_text)

def saveRecord(macaddress,record):
    file_name = macaddress.replace(':','_')
    dt = str(datetime.datetime.now())
    row = [dt]+record
    with open(file_name,'a') as f:
        f.write(','.join([str(x) for x in row])+'\n')

status_knowledge_file = 'knowledge.txt'
owner_knowledge_file = 'owner.txt'
email_ignored_macs = 'ignored.txt'


while(True):

    try:
        with open(email_ignored_macs, 'r') as f:
            ignored_macs = json.load(f)
    except IOError:
        ignored_macs = list()

    try:
        with open(status_knowledge_file,'r') as f:
            oldknowledge = json.load(f)
    except IOError:
        oldknowledge = dict()
    try:
        with open(owner_knowledge_file, 'r') as f:
            ownerknowledge = json.load(f)
    except IOError:
        ownerknowledge = dict()



    new_knowledge = dict()

    for i in range(2): #Run two iteration of nmap to determine online devices
        print "Running nmap Iteration: "+str(i)
        try:
            nmap = subprocess.check_output('sudo nmap -sP -PE -PA21,23,80,3389 192.168.10.1/24',shell=True)
        except subprocess.CalledProcessError as e:
            print 'nmam error'
            print str(e)
            time.sleep(60*5)
            continue

        print nmap
        pattern = "Nmap scan report for (.*)\nHost is up \(([0-9.]*)s latency\).\nMAC Address: ([0-9A-F:.]*) \((.*)\)\n"
        matches = re.findall(pattern,nmap)

        for match in matches:
            # match = ('Hostname ('192.168.0.1'), '0.075', 'A4:2B:8C:2D:6E:0B', 'Unknown')
            host_and_ip = re.findall(r'(.*) \(([0-9.]*)\)',match[0])
            if match[2] in ownerknowledge:
                owner = ownerknowledge[match[2]]
            else:
                owner = 'Unknown Owner'

            if len(host_and_ip) > 0:
                new_knowledge[match[2]] = list(((1,owner,) + host_and_ip[0] + match[1:2]+match[3:]))
            else:
                new_knowledge[match[2]] = list(((1,owner,) + ('Unknown Hostname',) + match[0:2]+match[3:]))

        print new_knowledge
        if i==0:
            print "Waiting 1 minute before next scan"
            time.sleep(60)

    email_lines = ""
    #match = (1,'Unkonwn Owner','Unknown Hostname', '192.168.0.1', '0.075', 'A4:2B:8C:2D:6E:0B', 'Unknown')
    for macaddress, knowledge in oldknowledge.items():
        if macaddress == 'Time':
            continue
        status = knowledge[0]
        if status == 0 and macaddress in new_knowledge: #this macaddress is online just now
            oldknowledge[macaddress] = new_knowledge[macaddress]
            if not macaddress in ignored_macs:
                email_lines += 'Came Home: '+macaddress +' ' + str(new_knowledge[macaddress])+'\n'
            saveRecord(macaddress,new_knowledge[macaddress])
        if status == 1 and macaddress not in new_knowledge: #this macaddress is offline just now
            ip = oldknowledge[macaddress][3] #Get its previously known IP address
            try:
                ping_response = subprocess.check_output('ping -c 4 '+ip,shell=True)
            except subprocess.CalledProcessError as e:
                print e.output
                ping_response = e.output
            ping_result = re.findall('([0-9]) received',ping_response)
            if ping_result[0] == '0': #Really offline
                oldknowledge[macaddress][0] = 0
                if not macaddress in ignored_macs:
                    email_lines += 'Left Home: ' + macaddress + ' ' + str(oldknowledge[macaddress])+'\n'
                saveRecord(macaddress,oldknowledge[macaddress])
            else:
                #Device is actually present. Ignore that it is gone in nmap, just a nmap glitch
                print 'Ping Alive : ' + macaddress + ': ' + str(oldknowledge[macaddress])

    for macaddress in new_knowledge.keys():
        if macaddress not in oldknowledge:
            #Got brand new device
            oldknowledge[macaddress] = new_knowledge[macaddress]
            if not macaddress in ignored_macs:
                email_lines += 'New MAC Home: ' + macaddress + ' ' + str(new_knowledge[macaddress])+'\n'
            saveRecord(macaddress, new_knowledge[macaddress])

    if email_lines != '':
        sendEmail(email_lines)

    oldknowledge['Time'] = str(datetime.datetime.now())
    with open(status_knowledge_file, 'w') as f:
        json.dump(oldknowledge,f)

    time.sleep(60*5)
