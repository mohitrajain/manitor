import time
import subprocess

# log file to create logs
logfile = 'sta.log'

def logger(log):
    print 'a'
    with open(logfile, 'r') as file:
        file.write(time.asctime() + ' :  ' + log + '\n')

def execute_out(cmd):
    Command = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    (out, err) = Command.communicate()
    if err:
        logger('Error Executing ' + cmd + ' \n' + err)
    return out

def execute(cmd):
    Command=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,shell=True)

# sets channel of the iface wireless card to ch
def setch(iface,ch):
    execute('iwconfig ' + iface + ' channel ' + str(ch))
    pass

def checkmon(iface):
    return True
    pass