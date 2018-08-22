#Section 0: Requirements
try:
    import subprocess
    import json
    import argparse
except:
    print("[!] Failed to import the dependencies... " +\
            "Please make sure to install all of the requirements " +\
            "and try again.")
    raise SystemExit

parser = argparse.ArgumentParser(usage="packetSniffer.py [options]")
parser.add_argument("--debug", action="store_true", help="turn debug mode on")

args = parser.parse_args()
debugMode = args.debug

def debug(msg=""):
    if debugMode:
        print("[DEBUG] " + msg)

debug("Welcome to Setup of DigitalB_Sniffer")

#Section 1: Data Processing from Server
debug("[I] Grabbing Customer Data From Server")
try:
    #TODO
    #Grab from server
    #Write to serverInfo.json
    #Check documentation for specific way to write data
    str = 1 + "hello" #Causes try block to fail and except loop to run
except:
    debug("[I] Server information not read")
    serverFile = open("serverInfo.json","r")
    serverInfo = json.load(serverFile)
    serverFile.close()

#Section 2: Updating Cron Jobs
debug("[I] Setting Wake Time: Daytime Job")
wakeHour = (int(serverInfo["wakeTime"].split(":")[0]) + serverInfo["tzOffset"]) % 24
wakeMinute = serverInfo["wakeTime"].split(":")[1]
debug(str(wakeHour)+" " + wakeMinute))
time.sleep(60)

debug("[I] Updating Cron Job")
try:
    subprocess.call("touch /etc/cron.d/digitalB_daytime",shell=True)
except:
    debug("[I] Couldn't call processes to remove cronjob")
daytimeJob = open("/etc/cron.d/digitalB_daytime","w")
daytimeCommand = "{} {} * * * root cd /root/DigitalB_Sniffer && /usr/bin/python3 daytimeSniffer.py".format(wakeMinute, wakeHour)
daytimeJob.write(daytimeCommand)
daytimeJob.close()

debug("[I] Setting Wake Time: Nighttime Job")
wakeHour = (int(serverInfo["sleepTime"].split(":")[0] + 1) + serverInfo["tzOffset"]) % 24
wakeMinute = serverInfo["sleepTime"].split(":")[1]
debug(str(wakeHour)+" " + wakeMinute)
time.sleep(60)

debug("[I] Updating Cron Job")
try:
    subprocess.call("touch /etc/cron.d/digitalB_nighttime",shell=True)
except:
    debug("[I] Couldn't call processes to remove cronjob")
nighttimeJob = open("/etc/cron.d/digitalB_nighttime","w")
nighttimeCommand = "{} {} * * * root cd /root/DigitalB_Sniffer && /usr/bin/python3 nighttimeSniffer.py".format(wakeMinute, wakeHour)
nighttimeJob.write(nighttimeCommand)
nighttimeJob.close()
