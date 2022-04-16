#!/usr/bin/env python3
#
# LCL GATEWAY
# LECHACAL.COM

import configparser
import serial
import os
import sys
import requests
import datetime
import optparse


if __name__ == "__main__":


    parser = optparse.OptionParser(usage="%prog [-d] [--version]", version = "prog 1.2.0")
    parser.add_option('-d', '--debug', dest='debug', default=False, action='store_true',)
    options, remainder = parser.parse_args()

    c = configparser.ConfigParser()
    c.read("/etc/lcl-gateway.conf")

    baud = c.getint('system','baud')
    serial_port = c.get('system', 'port')
    if not os.path.exists(serial_port):
        print('Serial port %s not found' % serial_port)
        sys.exit()
    ser = serial.Serial(serial_port, baud)

    DayOfMonth = datetime.datetime.utcnow().day
    ls_fileopen = False

    while True:
        try:
            data_in = ser.readline()

            utcnow = datetime.datetime.utcnow()
            timestamp = utcnow.strftime("%s")

            if options.debug: print(data_in)

            z = data_in.decode('ascii').strip().split(' ')
            csv = ','.join(z[1:])
            for sect in c.sections():
                if sect=='emoncms' and c.getboolean(sect,'enabled'):
                #EMONCMS
                    hostname = c.get(sect, 'hostname')
                    node = c.get(sect, 'node')
                    apikey = c.get(sect, 'apikey')
                    url = "http://%s/input/post?apikey=%s&node=%s&csv=%s" % (hostname, apikey, node, csv)
                    if options.debug: print(url)
                    r = requests.post(url)
                    #s = urllib2.urlopen(url)
                    if options.debug: print(r)
                if sect=='influxdb' and c.getboolean(sect,'enabled'):
                #INFLUXDB

                    t = timestamp
                    #t = timestamp + '000000000'
                    url = c.get(sect, 'url')
                    db = c.get(sect, 'db')
                    org = c.get(sect, 'org')
                    bucket = c.get(sect, 'bucket')
                    token = c.get(sect, 'token')
                    version = c.get(sect, 'version')
                    measurement = c.get(sect, 'measurement')
                    if version =='2':
                        headers = {'Authorization': 'Token %s' % (token)}
                        params = {"org":org,"bucket": bucket,"precision":"s"}
                    else:
                        headers = {}
                        params = {'db':db, 'precision':'s'}

                    i = 0
                    payload = ""
                    for zz in z[1:]:
                        i += 1
                        if zz!="":
                            payload += "%s,channel=%02d value=%s %s\n" % (measurement, i, zz,t)
                            #payload = "rpict3t1,channel=01 value=50.2 %s\nrpict3t1,channel=02 value=156.2 %s\n" % (t,t)
                    if options.debug: print(payload)
                    if version=='2':
                        r = requests.post(url, headers=headers, params=params, data=payload)
                    else:
                        r = requests.post(url, params=params, data=payload)
                    if options.debug: print(r.text)

                if sect=='localsave' and c.getboolean(sect,'enabled'):
                # LOCALSAVE
                    ls_dir = c.get(sect, 'directory')
                    filename = ls_dir+'/'+timestamp+'.csv'
                    if not ls_fileopen:
                        f = open(filename,'w')
                        ls_fileopen = True
                    if DayOfMonth != utcnow.day:
                        DayOfMonth = utcnow.day
                        if ls_fileopen: f.close()
                        f = open(filename,'w')
                        ls_fileopen = True

                    f.write(timestamp+','+csv+'\n')


        except KeyboardInterrupt:
            if ls_fileopen: f.close()
            print("Terminating.")
            break
