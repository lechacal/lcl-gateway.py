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
import argparse


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='LeChacal Gateway')
    parser.add_argument('-c', '--config', dest='config', default='/etc/lcl-gateway.conf', action='store')
    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true')
    args = parser.parse_args()

    if not os.access(args.config, os.R_OK):
        print(f'Config file not found: {args.config}')
        sys.exit(1)

    c = configparser.ConfigParser()
    c.read(args.config)

    baud = c.getint('system','baud')
    serial_port = c.get('system', 'port')
    if not os.path.exists(serial_port):
        print('Serial port %s not found' % serial_port)
        sys.exit(1)
    ser = serial.Serial(serial_port, baud)

    DayOfMonth = datetime.datetime.utcnow().day
    ls_fileopen = False

    while True:
        try:
            data_in = ser.readline()

            utcnow = datetime.datetime.utcnow()
            timestamp = utcnow.strftime("%s")

            if args.debug: print(data_in)

            z = data_in.decode('ascii').strip().split(' ')
            csv = ','.join(z[1:])
            for sect in c.sections():
                if sect=='emoncms' and c.getboolean(sect,'enabled'):
                #EMONCMS
                    hostname = c.get(sect, 'hostname')
                    node = c.get(sect, 'node')
                    apikey = c.get(sect, 'apikey')
                    url = "http://%s/input/post?apikey=%s&node=%s&csv=%s" % (hostname, apikey, node, csv)
                    if args.debug: print(url)
                    r = requests.post(url)
                    #s = urllib2.urlopen(url)
                    if args.debug: print(r)

                if sect=='influxdb' and c.getboolean(sect,'enabled'):
                #INFLUXDB
                    t = timestamp
                    #t = timestamp + '000000000'
                    version = c.get(sect, 'version')
                    url = c.get(sect, 'url')
                    measurement = c.get(sect, 'measurement')
                    if version =='2':
                        org = c.get(sect, 'org')
                        bucket = c.get(sect, 'bucket')
                        token = c.get(sect, 'token')
                        headers = {'Authorization': 'Token %s' % (token)}
                        params = {"org":org,"bucket": bucket,"precision":"s"}
                    else:
                        db = c.get(sect, 'db')
                        headers = {}
                        params = {'db':db, 'precision':'s'}

                    i = 0
                    payload = ""
                    for zz in z[1:]:
                        i += 1
                        if zz!="":
                            payload += "%s,channel=%02d value=%s %s\n" % (measurement, i, zz,t)
                    if args.debug: print(payload)
                    if version=='2':
                        r = requests.post(url, headers=headers, params=params, data=payload)
                    else:
                        r = requests.post(url, params=params, data=payload)
                    if args.debug: print(r.text)

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
