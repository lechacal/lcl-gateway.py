#!/usr/bin/env python3
#
# LCL GATEWAY
# LECHACAL.COM

import os
import sys
import logging
import datetime
import argparse
import configparser

import serial
import requests


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)

    parser = argparse.ArgumentParser(description='LeChacal Gateway')
    parser.add_argument('-c', '--config', dest='config', default='/etc/lcl-gateway.conf', action='store')
    parser.add_argument('-d', '--debug', dest='debug', default=False, action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.access(args.config, os.R_OK):
        logging.error('Config file not found: %s', args.config)
        sys.exit(1)

    c = configparser.ConfigParser()
    c.read(args.config)

    baud = c.getint('system','baud')
    serial_port = c.get('system', 'port')
    if not os.path.exists(serial_port):
        logging.error('Serial port %s not found', serial_port)
        sys.exit(1)
    ser = serial.Serial(serial_port, baud)
    logging.info('Reading data from %s', serial_port)

    DayOfMonth = datetime.datetime.utcnow().day
    ls_fileopen = False

    while True:
        try:
            data_in = ser.readline()
            logging.debug(data_in)

            utcnow = datetime.datetime.utcnow()
            timestamp = utcnow.strftime("%s")

            z = data_in.decode('ascii').strip().split(' ')
            csv = ','.join(z[1:])

            for sect in c.sections():
                if sect=='emoncms' and c.getboolean(sect,'enabled'):
                #EMONCMS
                    url = c.get(sect, 'url')
                    node = c.get(sect, 'node')
                    apikey = c.get(sect, 'apikey')
                    url = "%s?apikey=%s&node=%s&csv=%s" % (url, apikey, node, csv)
                    logging.debug(url)
                    r = requests.post(url)
                    logging.debug(r)

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
                    logging.debug(payload)
                    if version=='2':
                        r = requests.post(url, headers=headers, params=params, data=payload)
                    else:
                        r = requests.post(url, params=params, data=payload)
                    logging.debug(r.text)

                if sect=='localsave' and c.getboolean(sect,'enabled'):
                # LOCALSAVE
                    ls_dir = c.get(sect, 'directory')
                    filename = ls_dir+'/'+timestamp+'.csv'
                    if not ls_fileopen:
                        f = open(filename, 'wt')
                        ls_fileopen = True
                    if DayOfMonth != utcnow.day:
                        DayOfMonth = utcnow.day
                        if ls_fileopen:
                            f.close()
                        f = open(filename, 'wt')
                        ls_fileopen = True

                    f.write(timestamp+','+csv+'\n')


        except KeyboardInterrupt:
            if ls_fileopen:
                f.close()
            logging.info("Terminating.")
            break
