#!/usr/bin/env python3
#
# LCL GATEWAY
# LECHACAL.COM

import os
import sys
import re
import json
import logging
import datetime
import argparse
import configparser

import serial
import requests

HTTP_TIMEOUT=5

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

    channel_names = c.get('system', 'channel_names')
    channel_names = re.sub('\s', '', channel_names)
    channel_names = channel_names.split(',')
    logging.debug("Channel names: %s", channel_names)

    channels = c.get('system', 'channels', fallback='*')
    if channels == '*':
        channels = channel_names.keys()
    else:
        channels = re.sub('\s', '', channels)
        channels = channels.split(',')
    logging.debug("Channels: %s", channels)

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
            # Read one line from the source
            data_in = ser.readline()
            if not data_in:
                logging.warning("End of file reached: %s", serial_port)
                break
            logging.debug("DataIn: %s", data_in)

            # Parse the data - create a "dict" from channel names and the values
            data_in = data_in.decode('ascii').strip().split(' ')
            data_in = map(lambda x: float(x), data_in)
            data_in = dict(zip(channel_names, data_in))

            utcnow = datetime.datetime.utcnow()
            timestamp = utcnow.strftime("%s")

            for sect in c.sections():
                if sect=='emoncms' and c.getboolean(sect,'enabled'):
                #EMONCMS
                    url = c.get(sect, 'url')
                    node = c.get(sect, 'node')
                    apikey = c.get(sect, 'apikey')

                    data_out = { key: data_in[key] for key in data_in if key in channels }

                    payload = {
                        "apikey": apikey,
                        "node": node,
                        "fulljson": json.dumps(data_out, separators=(',', ':')),
                    }

                    logging.debug("URL: %s", url)
                    logging.debug("Payload: %s", payload)

                    r = requests.post(url, params=payload, timeout=HTTP_TIMEOUT)
                    logging.debug("Result: %d %s", r.status_code, r.reason)
                    if not r.ok:
                        logging.warning(r.text)

                if sect=='influxdb' and c.getboolean(sect,'enabled'):
                #INFLUXDB
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

                    payload = []
                    for channel in channels:
                        payload.append("%s,channel=%s value=%s %s" % (measurement, channel, data_in[channel], timestamp))
                    logging.debug(payload)
                    payload_str = "\n".join(payload)

                    if version=='2':
                        r = requests.post(url, headers=headers, params=params, data=payload_str, timeout=HTTP_TIMEOUT)
                    else:
                        r = requests.post(url, params=params, data=payload_str, timeout=HTTP_TIMEOUT)
                    logging.debug("Result: %d %s", r.status_code, r.reason)
                    if not r.ok:
                        logging.warning(r.text)

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

            logging.debug("---")


        except KeyboardInterrupt:
            if ls_fileopen:
                f.close()
            logging.info("Terminating.")
            break

        except requests.exceptions.ConnectionError as e:
            logging.warning(e)
