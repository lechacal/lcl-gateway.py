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

def post_to_url(session, *args, **kwargs):
    try:
        r = session.post(*args, **kwargs, timeout=HTTP_TIMEOUT)
        logging.debug("Result: %d %s", r.status_code, r.reason)
        if not r.ok:
            logging.warning(r.text)
    except requests.exceptions.ConnectionError as e:
        if e.args[0].args[0] == 'Connection aborted.':
            # emoncms.org doesn't like idle persistent connections
            # and aborts them from time to time
            logging.debug("Connection aborted - reconnecting")
            r = session.post(*args, **kwargs, timeout=HTTP_TIMEOUT)
            logging.debug("Result: %d %s", r.status_code, r.reason)
            if not r.ok:
                logging.warning(r.text)
        else:
            logging.warning("ConnectionError: %s", e)

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

    # Session provides a persistent connection support that
    # significantly speeds up data submission to the backends
    session = requests.Session()

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

            if 'emoncms' in c.sections() and c.getboolean('emoncms', 'enabled'):
            #EMONCMS
                url = c.get('emoncms', 'url')
                node = c.get('emoncms', 'node')
                apikey = c.get('emoncms', 'apikey')

                data_out = { key: data_in[key] for key in data_in if key in channels }

                payload = {
                    "apikey": apikey,
                    "node": node,
                    "fulljson": json.dumps(data_out, separators=(',', ':')),
                }

                logging.debug("URL: %s", url)
                logging.debug("Payload: %s", payload)

                post_to_url(session, url, data=payload)

            if 'influxdb' in c.sections() and c.getboolean('influxdb', 'enabled'):
            #INFLUXDB
                version = c.get('influxdb', 'version')
                url = c.get('influxdb', 'url')
                measurement = c.get('influxdb', 'measurement')
                if version =='2':
                    org = c.get('influxdb', 'org')
                    bucket = c.get('influxdb', 'bucket')
                    token = c.get('influxdb', 'token')
                    headers = {'Authorization': 'Token %s' % (token)}
                    params = {"org":org,"bucket": bucket,"precision":"s"}
                else:
                    db = c.get('influxdb', 'db')
                    headers = {}
                    params = {'db':db, 'precision':'s'}

                logging.debug("URL: %s", url)
                payload = []
                for channel in channels:
                    payload.append("%s,channel=%s value=%s %s" % (measurement, channel, data_in[channel], timestamp))
                logging.debug("Payload: %s", payload)
                payload_str = "\n".join(payload)

                post_to_url(session, url, headers=headers, params=params, data=payload_str)

            if 'localsave' in c.sections() and c.getboolean('localsave', 'enabled'):
            # LOCALSAVE
                ls_dir = c.get('localsave', 'directory')
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
