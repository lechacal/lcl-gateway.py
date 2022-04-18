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
        connection_aborted = False
        try:
            connection_aborted = e.args[0].args[0] == 'Connection aborted.'
        except:
            pass
        if connection_aborted:
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
    channel_names = re.sub('\\s', '', channel_names)
    channel_names = channel_names.split(',')
    logging.debug("Channel names: %s", channel_names)

    channels = c.get('system', 'channels', fallback='*')
    if channels == '*':
        channels = channel_names.keys()
    else:
        channels = re.sub('\\s', '', channels)
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

    # Rotate 'localsave' files every day
    ls_day = None

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
            data_in = map(float, data_in)
            data_in = dict(zip(channel_names, data_in))

            # Filter data by the requested channels
            data_out = { key: data_in[key] for key in data_in if key in channels }

            utcnow = datetime.datetime.utcnow()
            timestamp = utcnow.strftime("%s")

            if 'emoncms' in c.sections() and c.getboolean('emoncms', 'enabled'):
            #EMONCMS
                url = c.get('emoncms', 'url')
                node = c.get('emoncms', 'node')
                apikey = c.get('emoncms', 'apikey')

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
                    headers = {'Authorization': f'Token {token}'}
                    params = {"org":org,"bucket": bucket,"precision":"s"}
                else:
                    db = c.get('influxdb', 'db')
                    headers = {}
                    params = {'db':db, 'precision':'s'}

                logging.debug("URL: %s", url)
                payload = []
                for channel in data_out:
                    payload.append(f"{measurement},channel={channel} value={data_out[channel]} {timestamp}")
                logging.debug("Payload: %s", payload)
                payload_str = "\n".join(payload)

                post_to_url(session, url, headers=headers, params=params, data=payload_str)

            if 'localsave' in c.sections() and c.getboolean('localsave', 'enabled'):
            # LOCALSAVE
                if ls_day != utcnow.day:
                    ls_day = utcnow.day
                    ls_dir = c.get('localsave', 'directory')
                    ls_filename = os.path.join(ls_dir, f"lcl-{timestamp}.csv")
                    logging.debug("Localsave file: %s", ls_filename)
                    write_header = True

                csv = ",".join(map(lambda x: str(x+1), data_out.values()))
                with open(ls_filename, "at", encoding="ascii") as f:
                    if write_header:
                        csv_headers = ",".join(data_out.keys())
                        f.write(f"timestamp,{csv_headers}\n")
                        write_header = False

                    f.write(f"{timestamp},{csv}\n")

            logging.debug("---")


        except KeyboardInterrupt:
            logging.info("Terminating.")
            break

        except requests.exceptions.ConnectionError as e:
            logging.warning(e)
