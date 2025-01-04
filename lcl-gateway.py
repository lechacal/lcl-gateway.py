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

#from tinyflux import TinyFlux, Point

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
        channels = channel_names
    else:
        channels = re.sub('\\s', '', channels)
        channels = channels.split(',')
    logging.debug("Channels: %s", channels)

    # Parse zero thresholds, e.g. P*:10 or P1:20
    zero_thresholds = dict(zip(channels, [0]*len(channels)))    # Default is 0 for all channels
    zt_config = c.get('system', 'zero_thresholds', fallback='*:0')
    if zero_thresholds is not None:
        zt_config = re.sub('\\s', '', zt_config)
        zt_config = zt_config.split(',')
        for zt in zt_config:
            try:
                zt_ch, zt_val = zt.replace(' ', '').split(':')
                if zt_ch.endswith('*'):
                    for ch in zero_thresholds:
                        if ch.startswith(zt_ch[:-1]):
                            zero_thresholds[ch] = float(zt_val)
                else:
                    zero_thresholds[zt_ch] = float(zt_val)
            except Exception as ex:
                logging.warning('Invalid zero_threshold entry: %s (%s)', zt, ex)
    logging.debug("Zero thresholds: %s", zero_thresholds)

    serial_port = c.get('system', 'port')
    baud = c.get('system', 'baud')
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
    
    # Open the tinyflux db if enabled
    #if 'tinyfluxdb' in c.sections() and c.getboolean('tinyfluxdb', 'enabled'):
    #	tinyfluxdb = TinyFlux(c.get('tinyfluxdb', 'database_name'))

    while True:
        try:
            # Read one line from the source
            data_in = ser.readline()
            now = datetime.datetime.now()
            timestamp = now.strftime("%s")
            
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

            # Filter near-zero noise
            data_out = {
                    key: data_out[key] if abs(data_out[key]) > zero_thresholds.get(key, 0) else 0
                    for key in data_out
            }

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
                node = c.get('influxdb', 'node')
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
                all_values = ",".join([f"{k}={data_out[k]}" for k in data_out])
                #payload = f"{measurement},node={node} {all_values} {timestamp}" # Use RPi timestamp
                payload = f"{measurement},node={node} {all_values}"
                logging.debug("Payload: %s", payload)

                post_to_url(session, url, headers=headers, params=params, data=payload)

            if 'localsave' in c.sections() and c.getboolean('localsave', 'enabled'):
            # LOCALSAVE
                if ls_day != now.day:
                    ls_day = now.day
                    ls_dir = c.get('localsave', 'directory')
                    ls_filename = os.path.join(ls_dir, f"lcl-{timestamp}.csv")
                    logging.debug("Localsave file: %s", ls_filename)
                    write_header = True

                csv = ",".join(map(lambda x: str(x), data_out.values()))
                with open(ls_filename, "at", encoding="ascii") as f:
                    if write_header:
                        csv_headers = ",".join(data_out.keys())
                        f.write(f"timestamp,{csv_headers}\n")
                        write_header = False

                    f.write(f"{timestamp},{csv}\n")
                    
            #if 'tinyfluxdb' in c.sections() and c.getboolean('tinyfluxdb', 'enabled'):
            # TINYFLUX
            #	p = Point(
            #		time=now,
            #		tags={"device": c.get('tinyfluxdb', 'tag')},
            #		fields = data_out
            #		)
            #	tinyfluxdb.insert(p) 

            logging.debug("---")


        except KeyboardInterrupt:
            logging.info("Terminating.")
            #if 'tinyfluxdb' in c.sections() and c.getboolean('tinyfluxdb', 'enabled'):
            #	tinyfluxdb.close()
            break

        except requests.exceptions.ConnectionError as e:
            logging.warning(e)
