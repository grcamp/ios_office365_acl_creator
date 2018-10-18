#!/usr/bin/env python
#########################################################################
# Gregory Camp
# grcamp@cisco.com
# ios_office365_acl_creator
#
# https://docs.microsoft.com/en-us/office365/enterprise/office-365-ip-web-service
#
#########################################################################

import requests
import logging
import sys
import uuid
import json
import os
import datetime
import argparse
import socket
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from collections import OrderedDict

# Declare global variables
logger = logging.getLogger(__name__)


def warning(msg):
    logger.warning(msg)

def error(msg):
    logger.error(msg)

def fatal(msg):
    logger.fatal(msg)
    exit(1)

def is_ip_address(ipAddress):
    # Return true if IP is valid, else return false
    try:
        socket.inet_aton(ipAddress)
        return True
    except socket.error:
        return False

    # Return False
    return False

def email_report(smtpServer, subject, body, filename, fromAddr, toAddr, ccAddr=""):
    logger.info("Emailing {}".format(filename))

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = fromAddr
    msg['To'] = toAddr
    msg['Cc'] = ccAddr

    rcpt = ccAddr.split(",") + toAddr.split(",")

    msg.attach(MIMEText(body, 'plain'))

    attachment = open(filename, "rb")

    part = MIMEBase('application', 'octet-stream')
    part.set_payload((attachment).read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', "attachment; filename= {}".format(filename))

    msg.attach(part)

    server = smtplib.SMTP(smtpServer, 25)
    text = msg.as_string()
    server.sendmail(fromAddr, rcpt, text)
    server.quit()

def convert_u_to_str(input):
    if isinstance(input, dict):
        return {convert_u_to_str(key): convert_u_to_str(value) for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [convert_u_to_str(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def cidr_to_netmask(cidr):
    cidr = int(cidr)
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return (str( (0xff000000 & mask) >> 24)   + '.' +
            str( (0x00ff0000 & mask) >> 16)   + '.' +
            str( (0x0000ff00 & mask) >> 8)    + '.' +
            str( (0x000000ff & mask)))

def cidr_to_wildcard_mask(cidr):
    netmask = cidr_to_netmask(cidr)

    wildcard = str(abs(int(netmask.split('.')[0]) - 255)) + '.' + \
               str(abs(int(netmask.split('.')[1]) - 255)) + '.' + \
               str(abs(int(netmask.split('.')[2]) - 255)) + '.' + \
               str(abs(int(netmask.split('.')[3]) - 255))

    return wildcard

def get_ios_acl_lines(ips, protocol, ports):
    # Declare variables
    lines = []

    # Loop through list of IPs
    for ip in ips:
        # Loop through list of ports
        for port in ports:
            # If IP is an ipv4 address
            if is_ip_address(ip.split('/')[0]):
                # Check if port is a range
                if '-' in port:
                    # Replace - with a space
                    port = port.replace('-', ' ')
                    # Set match keyword
                    port_match = 'range'
                # Else port is not a range
                else:
                    # Set match keyword
                    port_match = 'eq'

                # Build ACL Line
                line = " permit {} {} {} {} {} any".format(protocol,
                                                           ip.split('/')[0],
                                                           cidr_to_wildcard_mask(ip.split('/')[1]),
                                                           port_match,
                                                           port)
                # Append line to list
                lines.append(line)

    # Return lines
    return lines

def main(**kwargs):
    # Declare variables
    lines = []
    lines.append('ip access-list extended OFFICE_365')

    # Set logging
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, format="%(asctime)s [%(levelname)8s]:  %(message)s")

    if kwargs:
        args = kwargs
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('output_file', help='Output File')
        parser.add_argument('--email', help='Email File')
        args = parser.parse_args()

    # Get WorldWide IP List
    my_guid = str(uuid.uuid4())
    my_json = requests.get("https://endpoints.office.com/endpoints/worldwide?clientrequestid={}".format(my_guid)).text
    items = json.loads(my_json)
    items = convert_u_to_str(items)

    # Loop through each item to find ips
    for item in iter(items):
        # If TCP ports are found
        if 'ips' in item and 'tcpPorts' in item:
            # Build ACL Lines
            lines += get_ios_acl_lines(item['ips'], 'tcp', item['tcpPorts'].split(','))
        # If UDP ports are found
        if 'ips' in item and 'udpPorts' in item:
            # Build ACL Lines
            lines += get_ios_acl_lines(item['ips'], 'udp', item['udpPorts'].split(','))

    # Remove duplicates
    uniq_lines = list(OrderedDict.fromkeys(lines))

    # Write file
    with open(args.output_file, 'w') as my_file:
        for line in uniq_lines:
            my_file.write("{}\n".format(line))

    # Email file
    if args.email:
        # Open file
        json_file = open(args.email, 'r')
        # Read file into a list
        config = json.load(json_file)
        # Close file
        json_file.close()
        # Get current Time
        currentDT = datetime.datetime.now()


        # Email report
        email_report(str(config['email']['smtp']),
                     "RBS - Office 365 ACL Config - {}/{}/{}".format(str(currentDT.month).zfill(2),
                                                                     str(currentDT.day).zfill(2),
                                                                     str(currentDT.year).zfill(2)),
                     "Office 365 ACL Config File {} attached".format(args.output_file),
                     args.output_file, str(config['email']['from']), str(config['email']['to']), str(config['email']['cc']))

    # Return 0
    return 0


if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        print str(e)
        os._exit(1)
