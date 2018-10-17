#!/usr/bin/env python
#########################################################################
# Gregory Camp
# grcamp@cisco.com
# ios_office365_acl_creator
#
#########################################################################

import requests
import logging
import sys
import os
import argparse
import xml.etree.ElementTree as ET

# Declare global variables
logger = logging.getLogger(__name__)


def warning(msg):
    logger.warning(msg)

def error(msg):
    logger.error(msg)

def fatal(msg):
    logger.fatal(msg)
    exit(1)


def cidr_to_netmask(cidr):
    cidr = int(cidr)
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    return (str( (0xff000000 & mask) >> 24)   + '.' +
            str( (0x00ff0000 & mask) >> 16)   + '.' +
            str( (0x0000ff00 & mask) >> 8)    + '.' +
            str( (0x000000ff & mask)))

def cidr_to_wildcard_mask(cidr):
    cidr = int(cidr)
    mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
    netmask = str( (0xff000000 & mask) >> 24)   + '.' + \
              str( (0x00ff0000 & mask) >> 16)   + '.' + \
              str( (0x0000ff00 & mask) >> 8)    + '.' + \
              str( (0x000000ff & mask))

    wildcard = str(abs(int(netmask.split('.')[0]) - 255)) + '.' + \
               str(abs(int(netmask.split('.')[1]) - 255)) + '.' + \
               str(abs(int(netmask.split('.')[2]) - 255)) + '.' + \
               str(abs(int(netmask.split('.')[3]) - 255))

    return wildcard

def get_ios_acl_lines(addresslist, protocol, ports):
    # Declare variables
    lines = []
    ip_addresses = []

    # permit tcp

    if addresslist.attrib['type'] == 'IPv4':
        for address in addresslist.iter('address'):
            for port in ports:
                line = " permit {} {} {} eq {} any".format(protocol,
                                                           address.text.split('/')[0],
                                                           cidr_to_wildcard_mask(address.text.split('/')[1]),
                                                           port)
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
        parser.add_argument('--o365', action='store_true', default=False, help='Office 365 Product Type')
        args = parser.parse_args()

    myXML = requests.get('https://support.content.office.net/en-us/static/O365IPAddresses.xml').text

    root = ET.fromstring(myXML)

    for product in root.iter('product'):
        if (product.attrib['name'] == 'o365') and (args.o365):
            for addresslist in product.iter('addresslist'):
                lines += get_ios_acl_lines(addresslist, 'tcp', ['80', '443'])

    # Return None
    return None


if __name__ == '__main__':
    try:
        main()
    except Exception, e:
        print str(e)
        os._exit(1)
