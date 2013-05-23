#!/usr/bin/env python
#
# cDorkedCheck is a simple script used to determine if domain name and IP address
# provided is malicious and related to the cDorked trojaned web server binaries.
#
# ie 
# python cDorkedCheck.py 5a41e2f57fe12caf.aaron-weisinger.info 62.212.132.148
# Cdorked domain
# XOR Seed is: 53
#
# Copyright (C) Dave Lowe 2013 <dave@davelowe.com.au>
#
# This file is part of cDorkedCheck.
# cDorkedCheck is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# cDorkedCheck is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with cDorkedCheck.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import getopt
import string
from optparse import OptionParser

__appname__ = 'cDorkedCheck'
__version__ = '0.0.0.0.0.0.1a - yes, thats a joke'
__author__ = "Dave Lowe <dave@davelowe.com.au>"
__licence__ = "GPL"

def is_hex(s):
     hex_digits = set(string.hexdigits)
     return all(c in hex_digits for c in s)

def bustXORSEED(obf, lastOctet):
    for key in range(1,255):
        buff = key ^ obf
        if buff == lastOctet:
            return key

def bustXOR(strBuff, lastOctet):
    l = []
    for a in xrange(0, len(strBuff), 2):
        intHexBuff = int(strBuff[a:a+2], 16)
        l.append(intHexBuff)

    seed = bustXORSEED(l[0], lastOctet)

    if not seed:
        print "Can't determine xor seed"
        sys.exit(1)

    ip = []
    ip.insert(0, str(l[3] ^ l[2]))
    ip.insert(1, str(l[2] ^ l[1]))
    ip.insert(2, str(l[1] ^ l[0]))
    ip.insert(3, str(l[0] ^ seed))
    return (ip, seed)

def splitSubdomain(strSub):
    first = list(strSub)
    listOfIP = first[1:][::2]
    strBuff = ''.join(listOfIP)
    return strBuff

def main(argv=None):
    if argv is None:
        argv = sys.argv

    usage = "usage: %prog DOMAIN IPADDRESS"
    parser = OptionParser(usage=usage, version=__version__)
    
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose")
    
    (options, args) = parser.parse_args(argv)

    if (len(argv) == 1):
        print "Error"
        sys.exit(1)

    try :
        strDomain = argv[1]
        strIP = argv[2]
    except IndexError:
        parser.print_help()
        sys.exit(1)

    # Obtain the subdomain
    strSubdomain = strDomain.split(".",1)[0]

    # Ensure subdomain is hex only
    if (is_hex(strSubdomain) == False):
        print >>sys.stderr, "Subdomain contains non-hex characters. Non-cDorked"
        sys.exit(1)

    elif (len(strSubdomain) != 16):
        print >>sys.stderr, "Subdomain is not 16 chars in length. Non-cDorked"
        sys.exit(1)

    if (options.verbose):print "Subdomain passed checks"

    # Return every second char from subdomain
    strObfIP = splitSubdomain(strSubdomain)
    if (options.verbose):print "Segmented subdomain obfuscated IP: %s" % (strObfIP)

    # We only need the last IP octet from the args to brute the xor seed
    lastOctet = int(strIP.split(".")[-1])
    if (options.verbose):print "Last IP octet from args: %s" % (lastOctet)

    # Brute the xor key, and return the seed plus deobfuscated IP address
    results = bustXOR(strObfIP, lastOctet)

    ip = results[0]
    seed = results[1]
    strIPFromSubDomain = '%s.%s.%s.%s' % (ip[0],ip[1],ip[2],ip[3])

    # If the IP address returned from the xor work is the same
    # as the IP provided via args, then bingo! Its cdork
    if strIPFromSubDomain == strIP:
        if (options.verbose): 
            print "Cdorked domain: %s IP: %s. Seed: %s" %(strDomain,strIPFromSubDomain, seed)
        else: 
            print "Cdorked domain: %s" %(strDomain)

if __name__ == "__main__":
    main()