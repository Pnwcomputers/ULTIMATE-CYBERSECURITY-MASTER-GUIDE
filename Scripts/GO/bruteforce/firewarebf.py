#!/usr/bin/env python3
"""Retired unsafe legacy example.

The former code performed remote firewall credential guessing. Use the vendor's administrative audit tools and approved identity controls.
This path is retained only to explain the retirement; it contains no former
payload, credential, or network code.
"""

raise SystemExit("Retired unsafe legacy example; see the module notice.")
# Copyright (c) 2012, AverageSecurityGuy
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
#  Redistributions of source code must retain the above copyright notice, this 
#  list of conditions and the following disclaimer.
#
#  Redistributions in binary form must reproduce the above copyright notice, 
#  this list of conditions and the following disclaimer in the documentation 
#  and/or other materials provided with the distribution.
#
#  Neither the name of AverageSecurityGuy nor the names of its contributors may
#  be used to endorse or promote products derived from this software without
#  specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
# OF SUCH DAMAGE.

#
# firewarebf.py attempts to bruteforce the password on a Watchguard firewall.

import poster
import urllib2
import ssl
import re
import argparse

#-----------------------------------------------------------------------------
# Functions
#-----------------------------------------------------------------------------
def list_from_file(filename):
    tmp = []
    try:
        f = open(filename, 'r')
    except:
        print "Could not open file: %s" % f.name()

    for line in f:
        tmp.append(line.rstrip('\r\n'))

    return tmp
    
def check_user_pass(url, user, pwd, domain):
    site = url + '/wgcgi.cgi?action=fw_logon&style=fw_logon.xsl&fw_logon_type=status'
    values = {'submit' : 'Login',
              'action' : 'fw_logon',
              'style' : 'fw_logon_progress.xsl',
              'fw_logon_type' : 'logon'}
              
    values['fw_username'] = user

Retired unsafe legacy example.

The former code performed remote firewall credential guessing. Use the vendor's administrative audit tools and approved identity controls.
This path is retained only to explain the retirement; it contains no former
payload, credential, or network code.
"""

raise SystemExit("Retired unsafe legacy example; see the module notice.")
