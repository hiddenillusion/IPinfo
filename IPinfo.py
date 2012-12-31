#!/usr/bin/env python

# IPinfo.py was created by Glenn P. Edwards Jr.
#   http://hiddenillusion.blogspot.com
#       @hiddenillusion
# Version 0.1.1
# Date: 12-18-2012

"""
Usage:
------
    1) Supply it an IP/site

Requirements:
-------------
    - simplejson
    - BeautifulSoup
    - API keys from Virus Total, Google Safe Browsing & Project Honeypot

 To-do:
--------
	- McAfee SiteAdvisor / TrustedSoruce
	- exsporure.iseclab.org
	- robtex
	- fast flux
    - cleanMX
	- sucuri
	- Phishtank, urlquery & wepawet are already in VirusTotal ...
	- malc0de
	- senderbase
	- spamhause / spamcop
    - if site given, use GeoIP/nslookup to get IP and use for Honeypot?
"""
import re
import os
import sys
import base64
import urllib
import urllib2
import socket
import simplejson
from datetime import datetime
from time import localtime, strftime
from BeautifulSoup import BeautifulSoup, NavigableString

s = sys.argv[1]
# sanity check for WOT
if re.match('^http(s)?://.*', s):
    s = re.sub('^http(s)?://','',s)

def header(msg):
    return "\n" + msg + "\n" + ("=" * 40)

def subTitle(msg):
    return msg + "\n" + ("-" * 40)

def GeoIP(s):
    """
    GeoIP info: http://freegeoip.net/static/index.html
    Restrictions: < 1,0000 queries an hour
    """
    print (header("GeoIP Information"))
    url = "http://freegeoip.net/json/"
    try:
        req = urllib2.urlopen(url + s)
        result = req.read()
        rpt = simplejson.loads(result)
        for key,value in rpt.iteritems():
            if value:
                print "%12s : %-s" % (key,value)
    except Exception, msg:
        print msg

def Honeypot(s):
    """
    Project Honeypot's Http:BL API info: https://www.projecthoneypot.org/httpbl_api.php
    """
    print (header("Project Honeypot"))
    api_key = "YOUR_API_KEY"
    if not api_key:
        print "[!] You must configure your Project Honeypot API key"
        return

    def threat_rating(num): 
        """
        third octet
        ranges from 0 (low) - 255 (severe)
        http://www.projecthoneypot.org/threat_info.php
        """
        if num <= 25: tr = "Low"
        elif num <= 50: tr = "Medium"
        elif num <= 75: tr = "High"
        elif num <= 100: tr = "Severe"
        else: tr = "N/A"
        return tr

    def visitor_type(num): 
        """
        fourth octet
        """
        if num == 0: vt = "Search Engine"
        elif num == 1: vt = "Suspicious"
        elif num == 2: vt = "Harvester"
        elif num == 3: vt = "Suspicious & Harvester"
        elif num == 4: vt = "Comment Spammer"
        elif num == 5: vt = "Suspicious & Comment Spammer"
        elif num == 6: vt = "Harvester & Comment Spammer"
        elif num == 7: vt = "Suspicious & Comment Spammer"
        else: vt = "N/A"
        return vt

    # if fourth octet is 0 (search engine), 3rd octet is identifier for search engine
    def search_engines(num):
        if num == 0: se = "Undocumented"
        elif num == 1: se = "AltaVista"
        elif num == 2: se = "Ask"
        elif num == 3: se = "Baidu"
        elif num == 4: se = "Excite"
        elif num == 5: se = "Google"
        elif num == 6: se = "Looksmart"
        elif num == 7: se = "Lycos"
        elif num == 8: se = "MSN"
        elif num == 9: se = "Yahoo"
        elif num == 10: se = "Cuil"
        elif num == 11: se = "InfoSeek"
        elif num == 11: se = "Misc"
        else: se = "N/A"
        return se

    fields = s.split('.')
    fields.reverse()
    flipped = '.'.join(fields)
    query = api_key + "." + flipped + "." + "dnsbl.httpbl.org"
    try:
        result = socket.gethostbyname(query)
        vt, tr, days_since_last_activity, response_code = [int(octet) for octet in result.split('.')[::-1]]
        if response_code != 127:
            print "Invalid Response Code"
        else:
            print "Visitor type............:",visitor_type(vt)
            if visitor_type == 0:
                tr = search_engines(tr)
                print "\t\t(%s)",threat_rating(tr)
            else:
                print "Threat rating...........: %s (%d)" % (threat_rating(tr),tr)
            print "Days since last activity:",days_since_last_activity
    except socket.gaierror:
        print "Not Listed"

def hpHosts(s):
    """
    hpHosts docs : http://hosts-file.net/?s=Help#developers
    """
    url = "http://verify.hosts-file.net/?v=IPinfo&s="
    arg = "&class=true&date=true&ip=true&ipptr=true&nb=1"
    print (header("hpHosts"))
    try:
        page = urllib2.urlopen(url + s + arg)        
        soup = BeautifulSoup(page)
        # strip HTML page breaks etc.
        txt = soup.findAll(text=lambda txt:isinstance(txt, NavigableString))
        for l in txt:
            val = l.split(',')
            """
            Classification explanations: http://hosts-file.net/?s=classifications
            """
            classes = {'ATS': 'Ad/tracking server', 
                       'EMD': 'Malware distribution', 
                       'EXP': 'Exploit site', 
                       'FSA': 'Rogue software distribution', 
                       'GRM': 'Astroturfing site', 
                       'HFS': 'Spamming', 
                       'HJK': 'Hijacking', 
                       'MMT': 'Misleading marketing tactics', 
                       'PSH': 'Phishing', 'WRZ': 'Warez'};
            # get rid of comments and other junk
            if not re.match('^(#|%|remarks:)', l):
                if re.search('Listed', val[0]):
                    print "[-] Listed?.......:",val[0].split('[')[0]
                if classes.has_key(val[1]):
                    print "[-] Classification:",classes[val[1]]
                if re.match('\d{2}-\d{2}-\d{4}',val[2]):
                    print "[-] Date..........:",val[2]
                if re.search('NETBLOCK', l):
                    m = re.search('\[NETBLOCK\](.*)\[\/NETBLOCK\]', str(txt))
                    g = m.group(1).split(',')
                    print "[-] Netblock info :"
                    for i in g:
                        # yes ... I'm OCD
                        s = re.sub("(^\su|'|\")","",i)
                        if not re.match('(^%\s|^%$|^$)',s):
                            print s
    except Exception, msg:
        print msg        

def SafeBrowsing(s):
    """
    Google SafeBrowsing API info: https://developers.google.com/safe-browsing/
    """
    print (header("Google Safe Browsing"))
    api_key = "YOUR_API_KEY"
    if not api_key:
        print "[!] You must configure your Google SafeBrowsing API key"
    else:
        url = "https://sb-ssl.google.com/safebrowsing/api/lookup?"
        parameters = {"client": "api", 
                      "apikey": api_key, 
                      "appver": "1.0", 
                      "pver": "3.0", 
                      "url": s} 
        data = urllib.urlencode(parameters)
        req = url + data
        try:
            response = urllib2.urlopen(req)
            result = response.read()
            if len(result):
                print "[-] Classification: ",result
            else: print "No Match"
        except Exception, msg:
            print msg

def WOT(s):
    """
    WOT API info: http://www.mywot.com/wiki/API
    Restrictions: < 50000 API requests during any 24 hour period & <= 10 requests per second
    """
    print (header("MyWOT"))

    # WOT scoring
    def category(num):
        if num == "0": rating = "Trustworthy"
        elif num == "1": rating = "Vendor reliable"
        elif num == "2": rating = "Privacy"
        elif num == "4": rating = "Child safety"
        else: rating = "N/A"
        return rating

    # WOT Reputation/Confidence scoring
    def score(num):
        if num > "80": con = "Excellent"
        elif num > "60": con = "Good"
        elif num > "40": con = "Unsatisfactory"
        elif num > "20": con = "Poor"
        elif num > "0": con = "Very Poor"
        else: con = "N/A"
        return con 

    url = "http://api.mywot.com/0.4/public_query2?target="
    try:    
        page = urllib2.urlopen(url + s).read()
        soup = BeautifulSoup(page)
        hits = soup.findAll('application')
        if len(hits):
            try:
                print (subTitle("      Category | Reputation | Confidence"))
                for h in hits:
                    print "%15s: %-s, %s" % (category(h['name']),score(h['r']),score(h['c']))
            except Exception, msg:
                print msg
        else: print "No Match"
    except Exception, msg:
        print msg        

def VirusTotal(s):
    """
    VirusTotal API info: https://www.virustotal.com/documentation/public-api/
    """
    print (header("Virus Total"))
    api_key = "YOUR_API_KEY"
    if not re.match('\d+', api_key):
        print "[!] You must configure your VirusTotal API key"
    else:
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": s, 
                      "apikey": api_key} 
        data = urllib.urlencode(parameters)
        try:
            req = urllib2.Request(url, data)            
            response = urllib2.urlopen(req)
            result = response.read()
            rpt = simplejson.loads(result)
            date = rpt["scan_date"].split(' ')[0]
            print "Scan Date..:",datetime.strptime(date, "%Y-%m-%d").strftime("%b %d %Y")
            print "Total Scans:",rpt["total"]
            print "Detected...:",rpt["positives"]
            print (subTitle("\t\tScanner | Classification"))
            for scanner in rpt["scans"]:
                if not re.match('clean site',rpt["scans"][scanner]["result"]):
                    print "%23s : %-s" % (scanner,rpt["scans"][scanner]["result"])
        except Exception, msg:
            print msg

def main():
    GeoIP(s)
    hpHosts(s)
    WOT(s)
    SafeBrowsing(s)
    VirusTotal(s)
    if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        Honeypot(s)

if __name__ == "__main__":
        main()