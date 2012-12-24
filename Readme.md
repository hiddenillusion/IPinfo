IPinfo.py
=============

Searches various online resources to try and get as much info about an IP/domain as possible.  I essentially wanted a more automated/scriptable way to get this information without having to check various sites etc. etc.

Requirements
------------
	* simplejson
	* Beautifulsoup	
	* API keys from Virus Total, Google Safe Browsing & Project Honeypot

Usage
-----

    usage: IPinfo.py <IP/domain>

Example output
--------------

	GeoIP Information
	========================================
	   longitude : 5.75
	country_name : Netherlands
	country_code : NL
              ip : 83.137.194.13
        latitude : 52.5

	hpHosts
	========================================
	[-] Listed?.......: Not Listed

	MyWOT
	========================================
		Category | Reputation | Confidence
	----------------------------------------
		Trustworthy: Very Poor, Very Poor
	Vendor reliable: Very Poor, Very Poor
			Privacy: Very Poor, Very Poor

	Google Safe Browsing
	========================================
	[-] Classification:  malware

	Virus Total
	========================================
	Scan Date..: Dec 17 2012
	Total Scans: 32
	Detected...: 3
					Scanner | Classification
	----------------------------------------
		Google Safebrowsing : malware site
	       Sucuri SiteCheck : malicious site
               SCUMWARE.org : malware site
      Comodo Site Inspector : suspicious site
                SecureBrain : unrated site
                   URLQuery : unrated site
                    Wepawet : unrated site	