#!/usr/bin/env python

#
# A virustotal.com Public API interactiong script
# Copyright (C) 2015, Tal Melamed <virustotal AT appsec.it>
# Contribute @ https://github.com/nu11p0inter/virustotal/
#
# VT SCAN EULA
# ------------
# By using the upload/ scan API, you consent to virustotal
# Terms of Service (https://www.virustotal.com/en/about/terms-of-service/)
# and allow VirusTotal to share this file with the security community. 
# See virustotal Privacy Policy (https://www.virustotal.com/en/about/privacy/) for details.
#

import hashlib, urllib, urllib2, json, os
try:
    import requests
except:
    print '[Warning] request module is missing. requests module is required in order to upload new files for scan.\nYou can install it by running: pip install requests.'

class vt:
    def __init__(self):
        self.api_key = '__VIRUS_TOTAL_API_KEY__'
        self.api_url = 'https://www.virustotal.com/vtapi/v2/'
        # default ouput format --> print to output
        # print, json, html
        self._output = "json"
        self.errmsg = 'Something went wrong. Please try again later, or contact us.'
        # print "Thank you for using virustotal by Tal Melamed <virustotal@appsec.it>\nContribute @ https://github.com/nu11p0inter/virustotal"

    # handles http error codes from vt
    def handleHTTPErros(self, code):
        if code == 404:
            print self.errmsg + '\n[Error 404].'
            return 0
        elif code == 403:
            print 'You do not have permissions to make that call.\nThat should not have happened, please contact us.\n[Error 403].'
            return 0
        elif code == 204:
            print 'The quota limit has exceeded, please wait and try again soon.\nIf this problem continues, please contact us.\n[Error 204].'
            return 0
        else:
            print self.errmsg + '\n[Error '+str(code)+']'
            return 0
        
    # change mode of api - scan/rescan, report or comment

    # change mode of output - json, html or print to output
    def out(self, xformat):
        if xformat == "print":
            self._output = "print"
        elif xformat == "html":
            self._output = "html"
        else:
            self._output = "json"
            
    # Sending and scanning files
    def scanfile(self, file):
        url = self.api_url + "file/scan"
        files = {'file': open(file, 'rb')}
        headers = {"apikey": self.api_key}
        try:
            response = requests.post( url, files=files, data=headers )
            xjson = response.json()
            response_code = xjson ['response_code']
            verbose_msg = xjson ['verbose_msg']
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()           

    # Sending and scanning URLs
    def scanurl(self, link):
        url = self.api_url + "url/scan"
        parameters = {"url": link, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
        
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc() 
        
    
    # Retrieving file scan reports
    def getfile(self, file):
        if os.path.isfile(file):
            f = open(file, 'rb')
            file = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "file/report"
        parameters = {"resource": file, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return self.report(xjson)
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()       
              
    # Retrieving URL scan reports
    def geturl(self, resource):
        url = self.api_url + "url/report" 
        parameters = {"resource": resource, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return self.report(xjson)
            else:
                print verbose_msg
        
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()
            
    #Retrieving IP address reports
    def getip (self, ip):
        url = self.api_url + "ip-address/report"
        parameters = {"ip": ip, "apikey": self.api_key}
        try:
            response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
            xjson = json.loads(response)
            response_code = xjson['response_code']
            verbose_msg = xjson['verbose_msg']
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()  
        
    # Retrieving domain reports
    def getdomain(self, domain):
        url = self.api_url + "domain/report"
        parameters = {"domain": domain, "apikey": self.api_key}
        try:
            response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
            xjson = json.loads(response)
            response_code = xjson['response_code']
            verbose_msg = xjson['verbose_msg']
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()  
        
    # Make comments on files and URLs
    def comment(self, resource, comment):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "comments/put"
        parameters = {"resource": resource, "comment": comment, "apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()
            
    #Rescanning already submitted files  
    def rescan(self, resource):
        if os.path.isfile(resource):
            f = open(resource, 'rb')
            resource = hashlib.sha256(f.read()).hexdigest()
            f.close()
        url = self.api_url + "file/rescan"
        parameters = {"resource":  resource, "apikey": self.api_key }
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        try:
            response = urllib2.urlopen(req)
            xjson = response.read()
            response_code = json.loads(xjson).get('response_code')
            verbose_msg = json.loads(xjson).get('verbose_msg')
            if response_code == 1:
                print verbose_msg
                return xjson
            else:
                print verbose_msg
                
        except urllib2.HTTPError, e:
            self.handleHTTPErros(e.code)
        except urllib2.URLError, e:
            print 'URLError: ' + str(e.reason)
        except Exception:
            import traceback
            print 'generic exception: ' + traceback.format_exc()

    # internal - returns results accourding to output format (json, html or output)
    # available only for getfile and geturl
    def report(self, jsonx):
        if self._output == "json":
            return jsonx

        elif self._output == "html":
            jsonx = json.loads(jsonx)
            url = jsonx.get('permalink')
            print url
            html = urllib2.urlopen(url, timeout=3).read()
            return html.replace('<div class="frame" style="margin:20px 0">', '<a href="https://github.com/nu11p0inter/virustotal"> Exceuted by Tal Melamed [virustotal@appsec.it]</a> <div class="frame" style="margin:20px 0">')
        
        else: #print
            avlist = []
            jsonx = json.loads(jsonx)
            scan_date = jsonx.get('scan_date')
            total = jsonx.get('total')
            positive = jsonx.get('positives')
            print 'Scan date: ' + scan_date
            print 'Detection ratio: ' + str(positive) + "/" + str(total)
            scans = jsonx.get('scans')
            for av in scans.iterkeys():
                res = scans.get(av)
                if res.get('detected') == True:
                    avlist.append('+ ' + av + ':  ' + res.get('result'))
            if positive > 0:
                for res in avlist:
                    print res
                return avlist
            else:
                return 0

    # set a new api-key
    def setkey(self, key):
        self.api_key = key
