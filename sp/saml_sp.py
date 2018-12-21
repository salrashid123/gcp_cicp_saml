#!/usr/bin/python

import base64
import datetime
import getopt
import getpass
import md5
import random
import sys
import time
import urllib
import urlparse
import xml.dom.minidom
import zlib
from xml.sax.saxutils import escape
from socket import gethostname
import libxml2
import xmlsec
import cgi
import urllib2
import httplib, ssl, socket
import json

from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, send_from_directory, session)

app = Flask(__name__, static_url_path='')
app.secret_key = 'notasecret'

class SignatureError(Exception):
  pass

projectId = '226130788915'
api_key='AIzaSyBP4WHhJRsUNADMXK_JPcptt4KdvBlQ3LE'
sp_domain = 'https://sp.providerdomain.com:38080'
saml_provider_id = 'saml.myIdP'   
samlIDs = {}
saml_issuer = 'authn.py'

@app.route('/')
def index():
    logged_in_user = ''
    if ('user' in session):
        logged_in_user = session['user']
    return render_template('index.html', footer_username=logged_in_user)

@app.route('/public/<path:path>')
def send_file(path):
    return send_from_directory('public', path)


@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')


def generateRedirect(redirect_path):
        url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/createAuthUri?key=' + api_key
        values = {'identifier' : saml_provider_id,
                'continueUri' : sp_domain + redirect_path,
                'context' : 'redirected url after signin' }

        session['requestUri'] = sp_domain + redirect_path
        data = json.dumps(values)
        clen = len(data)
        req = urllib2.Request(url, data, {'Content-Type': 'application/json', 'Content-Length': clen})
        f = urllib2.urlopen(req)
        response = f.read()
        f.close()
        json_data = json.loads(response)

        print(json_data)
        url = json_data['authUri']
        parsed = urlparse.urlparse(url)
        SAMLRequest = urlparse.parse_qs(parsed.query)['SAMLRequest'][0]

        sessionId = json_data['sessionId']
        session['sessionId'] = sessionId

        authURI = json_data['authUri'] 
      
        log("Redirecting to : " + json_data['authUri'])
        return authURI

@app.route('/acs', methods=["POST"])
def acs(): 
      SAMLResponse = request.form.get('SAMLResponse', None)
      RelayState = request.form.get('RelayState', None)
      print RelayState
      print SAMLResponse

      if (SAMLResponse is None or RelayState is None):
        return render_template('index.html', error_string='Error: RelayState or SAMLResponse not provided to /acs')       
      else:         
        postBody = "RelayState=" + urllib.quote(RelayState, safe='')  + "&SAMLResponse=" + urllib.quote(SAMLResponse, safe='')
        print postBody
        url = 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion?key=' + api_key
        values = {"requestUri": session['requestUri'],
                  'postBody' : postBody,
                  'sessionId': session['sessionId'],
                  'projectId': projectId }

        data = json.dumps(values)
        clen = len(data)
        req = urllib2.Request(url, data, {'Content-Type': 'application/json', 'Content-Length': clen})

        response = {}
        try:        
         f = urllib2.urlopen(req)
         response = f.read()
         f.close()         
        except urllib2.HTTPError as e:
            error_message = e.read()
            return( error_message )

        json_data = json.loads(response)                                                                                    
        formatted_response =  json.dumps(json_data, indent=4, sort_keys=True)
        print formatted_response
        session['verify_assertion_response'] = formatted_response

        user = json_data['federatedId'] 
        session['user'] = user

        log("*********** LOGGED IN AS: " + user)
        log("**********>> Redirecting back to " + session['relativerequestUri'])
        return redirect(session['relativerequestUri'], code=302)   
        #return render_template('secure.html', footer_username=user)

@app.route('/secure')
def secure(): 
    
  if 'user' in session:
    return render_template('secure.html', footer_username=session['user'], verify_assertion_response=session['verify_assertion_response'])
  else:
    session['relativerequestUri'] = '/secure'
    return redirect(generateRedirect('/secure'), code=302)    

def cleanup(doc=None, dsig_ctx=None, res=-1):
    if dsig_ctx is not None:
        dsig_ctx.destroy()
    if doc is not None:
        doc.freeDoc()
    return res
  
def log(msg):
    print ('[%s] %s') % (datetime.datetime.now(), msg)

def decode_base64_and_inflate(b64string):
    decoded_data = base64.b64decode(b64string)
    return zlib.decompress(decoded_data, -15)

def deflate_and_base64_encode(string_val):
    zlibbed_str = zlib.compress(string_val)
    compressed_string = zlibbed_str[2:-4]
    return base64.b64encode(compressed_string)


def usage():
    print ('\nUsage: saml_idp.py --debug  '
           '--port=<port>  \n'
           '--key_file=<private_key_file> \n '
           '--cert_file=<certificate_file>\n'
           '--projectId=<projectId>\n'
           '--api_key=<api_key>')


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], None,
                                   ["debug", "port=",
                                    "saml_issuer=", "cert_file=",
                                    "key_file=", "projectId=", "api_key=",
                                    "sp_domain=", "saml_provider_id="])
    except getopt.GetoptError:
        usage()
        sys.exit(1)

    for opt, arg in opts:
        if opt == "--debug":
            debug_flag = True
        if opt == "--saml_issuer":
            saml_issuer = arg
        if opt == "--port":
            port = int(arg)
        if opt == "--key_file":
            key_file = arg
        if opt == "--cert_file":
            cert_file = arg
        if opt == "--cert_file":
            cert_file = arg
        if opt == "--projectId":
            projectId = arg
        if opt == "--api_key":
            api_key = arg                        
        if opt == "--sp_domain":
            sp_domain = arg  
        if opt == "--saml_provider_id":
            saml_provider_id = arg  

    if not key_file or not cert_file:
        print('No private key specified to use for POST binding.')
        usage()
        sys.exit(1)

    context = ('server.crt', 'server.key')
    app.run(host='0.0.0.0', port=38080, debug=True,
            threaded=True, ssl_context=context)

