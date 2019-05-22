#!/usr/bin/python


import base64
import cgi
import datetime
import getopt
import getpass
import httplib
import json
import logging
import md5
import os
import pprint
import random
import socket
import ssl
import sys
import time
import urllib
import urllib2
import uuid
import xml.dom.minidom
import zlib
from socket import gethostname
from urlparse import urlparse
from xml.sax.saxutils import escape

import libxml2
import xmlsec
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, send_from_directory, session)

app = Flask(__name__, static_url_path='')
app.secret_key = 'notasecret'

debug_flag = False
saml_issuer = "authn.py"
acs_url_override = None
key_file = ''
key_pwd = ''
cert_file = None


class SignatureError(Exception):
    pass


def getrandom_samlID():
    return random.choice('abcdefghijklmnopqrstuvwxyz') + hex(random.getrandbits(160))[2:-1]


def _generate_response(now, later, username, login_req_id, recipient, audience):
    resp_rand_id = getrandom_samlID()
    rand_id_assert = getrandom_samlID()
    sigtmpl = ''
    key_info = ''

    sigtmpl = ('<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
               '<ds:SignedInfo>'
               '<ds:CanonicalizationMethod '
               'Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />'
               '<ds:SignatureMethod '
               'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />'
               '<ds:Reference URI="#%s">'
               '<ds:Transforms>'
               '<ds:Transform Algorithm='
               '"http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
               '</ds:Transforms>'
               '<ds:DigestMethod Algorithm='
               '"http://www.w3.org/2000/09/xmldsig#sha1" />'
               '<ds:DigestValue></ds:DigestValue>'
               '</ds:Reference>'
               '</ds:SignedInfo>'
               '<ds:SignatureValue/>'
               '<ds:KeyInfo>'
               '<ds:X509Data>'
               '<ds:X509Certificate></ds:X509Certificate>'
               '</ds:X509Data>'
               '</ds:KeyInfo>'
               '</ds:Signature>') % (resp_rand_id)
    resp = ('<saml2p:Response '
            'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="%s" InResponseTo="%s" Version="2.0" IssueInstant="%s" Destination="%s">'
            '<saml2:Issuer>%s</saml2:Issuer>'
            '%s'
            '<saml2p:Status>'
            '<saml2p:StatusCode '
            'Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            '</saml2p:Status>'
            '<saml2:Assertion '
            'Version="2.0" ID="%s" IssueInstant="%s">'
            '<saml2:Issuer>%s</saml2:Issuer>'
            '<saml2:Subject>'
            '<saml2:NameID>%s</saml2:NameID>'
            '<saml2:SubjectConfirmation '
            'Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml2:SubjectConfirmationData '
            'InResponseTo="%s" Recipient="%s" NotOnOrAfter="%s"/>'
            '</saml2:SubjectConfirmation>'
            '</saml2:Subject>'
            '<saml2:Conditions NotBefore="%s" NotOnOrAfter="%s">'
            '<saml2:AudienceRestriction>'
            '<saml2:Audience>%s</saml2:Audience>'
            '</saml2:AudienceRestriction>'
            '</saml2:Conditions>'
            '<saml2:AuthnStatement AuthnInstant="%s" SessionIndex="%s">'
            '<saml2:AuthnContext>'
            '<saml2:AuthnContextClassRef>'
            'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            '</saml2:AuthnContextClassRef>'
            '</saml2:AuthnContext>'
            '</saml2:AuthnStatement>'
            '</saml2:Assertion>'
            '</saml2p:Response>') % (resp_rand_id, login_req_id, now, recipient,
                                     saml_issuer, sigtmpl, rand_id_assert, now,
                                     saml_issuer, username,
                                     login_req_id, recipient, later,
                                     now, later, audience,
                                     now, rand_id_assert)

    resp = '<!DOCTYPE saml2p:Response [<!ATTLIST saml2p:Response ID ID #IMPLIED>]>' + resp
    resp = _signXML(resp)
    return resp


def _signXML(xml):
    dsigctx = None
    doc = None
    try:
        # initialization
        libxml2.initParser()
        libxml2.substituteEntitiesDefault(1)
        if xmlsec.init() < 0:
            raise SignatureError('xmlsec init failed')
        if xmlsec.checkVersion() != 1:
            raise SignatureError('incompatible xmlsec library version %s' %
                                 str(xmlsec.checkVersion()))
        if xmlsec.cryptoAppInit(None) < 0:
            raise SignatureError('crypto initialization failed')
        if xmlsec.cryptoInit() < 0:
            raise SignatureError('xmlsec-crypto initialization failed')

        doc = libxml2.parseDoc(xml)
        if not doc or not doc.getRootElement():
            raise SignatureError('error parsing input xml')
        node = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature,
                               xmlsec.DSigNs)
        if not node:
            raise SignatureError("couldn't find root node")

        dsigctx = xmlsec.DSigCtx()

        key = xmlsec.cryptoAppKeyLoad(key_file, xmlsec.KeyDataFormatPem,
                                      key_pwd, None, None)

        if not key:
            raise SignatureError(
                'failed to load the private key %s' % key_file)
        dsigctx.signKey = key

        if key.setName(key_file) < 0:
            raise SignatureError('failed to set key name')

        if xmlsec.cryptoAppKeyCertLoad(key, cert_file, xmlsec.KeyDataFormatPem) < 0:
            print "Error: failed to load pem certificate \"%s\"" % cert_file
            return cleanup(doc, dsigctx)

        if dsigctx.sign(node) < 0:
            raise SignatureError('signing failed')
        signed_xml = doc.serialize()

    finally:
        if dsigctx:
            dsigctx.destroy()
        if doc:
            doc.freeDoc()
        xmlsec.cryptoShutdown()
        xmlsec.shutdown()
        libxml2.cleanupParser()

    return signed_xml

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

@app.route('/public/<path:path>')
def send_file(path):
    return send_from_directory('public', path)

@app.route('/')
def index():
    logged_in_user = ''
    if ('user' in session):
        logged_in_user = session['user']
    return render_template('login.html', footer_username=logged_in_user)

@app.route('/_ah/health')
def health():
    return('ok')

@app.route('/login')
def login():

    RelayState = request.args.get('RelayState')
    SAMLRequest = request.args.get('SAMLRequest')

    if (RelayState is not None):
        session['RelayState'] = RelayState
    if (SAMLRequest is not None):
        session['SAMLRequest'] = SAMLRequest

    if ('user' in session and RelayState != None and SAMLRequest != None):
        return _postResoponse(session['user'])
    return render_template('login.html')


def _postResoponse(username):
    RelayState = session['RelayState']
    SAMLRequest = session['SAMLRequest']

    decoded_saml = decode_base64_and_inflate(SAMLRequest)
    xmldoc = xml.dom.minidom.parseString(decoded_saml)

    saml_oissuer = None
    req_id = None
    acs_url = None
    samlpnode = xmldoc.getElementsByTagName('saml2p:AuthnRequest')
    for node in samlpnode:
        if node.nodeName == 'saml2p:AuthnRequest':
            if samlpnode[0].hasAttribute('ID'):
                req_id = samlpnode[0].attributes['ID'].value
            samliss = node.getElementsByTagName('saml2:Issuer')
            for n_issuer in samliss:
                cnode = n_issuer.childNodes[0]
                if cnode.nodeType == node.TEXT_NODE:
                    saml_oissuer = cnode.nodeValue
            if samlpnode[0].hasAttribute('AssertionConsumerServiceURL'):
                acs_url = samlpnode[0].attributes['AssertionConsumerServiceURL'].value
            else:
                log('NO AssertionConsumerServiceURL sent in saml request')
                return render_template('login.html', error_string="Error: No AssertionConsumerServiceURL provided in SAMLRequest")
            if debug_flag:
                log('Parsed AssertionConsumerServiceURL: %s' % (acs_url))

    if not req_id:
        log('Error: could not parse request SAML request ID')
        return render_template('login.html', error_string="Error: could not parse request SAML request ID")

    if acs_url_override:
        redirect_location = acs_url_override
    elif acs_url:
        redirect_location = acs_url
    else:
        log('NO AssertionConsumerServiceURL sent in saml request or override')
        return render_template('login.html', error_string="Error: No AssertionConsumerServiceURL provided in SAMLRequest")

    if debug_flag:
        log('Redirecting to: %s' % (redirect_location))

    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    five_sec_from_now = time.strftime(
        '%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time()+30))
    samlresp = _generate_response(now, five_sec_from_now, session['user'],
                                  req_id, acs_url,
                                  saml_oissuer)

    samlresp = samlresp.replace("""<!DOCTYPE saml2p:Response [
<!ATTLIST saml2p:Response ID ID #IMPLIED>
]>
""", "")
    print xml.dom.minidom.parseString(samlresp).toprettyxml()
    return render_template('response.html', redirect_location=redirect_location, relay_state=RelayState,
                           saml_response=base64.encodestring(samlresp),
                           decoded_saml=xml.dom.minidom.parseString(samlresp).toprettyxml())


@app.route('/authenticate', methods=["POST"])
def autheticate():
    username = request.form.get('username')
    password = request.form.get('password')

    if 'SAMLRequest' not in session:
        session['user'] = username
        return render_template('portal.html', footer_username=session['user'])

    # AUTO LOG THE USER IN
    # TODO: validate via ldap, etc

    session['user'] = username
    return _postResoponse(username)


@app.route('/logout')
def logout():
    session.clear()
    return render_template('logout.html')


def usage():
    print ('\nUsage: saml_idp.py --debug  '
           '--port=<port>  '
           '--saml_issuer=<issuer>  '
           '--key_file=<private_key_file>  '
           '--cert_file=<certificate_file>\n')


if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], None,
                                   ["debug", "port=",
                                    "saml_issuer=", "cert_file=",
                                    "key_file=", "acs_url_override="])
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
        if opt == "--acs_url_override":
            acs_url_override = arg

    if not key_file or not cert_file:
        print('No private key specified to use for POST binding.')
        usage()
        sys.exit(1)

    context = ('server.crt', 'server.key')
    app.run(host='0.0.0.0', port=28080, 
            threaded=True, ssl_context=context)
