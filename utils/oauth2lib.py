#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import requests

import sys
import ssl
import base64

from os.path import abspath, realpath, isfile

from urllib.parse import urlencode, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from datetime import datetime, timedelta
from time import sleep


# See: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
# and: https://developers.google.com/identity/protocols/oauth2/limited-input-device


"""
  USAGE:

  mailer = Mailer(SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PWD)


  def auth_get(authorization_url):
    if mailer:
      mailer.send(SEND_TO, AUTH_SUBJECT, AUTH_TEXT.format(authorization_url), html=AUTH_HTML.format(authorization_url))

      authorization_code = run_server(SERVER_PORT, timeout=SERVER_TIMEOUT)
    else:
      print('Enter this url in a browser to authorize your application to receive emails:\n{}'.format(authorization_url))
      redirect_url = input('Paste the full redirect URL here: ')

      query = parse_qs(urlparse(redirect_url).query)
      authorization_code = queries.get('code')

    return authorization_code


  def device_auth_get(verification_url, user_code, expires_in):
    if mailer:
      mailer.send(SEND_TO, AUTH_SUBJECT, DEVICE_AUTH_TEXT.format(verification_url, user_code), html=DEVICE_AUTH_HTML.format(verification_url, user_code))
    else:
      print('Enter this url in a browser and enter the code {} to authorize your device to receive emails:\n{}'.format(user_code, verification_url))


  def auth():
    if REFRESH_TOKEN:
      ACCESS_TOKEN, REFRESH_TOKEN = auth_refresh(CLIENT_ID, CLIENT_SECRET, REFRESH_TOKEN, tenant_id=TENANT_ID)

    elif REDIRECT_URI:
      #authorization_url = auth_url(CLIENT_ID, REDIRECT_URI, tenant_id=TENANT_ID)
      #authorization_code = auth_get(authorization_url, REDIRECT_URI)
      authorization_code = auth_code(CLIENT_ID, REDIRECT_URI, callback=auth_get, tenant_id=TENANT_ID)

      if authorization_code:
        ACCESS_TOKEN, REFRESH_TOKEN = auth_request(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, authorization_code, tenant_id=TENANT_ID)

    else:
      device_code, expires_in, interval = device_auth_code(CLIENT_ID, callback=device_auth_get, tenant_id=TENANT_ID)
      if device_code:
        ACCESS_TOKEN, REFRESH_TOKEN  = device_auth_request(CLIENT_ID, CLIENT_SECRET, device_code, expires_in=expires_in, interval=interval, tenant_id=TENANT_ID)


  def imap():
    if ACCESS_TOKEN:
      mail = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
      mail.authenticate('XOAUTH2', lambda x: generate_xoauth2(IMAP_USER, ACCESS_TOKEN))
"""


AUTH_SUBJECT = 'Authorization required'

DEVICE_AUTH_TEXT = """\
Authorization has expired or needs to be initiated.
Use a web browser to open the page {}.
Enter the code {} to authorize your device to receive emails.
"""

DEVICE_AUTH_HTML = """\
<html>
  <body>
    <p>Authorization has expired or needs to be initiated.<br>
       Click this <a href="{}">link</a> and enter the code {}
       to authorize your device to receive emails.
    </p>
  </body>
</html>
"""

AUTH_TEXT = """\
Authorization has expired or needs to be initiated.
Enter this url in a browser to authorize your application to receive emails:
{}"""

AUTH_HTML = """\
<html>
  <body>
    <p>Authorization has expired or needs to be initiated.<br>
       Click this <a href="{}">link</a>
       to authorize your application to receive emails.
    </p>
  </body>
</html>
"""


class OAUTH2_TOKEN_ERROR(Exception):
  pass


class Mailer():
  def __init__(self, server, port, user, password):
    self.server = server
    self.port = port
    self.user = user
    self.password = password


  def send(self, send_to, subject, text, html=None):
    if not send_to:
      send_to = self.user

    message = MIMEMultipart('alternative')
    message['From'] = self.user
    if isinstance(send_to, list):
      message['To'] = ', '.join(send_to)
    else:
      message['To'] = send_to
    message['Subject'] = subject

    # Add HTML/plain-text parts to MIMEMultipart message
    # The email client will try to render the last part first
    message.attach(MIMEText(text, 'plain'))
    if html:
      message.attach(MIMEText(html, 'html'))

    # Create a secure SSL context
    #context = ssl.create_default_context()
    #with smtplib.SMTP_SSL(self.server, self.port, context=context) as server:

    # Create secure connection with server and send email
    with smtplib.SMTP(self.server, self.port) as server:
      server.starttls()
      server.login(self.user, self.password)
      server.sendmail(self.user, send_to, message.as_string())


def run_server(port, keyfile='key.pem', certfile='cert.pem', timeout=600):
  # Temporarily runs a basic HTTPS server listening for requests on the port specified
  # Make sure your router/firewall forwards external requests to this port

  #port = int(REDIRECT_URI.rsplit(':', maxsplit=1)[1].strip('/'))

  KEEP_RUNNING = True
  code = None

  keyfile = abspath(realpath(keyfile))
  certfile = abspath(realpath(certfile))

  if not isfile(keyfile) or not isfile(certfile):
    raise Exception('Invalid path to key and/or cert file')

  def validate(fields):
    nonlocal KEEP_RUNNING, code

    if fields and 'code' in fields:
       KEEP_RUNNING = False
       code = fields.get('code') # works without [0]

  class Server(BaseHTTPRequestHandler):
    def do_GET(self):
      query = urlparse(self.path).query
      fields= parse_qs(query)
      validate(fields)

      self.send_response(200)
      self.send_header("Content-type", "text/html")
      self.end_headers()
      self.wfile.write(b'Code received!')

    # Suppress log messages
    def log_message(self, format, *args):
      return

  handler_class = Server

  with HTTPServer(('', port), handler_class) as httpd:
    httpd.timeout = timeout
    httpd.handle_timeout = lambda: (_ for _ in ()).throw(TimeoutError())

    # To generate key and cert files with OpenSSL use the following command:
    # openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
    httpd.socket = ssl.wrap_socket (httpd.socket,
      keyfile=keyfile, certfile=certfile,
      server_side=True)

    try:
      while KEEP_RUNNING:
        httpd.handle_request()

    except KeyboardInterrupt:
      raise Exception('Terminated by user')

    except TimeoutError:
      raise Exception('Timeout')

  return code


def generate_xoauth2(username, access_token, base64_encode=False):
    auth_string = 'user={}\1auth=Bearer {}\1\1'.format(username, access_token)
    if base64_encode:
        auth_string = base64.b64encode(auth_string.encode()).decode()

    return auth_string


def auth_refresh(client_id, client_secret, refresh_token, tenant_id=None):
  data = {
    'client_id': client_id,
    'client_secret': client_secret, #'' if tenant_id else client_secret, # No client secret if tenant_id set (MS) ???
    'refresh_token': refresh_token,
    'grant_type': 'refresh_token',
    }

  if tenant_id:
    # MICROSOFT
    token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(tenant_id)
  else:
    # GOOGLE
    #token_url = 'https://accounts.google.com/o/oauth2/token'
    token_url = 'https://oauth2.googleapis.com/token'

  r = requests.post(token_url, data=data)
  response = r.json()

  if not r.ok:
    if 'error' in response:
      raise Exception(response.get('error_description'))
    else:
      raise Exception('Refresh access token failed with status code {}'.format(r.status_code))

  if 'access_token' in response:
    return response.get('access_token'), response.get('refresh_token')

  raise Exception('Refresh access token failed')


def auth_url(client_id, redirect_uri, offline=False, tenant_id=None):
  data = {
    'client_id': client_id,
    'redirect_uri': redirect_uri,
    'response_type': 'code',
    }

  if offline:
    # must be included to receive new refresh token with every request
    data['prompt'] = 'consent'
    data['access_type'] = 'offline'

  if tenant_id:
    # MICROSOFT
    authorization_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/authorize'.format(tenant_id)
    # include offline_access in scope to ensure response has refresh_token
    data['scope'] = 'offline_access https://outlook.office.com/IMAP.AccessAsUser.All'
  else:
    # GOOGLE
    #authorization_url  = 'https://accounts.google.com/o/oauth2/auth'
    authorization_url  = 'https://accounts.google.com/o/oauth2/v2/auth'
    data['scope'] = 'https://mail.google.com/ email'

  authorization_url = authorization_url + '?' + urlencode(data)

  return authorization_url


def auth_code(client_id, redirect_uri, offline=False, callback=None, tenant_id=None):
  authorization_url = auth_url(client_id, redirect_uri, offline=offline, tenant_id=tenant_id)

  # callback: Function that reads and returns authorization code from redirect_uri
  try:
    authorization_code = callback(authorization_url, redirect_uri)
  except:
    authorization_code = ''

  return authorization_code


def auth_request(client_id, client_secret, redirect_uri, authorization_code, tenant_id=None):
  data = {
    'client_id': client_id,
    'client_secret': client_secret,
    'redirect_uri': redirect_uri,
    'code': authorization_code,
    'grant_type': 'authorization_code',
    }

  if tenant_id:
    # MICROSOFT
    token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(tenant_id)
  else:
    # GOOGLE
    #token_url = 'https://accounts.google.com/o/oauth2/token'
    token_url = 'https://oauth2.googleapis.com/token'

  r = requests.post(token_url, data=data)
  response = r.json()

  if not r.ok:
    if 'error' in response:
      raise Exception(response.get('error_desciption'))
    else:
      raise Exception('Request access token failed with status code {}'.format(r.status_code))

  if 'access_token' in response:
    return response.get('access_token'), response.get('refresh_token')

  raise Exception('Request access token failed')



def device_auth_code(client_id, callback=None, tenant_id=None):
  data = {
    'client_id': client_id
  }

  if tenant_id:
    # MICROSOFT
    data['scope'] = 'offline_access https://outlook.office.com/IMAP.AccessAsUser.All'
    url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/devicecode'.format(tenant_id)
  else:
    # GOOGLE
    data['scope'] = 'email' #'https://mail.google.com/'
    url = 'https://oauth2.googleapis.com/device/code'

  r = requests.post(url, data=data)
  response = r.json()

  if not r.ok:
    if 'error' in response:
      raise Exception(response.get('error_description'))
    else:
      raise Exception('Request to url {} failed with status code {}.'.format(url, r.status_code))

  # Time (in s) user_code and device_code are valid
  # User must complete authorization flow before expiry
  expires_in = int(response.get('expires_in'))

  # Time (in s) to wait between polling requests to
  # authorization (token) server
  interval = response.get('interval')

  user_code = response.get('user_code')
  device_code = response.get('device_code')

  if 'verification_uri' in response:
    verification_url = response.get('verification_uri')
  else:
    verification_url = response.get('verification_url')

  # callback: Function that displays verification_url and user_code to the user
  try:
    wait = callback(verification_url, user_code)
  except:
    wait = 0

  if wait:
    expires_in = min(expires_in, wait)

  return device_code, expires_in, interval


def device_auth_request(client_id, client_secret, device_code, expires_in=600, interval=10, tenant_id=None):
  data = {
    'client_id': client_id,
    'client_secret': '' if tenant_id else client_secret, # No client secret if tenant_id set (MS) ???
    'code': device_code, # 'device_code':  device_code,
    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
  }

  if tenant_id:
    # MICROSOFT
    token_url = 'https://login.microsoftonline.com/{}/oauth2/v2.0/token'.format(tenant_id)
  else:
    # GOOGLE
    #token_url = 'https://accounts.google.com/o/oauth2/token'
    token_url = 'https://oauth2.googleapis.com/token'

  expires_at = datetime.now() + timedelta(seconds=expires_in)

  while datetime.now() < expires_at:
    r = requests.post(token_url, data=data)
    response = r.json()

    if not r.ok:
      if not  'error' in response:
        raise Exception('Request access token failed with status code {}'.format(r.status_code))

    if 'access_token' in response:
      return response.get('access_token'), response.get('refresh_token')

    sleep(interval)

  raise Exception('Timeout or code expired')
