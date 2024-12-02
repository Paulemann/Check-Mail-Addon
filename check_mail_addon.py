#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import email
import time
import datetime
import requests
import json
import html.parser
import base64
import select
import ssl

import logging
import configparser
import os
import sys

import argparse
import signal
import sqlite3

from socket import error as socket_error, create_connection as create_connection

#import errno
from html2text import html2text

from multiprocessing import *
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime, parsedate_tz, mktime_tz, getaddresses

from time import sleep


#Time format
TIME_FMT = '%d.%m.%Y %H:%M:%S'

# MS OAuth2 stuff
AUTH_URL = 'https://login.microsoftonline.com'
SCOPE = 'offline_access https://outlook.office.com/IMAP.AccessAsUser.All'


#logging.getLogger('requests.packages.urllib3').propagate = False
logging.getLogger('urllib3').setLevel(logging.WARNING)


# User defined Exceptions
class IDLE_DISCONNECT(Exception):
  pass

class IDLE_TIMEOUT(Exception):
  pass

class IDLE_COMPLETE(Exception):
  pass

class IMAP_CONNECT_ERROR(Exception):
  pass

class IMAP_AUTH_ERROR(Exception):
  pass


def generate_xoauth2(username, access_token, base64_encode=False):
    auth_string = 'user={}\1auth=Bearer {}\1\1'.format(username, access_token)
    if base64_encode:
        auth_string = base64.b64encode(auth_string.encode()).decode()

    return auth_string


def device_auth_initiate(client_id, tenant_id):
  # See: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
  data = {
    'scope': SCOPE,
    'client_id': client_id
  }

  r = requests.post('{}/{}/oauth2/v2.0/devicecode'.format(AUTH_URL, tenant_id), data=data)
  response = r.json()
  message = response.get('message')
  log(message, level='INFO')

  user_code = response.get('user_code')
  verification_uri = response.get('verification_uri')
  expires_in = response.get('expires_in')

  for host in _kodi_['host']:
    if host_is_up(host, _kodi_['port']):
      kodi_request(host, 'GUI.ShowNotification', params={'title': 'Device authorization required', 'message': message, 'displaytime': 2000}, port=_kodi_['port'], user=_kodi_['user'], password=_kodi_['password'])

  return response.get('device_code')


def device_auth_acquire(device_code, client_id, tenant_id):
  data = {
    'grant_type': 'urn:ietf:params:oauth:grant-type:device_code',
    'device_code': device_code,  #'code':  device_code
    'client_id': client_id
  }
  retries = 0

  log(' - Polling M365 Graph API for successful authentication ...', level='DEBUG')
  while retries < 10:
    r = requests.post('{}/{}/oauth2/v2.0/token'.format(AUTH_URL, tenant_id), data=data) # timeout?
    response = r.json()

    if response.get('refresh_token'):
      log(' - Access token acquired. User successfully authenticated', level='DEBUG')
      return response.get('access_token'), response.get('refresh_token')
    elif 'error' in response:
      log(' - Failed to acquire access token. Retrying ...', level='DEBUG')
      log(' - ' + response.get('error'), level='DEBUG')
      #log(response.get('error_description'), level='DEBUG')

    retries += 1
    sleep(10)

  log(' - Max. number of retries exceeded', level='ERROR')
  return None, None


def device_auth_refresh(client_id, client_secret, tenant_id, refresh_token):
  data = {
    'grant_type': 'refresh_token',
    'scope': SCOPE,
    'client_id': client_id,
    'client_secret': client_secret,
    'refresh_token': refresh_token
  }
  r = requests.post('{}/{}/oauth2/v2.0/token'.format(AUTH_URL, tenant_id), data=data)
  response = r.json()

  if response.get('refresh_token'):
    log(' - Access token refreshed. User successfully authenticated', level='DEBUG')
    return response.get('access_token'), response.get('refresh_token')
  else:
    log(' - Failed to refresh access token', level='DEBUG')
    return None, None


class Database(object):
  # mydb = Database('mail.db')
  # mydb.save(list_of_emails_as_dict)

  def __init__(self, path_to_db):
    self.connection = sqlite3.connect(path_to_db)
    self.cursor = self.connection.cursor()

    log('Creating database in \'{}\' ...'.format(path_to_db), level='DEBUG')
    self.create()

  def create(self):
    try:
      self.cursor.execute("""CREATE TABLE IF NOT EXISTS email
                             (id INTEGER PRIMARY KEY,
                              sender TEXT,
                              replyto TEXT,
                              recipients TEXT,
                              cc TEXT,
                              subject TEXT,
                              sent TEXT,
                              received TEXT,
                              text TEXT,
                              html TEXT,
                              attachments TEXT,
                              created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                              NOT NULL)
                          """)
      self.cursor.execute("""CREATE UNIQUE INDEX sender_subject ON email(sender, subject)""")

    except sqlite3.OperationalError:
      log('Database already exists.', level='DEBUG')

  def save(self, mails):
    with self.connection:
      log('Saving new mails to database.', level='DEBUG')
      sql = """INSERT OR IGNORE INTO email
               (sender,
                replyto,
                recipients,
                cc,
                subject,
                sent,
                received,
                text,
                html, attachments)
               VALUES
               (:from,
                :replyto,
                :to,
                :cc,
                :subject,
                :sent,
                :rcvd,
                :text,
                :html,
                :attach)
            """
      self.cursor.executemany(sql, mails)


def handler_stop_signals(signum, frame):
  sys.exit(0)

signal.signal(signal.SIGINT, handler_stop_signals)
signal.signal(signal.SIGTERM, handler_stop_signals)


def is_mailaddress(a):
  try:
    t = a.split('@')[1].split('.')[1]
  except:
    return False

  return True


def is_hostname(h):
  try:
    t = h.split('.')[2]
  except:
    return False

  return True


def is_int(n):
  try:
    t = int(n)
  except:
    return False

  return True


def log(message, level='INFO'):
  timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')
  if _log_file_:
    if level == 'DEBUG' and _debug_:
      logging.debug(message)
    if level == 'INFO':
      logging.info(message)
    if level == 'WARNING':
      logging.warning(message)
    if level == 'ERROR':
      logging.error(message)
    if level == 'CRITICAL':
      logging.crtitcal(message)
  else:
     if level != 'DEBUG' or _debug_:
       print('{} [{:^5s}]: {}'.format(timestamp, level,  message))


def save_value(section, option, value):
  try:
    config = configparser.ConfigParser(delimiters=('='))

    config.read([os.path.abspath(_config_file_)])

    if not config.has_section(section):
      log(' - There\'s no section \'{} \' in file \'{}\''.format(section, _config_file_), level='ERROR')
      return False

    config.set(section, option, value)

    with open(os.path.abspath(_config_file_), 'w') as configfile:
      config.write(configfile, space_around_delimiters=True)

  except Exception as e:
    log(' - Failed to update option \'{}\' in section \'{}\' of file \'{}\': {}'.format(option, section, _config_file_, e), level='ERROR')
    return False

  log(' - Successfully updated option \'{}\' in section \'{}\' of file \'{}\''.format(option, section, _config_file_), level='DEBUG')
  return True


def save_timestamp(user, timestamp):
  section = user

  for account in _accounts_:
    if account['user'] == user:
      section = account['name']

  return save_value(section, 'updated', timestamp)


def save_token(user, token):
  section = user

  for account in _accounts_:
    if account['user'] == user:
      section = account['name']

  return save_value(section, 'refresh_token', token)


def read_section(config, section, options, my_dict):

  for key, value in options.items():
    if value['type'] == 'int':
      if config.has_option(section, key):
        my_dict[key] = int(config.get(section, key))
      else:
        my_dict[key] = int(value['default'])

    elif value['type'] == 'str':
      if config.has_option(section, key):
        my_dict[key] = config.get(section, key) #.lower()
      else:
        my_dict[key] = value['default']

    elif value['type'] == 'list':
      if config.has_option(section, key):
        my_dict[key] = [p.strip(' "\'').lower() for p in config.get(section, key).split(',')]
      else:
        my_dict[key] = value['default']

    elif value['type'] == 'csv':
      if config.has_option(section, key):
        my_dict[key] = [int(p) for p in config.get(section, key).split(',')]
      else:
        my_dict[key] = value['default']

    elif value['type'] == 'bool':
      if config.has_option(section, key):
        my_dict[key] = (config.get(section, key) == 'yes')
      else:
        my_dict[key] = bool(value['default'])

    elif value['type'] == 'date':
      if config.has_option(section, key):
        my_dict[key] = datetime.datetime.strptime(config.get(section, key), TIME_FMT)
      else:
        my_dict[key] = value['default']

    if 'test' in value:
      if value['type'] in ['list', 'csv']:
        test = my_dict[key]
      else:
        test = [my_dict[key]]
      for element in test:
        if not value['test'](element):
          raise ValueError


def read_config():
  global _kodi_, _accounts_, _attachments_, _notification_title_, _msg_from_, _msg_subject_

  if not os.path.exists(_config_file_):
    log('Could not find configuration file \'{}\''.format(_config_file_), level='ERROR')
    return False

  try:
    # Read the config file
    config = configparser.ConfigParser()
    config.read([os.path.abspath(_config_file_)])

    _notification_title_ = 'New Message for'
    _msg_from_           = 'From'
    _msg_subject_        = 'Subject'

    _kodi_               = {}
    _attachments_        = {}
    _accounts_           = []

    for section_name in config.sections():
      if is_mailaddress(section_name):
        _accounts_.append({'name': section_name})

      if section_name == 'Customization':
        _notification_title_ = config.get('Customization', 'newmessagefor')
        _msg_from_           = config.get('Customization', 'from')
        _msg_subject_        = config.get('Customization', 'subject')

    kodi_options = {
      'host': {'type': 'list', 'test': is_hostname, 'default': None},
      'port': {'type': 'int', 'test': is_int, 'default': None},
      'user': {'type': 'str', 'default': None},
      'password': {'type': 'str', 'default': None}
      }
    read_section(config, 'KODI JSON-RPC', kodi_options, _kodi_)

    attachments_options = {
      'path': {'type': 'str', 'default': None},
      'type': {'type': 'list', 'default': None},
      'from': {'type': 'list', 'default': None}
      }
    read_section(config, 'Attachments', attachments_options, _attachments_)

    for account in _accounts_:
      account_options = {
        'server': {'type': 'str', 'test': is_hostname, 'default': None},
        'ssl': {'type': 'bool', 'default': True},
        'port': {'type': 'int', 'test': is_int, 'default': 993},
        'user': {'type': 'str', 'default': account['name']},
        'password': {'type': 'str', 'default': ''},
        'updated': {'type': 'date', 'default': None},
        'authmethod': {'type': 'str', 'default': 'basic'}
        }
      read_section(config, account['name'], account_options, account)

      account['oauth2'] = {}
      if account['authmethod'] == 'oauth2':
        oauth2_options = {
          'refresh_token': {'type': 'str', 'default': None},
          'tenant_id': {'type': 'str', 'default': 'consumers'},
          'client_id': {'type': 'str', 'default': None},
          'client_secret': {'type': 'str', 'default': ''}
          }
        read_section(config, account['name'], oauth2_options, account['oauth2'])

  except Exception as e:
    log('Could not process configuration file: {}'.format(type(e)), level='ERROR')
    return False

  return True


class MailBox(object):
  def __init__(self, server, user, password, port=None, ssl=True, updated=None, authmethod='basic', **kwargs):
    self.server = server
    self.user = user
    self.password = password
    self.ssl = ssl
    self.port = port
    self.authmethod = authmethod
    if self.authmethod == 'oauth2':
      self.client_id = kwargs['client_id']
      self.tenant_id = kwargs['tenant_id']
      self.client_secret = kwargs['client_secret']
      self.refresh_token = kwargs['refresh_token']

    if updated:
      log(' - Last message was received on {}'.format(updated.strftime('%B %-d, %Y at %-H:%M')), level='DEBUG')
      self.updated = updated
    else:
      log(' - Date of the last received message is unknown', level='DEBUG')
      self.updated = datetime.datetime.now().replace(second=0, microsecond=0)

    try:
       self.connect()
    except:
       raise

  def monitor(self, folder, callback=None, catchup=False):
    self.isRunning = False
    self.mon = Process(target=self.update, args=(folder, callback, catchup,))
    self.mon.start()

  def is_idle(self):
    return self.mon.is_alive() # and self.isRunning

  def close(self):
    self.mon.terminate()
    self.isRunning = False
    try:
      self.imap.done()

      self.imap.close()
      self.imap.logout()
    except:
      pass

  def search(self, *args):
    status, data = self.imap.uid('search', None, 'UNSEEN', *args)
    if status == 'OK' and data[0]:
      uid_list = data[0].split()
      return uid_list
    else:
      return []

  def mark_unseen(self, uid):
    status, data = self.imap.uid('store', uid, '-FLAGS', '(\\SEEN)')

  def mark_ssen(self, uid):
    status, data = self.imap.uid('store', uid, '+FLAGS', '(\\SEEN)')

  def delete(self, uid):
    status, data = self.imap.uid('store', uid, '+FLAGS', '(\\DELETED)')
    if status == 'OK':
      self.imap.expunge()

  def fetch(self, uid):
    #status, data = self.imap.uid('fetch', uid, '(RFC822)')
    status, data = self.imap.uid('fetch', uid, '(BODY.PEEK[])')
    if status == 'OK' and data[0]:
      email_msg = email.message_from_string(data[0][1].decode('utf-8'))
      #email_msg = email.message_from_bytes(data[0][1])
      return email_msg
    else:
      return None

  def num2uid(self, num):
    status, data = self.imap.fetch(num, 'UID')
    if status == 'OK' and data:
      for item in data:
        resp = [i.strip(b'()') for i in item.split()]
        if resp[0] == num and resp[1] == b'UID':
          return resp[2]
    return None

  def connect(self):
    if self.ssl:
      if not self.port:
        self.port = 993
    else:
      if not self.port:
        self.port = 143

    try:
      if self.authmethod == 'oauth2':
        log(' - Login attempt with method \'oauth2\' ...', level='DEBUG')

        if self.refresh_token:
          log(' - Refreshing access token ...', level='DEBUG')
          access_token, refresh_token = device_auth_refresh(self.client_id, self.client_secret, self.tenant_id, self.refresh_token)
        else:
          log(' - Requesting access token ...', level='DEBUG')
          device_code = device_auth_initiate(self.client_id, self.tenant_id)
          access_token, refresh_token = device_auth_acquire(device_code, self.client_id, self.tenant_id)

        if refresh_token:
          log(' - Saving refresh token ...', level='DEBUG')
          self.refresh_token = refresh_token
          save_token(self.user, self.refresh_token)

      if self.ssl:
        self.imap = imaplib.IMAP4_SSL(self.server, self.port)
      else:
        self.imap = imaplib.IMAP4(self.server, self.port)

      log(' - Connected to \'{}\''.format(self.server), level='DEBUG')

      #self.imap.debug = 10 # 4

      if self.authmethod == 'oauth2':
        auth_string = generate_xoauth2(self.user, access_token)

        self.imap.authenticate('XOAUTH2', lambda x: auth_string.encode())

      else:
        log(' - Login attempt with username and password ...', level='DEBUG')
        self.imap.login(self.user, self.password)

    except socket.error as e:
      log(' - Connection to \'{}:{}\' failed with error \'{}\''.format(self.server, self.port, e), level='DEBUG')
      raise IMAP_CONNECT_ERROR(e)

    except Exception as e:
      log(' - Login of user \'{}\' failed with error \'{}\''.format(self.user, e), level='DEBUG')
      raise IMAP_AUTH_ERROR(e)

    log(' - Mailbox user \'{}\' logged in'.format(self.user), level='DEBUG')

  def select(self, folder):
    if folder:
      status, data = self.imap.select(folder, readonly=True)
      if status == 'OK':
        log(' - Mailbox folder \'{}\' selected: {} messages'.format(folder, int(data[0])), level='DEBUG')
        return int(data[0])
      else:
        log(' - Selection of mailbox folder \'{}\' failed'.format(folder), level='DEBUG')
        raise Exception('Mailbox failure')
    else:
      log(' - Mailbox folder not specified', level='DEBUG')
      raise Exception('Mailbox not specified')

  def reconnect(self):
    try:
      self.imap.done()

      self.close()
      self.logout()
    except:
      pass

    self.connect()

  def update(self, folder, callback, catchup=False):
    def evaluate(start, end, callback):
      start_uid = self.num2uid(str(start).encode())
      uid_list = self.search('UID {}:*'.format(int(start_uid)))

      if uid_list:
        uid_list = [u for u in uid_list if u != start_uid]
        end = max(end, len(uid_list) + start)

      if end > start:
        log('Found {} new UID{}: {}'.format(end - start, 's' if (end - start) > 1 else '', ', '.join([u.decode('utf-8') for u in uid_list])), level='DEBUG')

        for uid in uid_list:
          email_msg = self.fetch(uid)

          if email_msg:
            try:
              timestamp = email_msg['received'].split(';')[-1].strip()
              timestamp = ''.join(timestamp.split('\r\n'))
            except:
              timestamp = datetime.datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
            self.updated = datetime.datetime.fromtimestamp(mktime_tz(parsedate_tz(timestamp)))
            save_timestamp(self.user, self.updated.strftime(TIME_FMT))

          if email_msg and callback:
            callback(self.user, email_msg)
      else:
        log('No new UID', level='DEBUG')

    try:
      total_msgs = self.select(folder)
    except Exception as e:
      log('A fatal error occured: \'{}\'. Abort.'.format(e), level='ERROR')
      return

    if catchup:
      log('Retrieving unread messages ...', level='DEBUG')

      # Fetch all unread messages since last update:
      date = self.updated.strftime("%d-%b-%Y")

      # Fetch all unread messages of past x days:
      #date = (datetime.date.today() - datetime.timedelta(x)).strftime("%d-%b-%Y")

      uid_list = self.search('SENTSINCE', date)

      # Fetch unread messages only for today:
      #today = datetime.date.today().strftime("%d-%b-%Y")
      #uid_list = self.search('ON', today)

      if uid_list:
        log(' - Found {} unread messages'.format(len(uid_list)), level='DEBUG')
        for uid in uid_list:
          email_msg = self.fetch(uid)
          callback(self.user, email_msg)
      else:
        log(' - No unread messages', level='DEBUG')

    self.isRunning = True

    while(self.isRunning):
      new_msg = False

      try:
        for num, msg in self.imap.idle():
          if msg == b'EXISTS':
            log('Size of \'{}\' has changed. {} messages (current) --> {} messages (new)'.format(folder, total_msgs, int(num)), level='DEBUG')
            counter = int(num)
            if counter > total_msgs:
              new_msg = True
              self.imap.done()
              continue

            total_msgs = counter
            log('Size of \'{}\' updated: {} messages'.format(folder, total_msgs), level='DEBUG')

      except IDLE_COMPLETE:
        if new_msg:
          evaluate(total_msgs, counter, callback)
          total_msgs = counter
          log('Size of \'{}\' updated: {} messages'.format(folder, total_msgs), level='DEBUG')
        log('Restarting IDLE ...', level='DEBUG')

      except Exception as e:
        log('Error: \'{}\'. Reconnecting to \'{}\' ...'.format(e, self.server), level='DEBUG')
        try:
          self.reconnect()
          counter = self.select(folder)
          if counter > total_msgs:
            evaluate(total_msgs, counter, callback)
          total_msgs = counter
        except Exception as e:
          log('A fatal error occured: \'{}\'. Abort.'.format(e), level='ERROR')
          break

    self.isRunning = False


def done(connection):
  if connection.state == 'IDLE':
    log('Sending \'DONE\' for {}'.format(connection.tag.decode()), level='DEBUG')
    connection.send(b'DONE' + imaplib.CRLF)


def idle(connection):
  try:
    connection.state_before_idle = connection.state
    connection.tag = connection._new_tag()

    connection.send(connection.tag + b' IDLE' + imaplib.CRLF)
    response = connection.readline().strip()

    if response.startswith(b'+'):
      log('{} IDLE started: \'{}\''.format(connection.tag.decode(), response.decode()), level='DEBUG')
    else:
      raise Exception('Failed to IDLE')

    connection.sock.setblocking(False)
    connection.state = 'IDLE'

    while connection.state == 'IDLE':
      try:
        readable = select.select([connection.sock], [], [], _socket_timeout_)[0]

        if readable:
          for response in iter(connection.readline, b''):
            response = response.strip()
            log('{} IDLE; Response: \'{}\''.format(connection.tag.decode(), response.decode()), level='DEBUG')

            if response.startswith(connection.tag + b' OK'):
              raise IDLE_COMPLETE('IDLE completed')

            elif response.startswith(b'* BYE '):
              raise IDLE_DISCONNECT('Connection closed by server')

            else:
              num, message = response.split(maxsplit=2)[1:]
              if num.isdigit():
                yield num, message

        else:
          log('{} IDLE; User defined timeout'.format(connection.tag.decode()), level='DEBUG')
          connection.done()

      except ssl.SSLError as e:
        if  e.errno == ssl.SSL_ERROR_WANT_READ:
          continue
        else:
          raise IDLE_DISCONNECT('Connection closed by server')

      except (socket_error, OSError):
        raise IDLE_TIMEOUT('Connection timed out')

      except:
        raise

  except:
    raise

  finally:
    connection.state = connection.state_before_idle
    connection.sock.setblocking(True)


#imaplib.Debug = 4
imaplib.IMAP4.idle = idle
imaplib.IMAP4.done = done


def kodi_request(host, method, params=None, port=8080, user=None, password=None):
  url  = 'http://{}:{}/jsonrpc'.format(host, port)
  headers = {'content-type': 'application/json'}
  data = {
           'jsonrpc': '2.0',
           'method': method,
           'id': 1
         }
  if params:
    data['params'] = params

  if user and password:
    auth_str = '{}:{}'.format(user, password)
    base64str = base64.b64encode(auth_str.encode()).decode()
    headers['Authorization'] = 'Basic {}'.format(base64str)

  try:
    response = requests.post(url, data=json.dumps(data), headers=headers, timeout=10)
  except:
    return False

  if response.ok:
    data = response.json()
    return (data['result'] == 'OK')
  else:
    return False


def host_is_up(host, port):
  try:
    sock = create_connection((host, port), timeout=3)
  except:
    return False

  return True


def notify(user, sender, subject):
  if not sender or not subject:
    return

  notification_title = '{} {}'.format(_notification_title_, user)
  notification_text = '{}: {} | {}: {}'.format(_msg_from_, sender, _msg_subject_, subject)

  for host in _kodi_['host']:
    if host_is_up(host, _kodi_['port']):
      log('Notfying host \'{}\''.format(host), level='DEBUG')
      kodi_request(host, 'GUI.ShowNotification', params={'title': notification_title, 'message': notification_text, 'displaytime': 2000}, port=_kodi_['port'], user=_kodi_['user'], password=_kodi_['password'])
    else:
      log('KODI host \'{}\' is down; Skip sending notification'.format(host), level='DEBUG')


def decode_safely(s, charset='ascii'):
  if not isinstance(s, bytes):
    return s

  try:
    return s.decode(charset or 'ascii', 'replace')
  except:
    return s.decode('ascii', 'replace')


def decode_rfc2047_header(h):
  return ' '.join(decode_safely(s, charset) for s, charset in decode_header(h))
  #return ' '.join(decode_safely(s, charset).replace('\r\n', '') for s, charset in decode_header(h))

def getmailaddresses(msg, field):
  addresses = []

  for name, address in getaddresses(msg.get_all(field, [])):
    if name:
      name = decode_rfc2047_header(name)
    elif address:
      name = address
    else:
      name, address = ('', '')
    addresses.append((name, address))
  return addresses


def show(user, message):
  if not message:
    return

  msg = {
    'from': [],
    'replyto': [],
    'to': [],
    'cc': [],
    'subject': '',
    'sent': '',
    'rcvd': '',
    'text': '',
    'html': '',
    'attach': []
  }

  try:
    msg['from']    = getmailaddresses(message, 'from')
    msg['replyto'] = getmailaddresses(message, 'reply-to')
    msg['to']      = getmailaddresses(message, 'to')
    msg['cc']      = getmailaddresses(message, 'cc')

    #msg['subject'] = decode_rfc2047_header(message['Subject'].replace('\r\n', ''))
    msg['subject'] = message['Subject']
    msg['subject'] = ''.join(msg['subject'].split('\r\n'))
    msg['subject'] = decode_rfc2047_header(msg['subject'])

    msg['sent'] = message['date']
    msg['sent'] = ''.join(msg['sent'].split('\r\n'))
    msg['sent'] = datetime.datetime.fromtimestamp(mktime_tz(parsedate_tz(msg['sent'])))

    try:
      msg['rcvd'] = message['received'].split(';')[-1].strip()
      msg['rcvd'] = ''.join(msg['rcvd'].split('\r\n'))
    except:
      msg['rcvd'] = datetime.datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
    msg['rcvd'] = datetime.datetime.fromtimestamp(mktime_tz(parsedate_tz(msg['rcvd'])))

  except Exception as e:
    log('Error: \'{}\' while processing data from message header'.format(e), level='ERROR')
    return

  #from_name, from_address = parseaddr(message['From'])
  from_name, from_address = msg['from'][0]
  if not from_address:
    log('Could not parse sender\'s mail address from header', level='ERROR')
    return

  notify(user, from_name if from_name else from_address, msg['subject'])

  log('New Message:')
  log('================================================================================')
  log('From: {}'.format(', '.join('{} <{}>'.format(n, a) for n, a in msg['from'])))
  if msg['replyto']:
    log('Reply-to: {}'.format(', '.join('{} <{}>'.format(n, a) for n, a in msg['replyto'])))
  log('To: {}'.format(', '.join('{} <{}>'.format(n, a) for n, a in msg['to'])))
  if msg['cc']:
    log('Cc: {}'.format(', '.join('{} <{}>'.format(n, a) for n, a in msg['cc'])))
  log('Sent: {}'.format(msg['sent'].strftime(TIME_FMT)))
  log('Received: {}'.format(msg['rcvd'].strftime(TIME_FMT)))
  log('Subject: {}'.format(msg['subject']))
  log('================================================================================')

  try:
    fileName = ''

    for part in message.walk():
      log('Content-Type:        {}'.format(part.get_content_type()), level='DEBUG')
      log('Content-Disposition: {}'.format(part.get('Content-Disposition')), level='DEBUG')

      if part.get_content_maintype() == 'multipart':
        continue

      #if part.get('Content-Disposition') is None:
      if part.get('Content-Disposition') is None or 'attachment' not in part.get('Content-Disposition'):
        if part.get_content_type() == 'text/plain':
          charset = part.get_content_charset('iso-8859-1')
          msg['text'] = part.get_payload(decode=True).decode(charset, 'replace')
          #log('{}'.format(msg['text']), level='DEBUG')
          log('Mesagge has text body of {} bytes'.format(len(msg['text'])), level='DEBUG')
        if part.get_content_type() == 'text/html':
          #msg['html'] = part.get_payload()
          charset = part.get_content_charset('iso-8859-1')
          msg['html'] = part.get_payload(decode=True).decode(charset, 'replace') #.decode('raw-unicode-escape')
          log('Mesagge has html body of {} bytes'.format(len(msg['html'])), level='DEBUG')
          if not msg['text']:
            msg['text'] = html2text(msg['html'])
            #log('{}'.format(msg['text']), level='DEBUG')
            log('Mesagge has text body converted from html body of {} bytes'.format(len(msg['text'])), level='DEBUG')
        #if 'filename' not in part.get('Content-Disposition'):
        continue

      fileName, charset = decode_header(part.get_filename() or '')[0]
      if isinstance(fileName, bytes):
        fileName = fileName.decode(charset or 'ascii')

      if bool(fileName):
        fileExt = os.path.splitext(fileName)[-1]
        log('Processing attachment \'{}\''.format(fileName), level='DEBUG')

        msg['attach'].append(fileName)

        if _attachments_['from'] != ['*'] and (not any(n in from_name.lower() for n in _attachments_['from']) and not any(a in from_address.lower() for a in _attachments_['from'])):
          log('Attachment sender \'{} ({})\' is not configured for download'.format(from_name or 'unknown', from_address), level='DEBUG')
          break

        dnldFolder = os.path.join(_attachments_['path'], from_name if from_name else from_address)

        if _attachments_['type'] != ['*'] and not any(e in fileExt.lower() for e in _attachments_['type']):
          log('Attachment type \'{}\' is not configured for download'.format(fileExt), level='DEBUG')
          continue

        filePath = os.path.join(dnldFolder, fileName)

        if not os.path.isfile(filePath):
          if not os.path.isdir(dnldFolder):
            try:
              os.makedirs(dnldFolder)
            except OSError:
              log('Creation of download folder \'{}\' failed'.format(dnldFolder), level='ERROR')
              return
            else:
              log('Successfully created download folder \'{}\''.format(dnldFolder), level='DEBUG')

          with open(filePath, 'wb') as fp:
            fp.write(part.get_payload(decode=True))
          log('Attachment \'{}\' saved in folder \'{}\''.format(fileName, dnldFolder))
        else:
          log('Attachment \'{}\' already exists in folder \'{}\''.format(fileName, dnldFolder))

    msg['from']    = ', '.join('{} <{}>'.format(n, a) for n, a in msg['from'])
    msg['replyto'] = ', '.join('{} <{}>'.format(n, a) for n, a in msg['replyto'])
    msg['to']      = ', '.join('{} <{}>'.format(n, a) for n, a in msg['to'])
    msg['cc']      = ', '.join('{} <{}>'.format(n, a) for n, a in msg['cc'])
    msg['sent']    = msg['sent'].strftime(TIME_FMT)
    msg['rcvd']    = msg['rcvd'].strftime(TIME_FMT)
    msg['attach']  = ', '.join(msg['attach'])

    #mydb.save([msg])

  except Exception as e:
    log('Unexpected exception: \'{}\' while saving attachment \'{}\''.format(e, fileName), level='ERROR')
    pass


if __name__ == '__main__':
  global _config_file_, _log_file_, _debug_, _notification_title_, _msg_from_, _msg_subject_, _socket_timeout_

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host when a new email is received')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  parser.add_argument('-u', '--update', dest='update', action='store_true', help="Show messages since last recorded update (Default: False)")
  parser.add_argument('-l', '--logfile', dest='log_file', default=None, help="Path to log file (Default: None=stdout)")
  parser.add_argument('-t', '--timeout', dest='timeout', default=840, help="Connection Timeout (Default: 840 sec. = 14 min.)")
  parser.add_argument('-c', '--config', dest='config_file', default=os.path.splitext(os.path.basename(__file__))[0] + '.ini', help="Path to config file (Default: <Script Name>.ini)")

  args = parser.parse_args()

  _config_file_ = args.config_file
  _log_file_ = args.log_file
  _debug_ = args.debug
  _socket_timeout_ = int(args.timeout)

  _db_file_ = os.path.splitext(os.path.basename(__file__))[0] + '.db'

  if _log_file_:
    logging.basicConfig(filename=_log_file_, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='w', level=logging.DEBUG)

  log('Configured options:', level='DEBUG')
  log(' - Output Debug:  {}'.format(_debug_), level='DEBUG')
  log(' - Log File:      {}'.format(_log_file_), level='DEBUG')
  log(' - Conn. Timeout: {} sec.'.format(_socket_timeout_), level='DEBUG')
  log(' - Config. File:  {}'.format(_config_file_), level='DEBUG')

  log('Reading configuration ...', level='DEBUG')
  if not read_config():
    sys.exit(1)

  log(' - Configuration: OK', level='DEBUG')
  log(' - Accounts:      {}'.format(', '.join([account['name'] for account in _accounts_])), level='DEBUG')
  log(' - Customization: \'New Message for\': \'{}\' | \'From\': \'{}\' | \'Subject\': \'{}\''.format(_notification_title_, _msg_from_, _msg_subject_), level='DEBUG')
  log(' - Attachments of types \'{}\' sent from \'{}\' will be saved in \'{}\''.format(', '.join(_attachments_['type']), ', '.join(_attachments_['from']), _attachments_['path']), level='DEBUG')

  Failure = False

  #mydb = Database(_db_file_)

  ##accounts = [ account for account in _accounts_ ]
  ##for account in accounts:
  for account in _accounts_:
    log('Processing mail account \'{}\' ...'.format(account['name']), level='DEBUG')
    try:
      account['connection'] = MailBox(account['server'], account['user'], account['password'], updated=account['updated'], authmethod=account['authmethod'], **account['oauth2'])
    except Exception as e:
      log(' - An error occured while initializing account \'{}\': \'{}\'. Skip.'.format(account['name'], e), level='ERROR')
      ### Remove failed account from list
      ##_accounts_.remove(account)
      continue

    account['connection'].monitor('Inbox', callback=show, catchup=args.update)
    sleep(1)

  while(not Failure):
    try:
      # Check if processes are still alive:
      for account in _accounts_:
        if 'connection' in account and not account['connection'].is_idle():
          log('Idle process appears to be dead. Reconnecting to \'{}\'.'.format(account['server']), level='DEBUG')
          try:
            account['connection'].connect()
          except Exception as e:
            log('A fatal error occured while updating account \'{}\': \'{}\'. Abort.'.format(account['name'], e), level='ERROR')
            Failure = True
            break
          account['connection'].monitor('Inbox', callback=show)
        sleep(1)

    except (KeyboardInterrupt, SystemExit):
      # Overwrite output of '^C' in case of KeyboardInterrupt:
      sys.stderr.write('\r')
      log('Abort requested by user or system', level='DEBUG')
      break

    # Handle any unexpected error:
    except Exception as e:
      log('An unexpected error occured: \'{}\'. Abort.'.format(e), level='ERROR')
      break

  for account in _accounts_:
    if 'connection' in account:
      account['connection'].close()

  status = 1 if Failure else 0
  sys.exit(status)
