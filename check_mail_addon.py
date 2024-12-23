#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import email
import requests
import json
import html.parser
import base64

import logging
import configparser
import os
import sys

import argparse
import signal
import sqlite3

from socket import error as socket_error, create_connection as create_connection
from datetime import datetime, timedelta, date

from html2text import html2text

from multiprocessing import *
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime, parsedate_tz, mktime_tz, getaddresses

from time import sleep

from utils.oauth2lib import *
from utils.imapidle import *

# Valid Email 2nd lvel Domains
MICROSOFT_DOMAINS = ['hotmail', 'outlook', 'live', 'msn']
GOOGLE_DOMAINS = ['gmail', 'googlemail', 'google']

# Time format
TIME_FMT = '%d.%m.%Y %H:%M:%S'

#logging.getLogger('requests.packages.urllib3').propagate = False
logging.getLogger('urllib3').setLevel(logging.WARNING)


def log(message, level='INFO'):
  timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')
  if LOG_FILE:
    if level == 'DEBUG' and __DEBUG__:
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
     if level != 'DEBUG' or __DEBUG__:
       print('{} [{:^5s}]: {}'.format(timestamp, level,  message))


def debug(message):
  log(message, level='DEBUG')


def device_auth_get(verification_url, user_code):
  log(' - Sending OAuth2 notification message to kodi host(s) {}'.format(', '.join(KODI['host'])), level='DEBUG')
  for host in KODI['host']:
    if host_is_up(host, KODI['port']):
      kodi_request(host, 'GUI.ShowNotification', params={'title': LOCALE['auth_required'],
        'message': LOCALE['device_auth_message'].format(verification_url, user_code),
        'displaytime': 10000},
        port=KODI['port'], user=KODI['user'], password=KODI['password'])
    else:
      log(' - Kodi host {} is down or unreachable'.format(host), level='DEBUG')

  if MAILER:
    log(' - Sending OAuth2 notification message to {}'.format(', '.join(OAUTH2['notify'])), level='DEBUG')
    MAILER.send(OAUTH2['notify'], LOCALE['auth_required'],
      LOCALE['device_auth_message_text'].format(verification_url, user_code),
      html=LOCALE['device_auth_message_html'].format(verification_url, user_code))
  #else:
  #  print('Enter this url in a browser and enter the code {} to authorize your device to receive emails:\n{}'.format(user_code, verification_url)) # --> log?

  return OAUTH2['wait']


def auth_get(authorization_url, redirect_uri):
  log(' - Sending OAuth2 notification message to kodi host(s) {}'.format(', '.join(KODI['host'])), level='DEBUG')
  for host in KODI['host']:
    if host_is_up(host, KODI['port']):
      kodi_request(host, 'GUI.ShowNotification', params={'title': LOCALE['auth_required'],
       'message': LOCALE['auth_message'].format(authorization_url),
       'displaytime': 10000},
       port=KODI['port'], user=KODI['user'], password=KODI['password'])
    else:
      log(' - Kodi host {} is down or unreachable'.format(host), level='DEBUG')


  if MAILER:
    log(' - Sending OAuth2 notification message to {}'.format(', '.join(OAUTH2['notify'])), level='DEBUG')
    MAILER.send(OAUTH2['notify'], LOCALE['auth_required'],
      LOCALE['auth_message_text'].format(authorization_url),
      html=LOCALE['auth_message_html'].format(authorization_url))

    s = redirect_uri.rsplit(':', maxsplit=1)[1].strip('/')
    redirect_port = int(s) if s.isdigit() else 443

    log(' - Running local web server on port {} ...'.format(redirect_port), level='DEBUG')
    authorization_code = run_server(redirect_port, timeout=OAUTH2['wait'])
    log(' - Local web server stopped: authorization code received', level='DEBUG')
  #else:
  #  print('Enter this url in a browser to authorize your application to receive emails:\n{}'.format(authorization_url)) # --> log?
  #  redirect_url = input('Paste the full redirect URL here: ')

  #  query = parse_qs(urlparse(redirect_url).query)
  #  authorization_code = queries.get('code')

  return authorization_code


class Database(object):
  # Usage:
  # mydb = Database('mail.db')
  # mydb.save(list_of_emails_as_dict)

  def __init__(self, path_to_db):
    self.connection = sqlite3.connect(path_to_db)
    self.cursor = self.connection.cursor()

    log('Creating database in {} ...'.format(path_to_db), level='DEBUG')
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
      log('Database already exists.', level='ERROR')

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


def e_decode(e):
  try:
    return e.args[0].decode()
  except:
    return str(e)


def is_https(u):
  try:
    return u.lower().startswith('https://')
  except:
    return False


def is_mailaddress(a):
  try:
    t = a.split('@')[1].split('.')[1]
    return True
  except:
    return False


def is_hostname(h):
  try:
    t = h.split('.')[2]
    return True
  except:
    return False


def is_int(n):
  try:
    t = int(n)
    return True
  except:
    return False


def is_method(f):
  try:
    return callable(f)
  except:
    return False


def save_value(section, option, value):
  try:
    config = configparser.ConfigParser(delimiters=('='))

    config.read([os.path.abspath(CONFIG_FILE)])

    if not config.has_section(section):
      log(' - There\'s no section [{}] in file {}'.format(section, CONFIG_FILE), level='ERROR')
      return False

    if value is False:
      if config.has_option(section, option):
        config.remove_option(section, option)
    else:
      config.set(section, option, value)

    with open(os.path.abspath(CONFIG_FILE), 'w') as configfile:
      config.write(configfile, space_around_delimiters=True)

  except Exception as e:
    log(' - Updating option \'{}\' in section [{}] of file {} failed: {}'.format(option, section, CONFIG_FILE, str(e)), level='ERROR')
    return False

  if value is False:
    log(' - Option \'{}\' in section [{}] of file {} removed'.format(option, section, CONFIG_FILE), level='DEBUG')
  else:
    log(' - Option \'{}\' in section [{}] of file {} updated'.format(option, section, CONFIG_FILE), level='DEBUG')

  return True


def save_timestamp(user, timestamp):
  section = user

  for account in ACCOUNTS:
    if account['user'] == user:
      section = account['name']

  return save_value(section, 'updated', timestamp)


def save_token(user, token):
  section = user

  for account in ACCOUNTS:
    if account['user'] == user:
      section = account['name']

  return save_value(section, 'refresh_token', token)


def remove_token(user):
  section = user

  for account in ACCOUNTS:
    if account['user'] == user:
      section = account['name']

  return save_value(section, 'refresh_token', False)


def read_section(config, section, options, my_dict):

  for option, value in options.items():
    if value.get('type') == 'int':
      if config.has_option(section, option):
        my_dict[option] = int(config.get(section, option))
      else:
        my_dict[option] = int(value.get('default', 0))

    elif value.get('type') == 'str':
      if config.has_option(section, option):
        my_dict[option] = config.get(section, option) #.lower()
      else:
        my_dict[option] = value.get('default', '')

    elif value.get('type') == 'list':
      if config.has_option(section, option):
        my_dict[option] = [p.strip(' "\'').lower() for p in config.get(section, option).split(',')]
      else:
        my_dict[option] = value.get('default', [])

    elif value.get('type') == 'csv':
      if config.has_option(section, option):
        my_dict[option] = [int(p) for p in config.get(section, option).split(',')]
      else:
        my_dict[option] = value.get('default', [])

    elif value.get('type') == 'bool':
      if config.has_option(section, option):
        my_dict[option] = (config.get(section, option) == 'yes')
      else:
        my_dict[option] = bool(value.get('default', 0))

    elif value.get('type') == 'date':
      if config.has_option(section, option):
        my_dict[option] = datetime.strptime(config.get(section, option), TIME_FMT)
      else:
        my_dict[option] = value.get('default', None)

    if value.get('mandatory') and not my_dict[option]:
      log('Missing mandatory config value; section: [{}], option: {}'. format(section, option), level='ERROR')
      raise Exception('Missing value')

    if value.get('test') and my_dict[option]:
      if value['type'] in ['list', 'csv']:
        test = my_dict[option]
      else:
        test = [my_dict[option]]

      for element in test:
        if element and not value['test'](element):
          log('Invalid config value; section: [{}], option: {}, value: {}'. format(section, option, config.get(section, option)), level='ERROR')
          raise Exception('Invalid value')


def read_config():
  global KODI, ACCOUNTS, ATTACHMENTS, LOCALE, MAILER, OAUTH2

  if not os.path.exists(CONFIG_FILE):
    log('Missíng configuration file {}'.format(CONFIG_FILE), level='ERROR')
    raise Exception('Missing config file')

  try:
    config = configparser.ConfigParser()
    config.read([os.path.abspath(CONFIG_FILE)])

    ACCOUNTS = []
    for section_name in config.sections():
      if is_mailaddress(section_name):
        account = {'name': section_name.strip()}
        ACCOUNTS.append(account)
        #ACCOUNTS.append({'name': section_name})

    OAUTH2 = {}
    oauth2_options = {
      'notify': {'type': 'list', 'test': is_mailaddress},
      'wait':   {'type': 'int', 'default': 300}
      }
    read_section(config, 'OAuth2', oauth2_options, OAUTH2)

    LOCALE = {}
    locale_options = {
      'new_message_for':          {'type': 'str', 'default': 'New message for'},
      'from':                     {'type': 'str', 'default': 'From'},
      'subject':                  {'type': 'str', 'default': 'Subject'},
      'auth_required':            {'type': 'str', 'default': 'Authorization required'},
      'auth_message':             {'type': 'str', 'default': 'Use a web browser to open the page {} to authorize your application to read email messages.'},
      'device_auth_message':      {'type': 'str', 'default': 'Use a web browser to open the page {} and enter the code {} to authorize your device.'},
      'auth_message_text':        {'type': 'str', 'default': AUTH_TEXT},
      'device_auth_message_text': {'type': 'str', 'default': DEVICE_AUTH_TEXT},
      'auth_message_html':        {'type': 'str', 'default': AUTH_HTML},
      'device_auth_message_html': {'type': 'str', 'default': DEVICE_AUTH_HTML},
      }
    read_section(config, 'Customization', locale_options, LOCALE)

    KODI = {}
    kodi_options = {
      'host': {'type': 'list', 'test': is_hostname},
      'port': {'type': 'int', 'test': is_int, 'default': 8080},
      'user': {'type': 'str', 'default': 'kodi'},
      'password': {'type': 'str'}
      }
    read_section(config, 'KODI JSON-RPC', kodi_options, KODI)

    ATTACHMENTS = {}
    attachments_options = {
      'path': {'type': 'str'},
      'type': {'type': 'list'},
      'from': {'type': 'list'}
      }
    read_section(config, 'Attachments', attachments_options, ATTACHMENTS)

    SMTP = []
    for account in ACCOUNTS:
      account_options = {
        'imap_host': {'type': 'str',  'test': is_hostname, 'mandatory': True},
        'imap_port': {'type': 'int',  'test': is_int, 'default': 993},
        'imap_ssl':  {'type': 'bool', 'default': True},
        'smtp_host': {'type': 'str',  'test': is_hostname},
        'smtp_port': {'type': 'int',  'test': is_int, 'default': 587},
        'user':      {'type': 'str',  'default': account['name'], 'mandatory': True},
        'password':  {'type': 'str'},
        'updated':   {'type': 'date'},
        }
      read_section(config, account['name'], account_options, account)

      if account['smtp_host']:
        SMTP.append(account)

      account['oauth2_parms'] = {}
      if config.has_option(account['name'], 'client_id'):
        oauth2_parms = {
          'client_id':     {'type': 'str', 'mandatory': True},
          'client_secret': {'type': 'str'},
          'refresh_token': {'type': 'str'},
          'tenant_id':     {'type': 'str', 'default': 'consumers' if account['name'].split('@')[1].split('.')[0] in MICROSOFT_DOMAINS else ''},
          'redirect_uri':  {'type': 'str', 'test': is_https},
          }
        read_section(config, account['name'], oauth2_parms, account['oauth2_parms'])

        if config.has_option(account['name'], 'redirect_uri'):
          if 'auth_get' in globals():
            account['oauth2_parms']['callback'] = auth_get
        else:
          if 'device_auth_get' in globals():
            account['oauth2_parms']['callback'] = device_auth_get

    if SMTP:
      log(' - SMTP data found', level='DEBUG')
      MAILER = Mailer(SMTP[0]['smtp_host'], SMTP[0]['smtp_port'], SMTP[0]['user'], SMTP[0]['password'])
    else:
      log(' - No SMTP data', level='DEBUG')
      MAILER = None

  except:
    raise


class MailBox(object):
  def __init__(self, server, user, password, port=None, ssl=True, updated=None, **oauth2_parms):
    self.server   = server
    self.user     = user
    self.password = password
    self.port     = port
    self.ssl      = ssl

    if oauth2_parms:
      for attr in ['client_id', 'client_secret', 'refresh_token', 'redirect_uri', 'callback', 'tenant_id']:
        setattr(self, attr, oauth2_parms.get(attr))

    if updated:
      log(' - Last message received on {}'.format(updated.strftime('%B %-d, %Y at %-H:%M')), level='DEBUG')
      self.updated = updated
    else:
      log(' - Date of last received message is unknown', level='DEBUG')
      self.updated = datetime.now().replace(second=0, microsecond=0)

    try:
      self.connect()
    except:
      self.close()
      raise


  def monitor(self, folder, callback=None, catchup=False):
    self.isRunning = False
    self.mon = Process(target=self.update, args=(folder, callback, catchup,))
    self.mon.start()


  def is_idle(self):
    return self.mon.is_alive() # and self.isRunning


  def close(self, terminate=True):
    log(' - Closing connection to {} ...'.format(self.server), level='DEBUG')

    if hasattr(self, 'imap') and self.imap:
      try:
        self.imap.done(debug=debug)
        self.imap.close()

      except Exception as e:
        pass

      finally:
        self.imap.logout()

    if terminate:
      try:
        self.isRunning = False
        if hasattr(self, 'mon') and self.mon:
          self.mon.terminate()

      except Exception as e:
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
      email_msg = email.message_from_bytes(data[0][1])
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
    if not self.port:
      self.port = 993 if self.ssl else 143

    access_token = ''
    refresh_token = ''

    try:
      if hasattr(self, 'client_id') and self.client_id:
        log(' - Auth. method: OAuth2', level='DEBUG')

        if self.refresh_token:
          log(' - Requesting access token (using refresh token)', level='DEBUG')
          access_token, refresh_token = auth_refresh(self.client_id, self.client_secret, self.refresh_token, tenant_id=self.tenant_id)

        elif self.redirect_uri:
          log(' - Requesting access token (application authorization required)', level='DEBUG')

          if not self.callback:
            raise Exception('OAuth2 callback not set')

          authorization_code = auth_code(self.client_id, self.redirect_uri, offline=True, callback=self.callback, tenant_id=self.tenant_id)
          if authorization_code:
            access_token, refresh_token = auth_request(self.client_id, self.client_secret, self.redirect_uri, authorization_code, tenant_id=self.tenant_id)
          else:
            raise Exception('No OAuth2 authorization code')

        else:
          log(' - Requesting access token (device authorization required)', level='DEBUG')

          if not self.callback:
            raise Exception('OAuth2 callback not set')

          device_code, expires_in, interval = device_auth_code(self.client_id, callback=self.callback, tenant_id=self.tenant_id)
          if device_code:
            access_token, refresh_token = device_auth_request(self.client_id, self.client_secret, device_code, expires_in=expires_in, interval=interval, tenant_id=self.tenant_id)
          else:
            raise Exception('No OAuth2 device code')

        if refresh_token:
          log(' - New refresh token received', level='DEBUG')
          self.refresh_token = refresh_token
          save_token(self.user, self.refresh_token)

      else:
        log(' - Auth. method: username, password', level='DEBUG')

      if self.ssl:
        self.imap = imaplib.IMAP4_SSL(self.server, self.port)
      else:
        self.imap = imaplib.IMAP4(self.server, self.port)

      log(' - Connected to {}'.format(self.server), level='DEBUG')

      #self.imap.debug = 4 # 10

      if access_token:
        auth_string = generate_xoauth2(self.user, access_token)
        self.imap.authenticate('XOAUTH2', lambda x: auth_string.encode())

      elif self.password:
        self.imap.login(self.user, self.password)

      else:
         raise Exception('Insufficient login/auth data')

    except socket_error as e:
      log(' - Connection to {}:{} failed: {}'.format(self.server, self.port, e_decode(e)), level='ERROR')
      raise IMAP_CONNECT_ERROR(e_decode(e))

    except Exception as e:
      log(' - Login of user {} failed: {}'.format(self.user, e_decode(e)), level='ERROR')

      # Token expired, revoked or authentication failed due to invalid credentials
      if hasattr(self, 'refresh_token') and self.refresh_token:
        log(' - Removing invalid token from configuration ...', level='DEBUG')
        self.refresh_token = ''
        remove_token(self.user)

        raise OAUTH2_TOKEN_ERROR(e_decode(e))

      raise IMAP_AUTH_ERROR(e_decode(e))

    log(' - User {} logged in'.format(self.user), level='DEBUG')


  def select(self, folder):
    if folder:
      status, data = self.imap.select(folder, readonly=True)
      if status == 'OK':
        log(' - {}: {} messages'.format(folder, int(data[0])), level='DEBUG')
        return int(data[0])
      else:
        log(' - Selection of {} failed'.format(folder), level='DEBUG')
        raise Exception('Mailbox folder selection failed')
    else:
      log(' - Mailbox folder unnamed', level='DEBUG')
      raise Exception('Mailbox folder unnamed')


  def reconnect(self, terminate=True):
    self.close(terminate)
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
              timestamp = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
            self.updated = datetime.fromtimestamp(mktime_tz(parsedate_tz(timestamp)))
            save_timestamp(self.user, self.updated.strftime(TIME_FMT))

          if email_msg and callback:
            callback(self.user, email_msg)
      else:
        log('No new UID', level='DEBUG')


    try:
      total_msgs = self.select(folder)

    except Exception as e:
      log('Error: {}, {}'.format(type(e).__name__, str(e)), level='ERROR')
      return

    if catchup:
      log('Retrieving unread messages ...', level='DEBUG')

      # Fetch all unread messages since last update:
      date = self.updated.strftime("%d-%b-%Y")

      # Fetch all unread messages of past x days:
      #date = (date.today() - timedelta(x)).strftime("%d-%b-%Y")

      uid_list = self.search('SENTSINCE', date)

      # Fetch unread messages only for today:
      #today = date.today().strftime("%d-%b-%Y")
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
      err = None

      try:
        for num, msg in self.imap.idle(timeout=IDLE_TIMEOUT, debug=debug):
          if msg == b'EXISTS':
            log('{} changed: {} messages (current) --> {} messages (new)'.format(folder, total_msgs, int(num)), level='DEBUG')

            counter = int(num)
            if counter > total_msgs:
              new_msg = True
              self.imap.done(debug=debug)
              continue

            total_msgs = counter
            log('{} counter updated: {} messages'.format(folder, total_msgs), level='DEBUG')

      except IDLE_COMPLETE:
        try:
          if new_msg:
            evaluate(total_msgs, counter, callback)

            total_msgs = counter
            log('{} counter updated: {} messages'.format(folder, total_msgs), level='DEBUG')

          log('Restarting IDLE ...', level='DEBUG')

        except Exception as e:
          err = e

      except Exception as e:
        err = e

      finally:
        try:
          if err:
            log('Error: {}, {}. Reconnecting to {} ...'.format(type(err).__name__, str(err), self.server), level='ERROR')

            self.reconnect(terminate=False)

            counter = self.select(folder)
            if counter > total_msgs:
              evaluate(total_msgs, counter, callback)

            total_msgs = counter

        except Exception as e:
          if 'expired' in str(e) or 'revoked' in str(e):
            log('Token expired or revoked: {}'.format(str(e)), level='ERROR')
            if hasattr(self, 'refresh_token') and self.refresh_token:
              self.refresh_token = ''
              remove_token(self.user)

          else:
            log('Error: {}, {}'.format(type(e).__name__, str(e)), level='ERROR')

          break # --> will break out of the loop and quit update, #raise # --> will raise Exeption to main and terminate program

    self.isRunning = False


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
    r = requests.post(url, data=json.dumps(data), headers=headers, timeout=10)
  except:
    return False

  if r.ok:
    response = r.json()
    return (response['result'] == 'OK')
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

  notification_title = '{} {}'.format(LOCALE['new_message_for'], user)
  notification_text = '{}: {} | {}: {}'.format(LOCALE['from'], sender, LOCALE['subject'], subject)

  for host in KODI['host']:
    if host_is_up(host, KODI['port']):
      log('Notfying host {}'.format(host), level='DEBUG')
      kodi_request(host, 'GUI.ShowNotification', params={'title': notification_title, 'message': notification_text, 'displaytime': 2000}, port=KODI['port'], user=KODI['user'], password=KODI['password'])
    else:
      log('KODI host {} is down; Skip sending notification'.format(host), level='DEBUG')


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

  try:
    msg = {
      'from':    ', '.join('{} <{}>'.format(n, a) for n, a in getmailaddresses(message, 'from')),
      'replyto': ', '.join('{} <{}>'.format(n, a) for n, a in getmailaddresses(message, 'reply-to')),
      'to':      ', '.join('{} <{}>'.format(n, a) for n, a in getmailaddresses(message, 'to')),
      'cc':      ', '.join('{} <{}>'.format(n, a) for n, a in getmailaddresses(message, 'cc')),
      'subject': decode_rfc2047_header(''.join(message['Subject'].split('\r\n'))),
      'sent':    datetime.fromtimestamp(mktime_tz(parsedate_tz(''.join(message['date'].split('\r\n'))))).strftime(TIME_FMT),
      'attach': []
    }

    try:
      msg['rcvd'] = ''.join(message['received'].split(';')[-1].strip().split('\r\n'))
    except:
      msg['rcvd'] = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
    msg['rcvd'] = datetime.fromtimestamp(mktime_tz(parsedate_tz(msg['rcvd']))).strftime(TIME_FMT)

  except Exception as e:
    log('Error while processing message header: {}'.format(str(e)), level='ERROR')
    return

  from_name, from_address = (x.strip('<>') for x in msg['from'].split(',')[0].rsplit(maxsplit=1))
  if not from_address:
    log('Could not parse sender\'s mail address from header', level='ERROR')
    return

  notify(user, from_name if from_name else from_address, msg['subject'])

  log('New Message:')

  fileName = ''

  for part in message.walk():
    log('Content-Type:        {}'.format(part.get_content_type()), level='DEBUG')
    log('Content-Disposition: {}'.format(part.get('Content-Disposition')), level='DEBUG')

    if part.get_content_maintype() == 'multipart':
      continue

    try:
      if part.get('Content-Disposition') is None or 'attachment' not in part.get('Content-Disposition'):
        if part.get_content_type() == 'text/plain':
          charset = part.get_content_charset('iso-8859-1')
          msg['text'] = part.get_payload(decode=True).decode(charset, 'replace')
          log('Message text body: {} bytes'.format(len(msg['text'])), level='DEBUG')

        if part.get_content_type() == 'text/html':
          charset = part.get_content_charset('iso-8859-1')
          msg['html'] = part.get_payload(decode=True).decode(charset, 'replace') #.decode('raw-unicode-escape')
          log('Message html body: {} bytes'.format(len(msg['html'])), level='DEBUG')
          if not msg.get('text'):
            msg['text'] = html2text(msg['html'])
            log('Message text body: {} bytes (converted from html)'.format(len(msg['text'])), level='DEBUG')

        continue

    except Exception as e:
      log('Unexpected error while processing message part {}: {}'.format(part.get_content_type(), str(e)), level='ERROR')
      #break
      continue

    try:
      fileName, charset = decode_header(part.get_filename() or '')[0]
      if isinstance(fileName, bytes):
        fileName = fileName.decode(charset or 'ascii')

      if bool(fileName):
        fileExt = os.path.splitext(fileName)[-1]
        log('Processing attachment {}'.format(fileName), level='DEBUG')

        msg['attach'].append(fileName)

        if ATTACHMENTS['from'] != ['*'] and (not any(n in from_name.lower() for n in ATTACHMENTS['from']) and not any(a in from_address.lower() for a in ATTACHMENTS['from'])):
          log('Attachements sent from \'{} ({})\' not configured for saving'.format(from_name or 'unknown', from_address), level='DEBUG')
          break

        dnldFolder = os.path.join(ATTACHMENTS['path'], from_name if from_name else from_address)

        if ATTACHMENTS['type'] != ['*'] and not any(e in fileExt.lower() for e in ATTACHMENTS['type']):
          log('Attachments of type \'{}\' not configured for saving'.format(fileExt), level='DEBUG')
          continue

        filePath = os.path.join(dnldFolder, fileName)

        if not os.path.isfile(filePath):
          if not os.path.isdir(dnldFolder):
            try:
              os.makedirs(dnldFolder)
            except OSError:
              log('Error: Creation of download folder {} failed'.format(dnldFolder), level='ERROR')
              return
            else:
              log('Successfully created download folder {}'.format(dnldFolder), level='DEBUG')

          with open(filePath, 'wb') as fp:
            fp.write(part.get_payload(decode=True))
          log('Attachment {} saved in folder {}'.format(fileName, dnldFolder), level='DEBUG')
        else:
          log('Attachment {} already exists in folder {}'.format(fileName, dnldFolder), level='DEBUG')

    except Exception as e:
      log('Unexpected error while processing attachment {}: {}, {}'.format(fileName, type(e).__name__, str(e)), level='ERROR')
      continue

  msg['attach']  = ', '.join(msg['attach'])

  log('================================================================================')
  log('From:        {}'.format(msg['from']))
  if msg['replyto']:
    log('Reply-to:    {}'.format(msg['replyto']))
  log('To:          {}'.format(msg['to']))
  if msg['cc']:
    log('Cc:          {}'.format(msg['cc']))
  log('Sent:        {}'.format(msg['sent']))
  log('Received:    {}'.format(msg['rcvd']))
  log('Subject:     {}'.format(msg['subject']))
  if msg['attach']:
    log('Attachments: {}'.format(msg['attach']))
  log('================================================================================')

  #mydb.save([msg])


if __name__ == '__main__':
  global CONFIG_FILE, LOG_FILE, IDLE_TIMEOUT, __DEBUG__

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host when a new email is received')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  parser.add_argument('-u', '--update', dest='update', action='store_true', help="Show messages since last recorded update (Default: False)")
  parser.add_argument('-l', '--logfile', dest='log_file', default=None, help="Path to log file (Default: None=stdout)")
  parser.add_argument('-t', '--timeout', dest='timeout', default=840, help="Connection Timeout (Default: 840 sec. = 14 min.)")
  parser.add_argument('-c', '--config', dest='config_file', default=os.path.splitext(os.path.basename(__file__))[0] + '.ini', help="Path to config file (Default: <Script Name>.ini)")

  args = parser.parse_args()

  CONFIG_FILE  = args.config_file
  LOG_FILE     = args.log_file
  IDLE_TIMEOUT = int(args.timeout)
  __DEBUG__    = args.debug

  DB_FILE = os.path.splitext(os.path.basename(__file__))[0] + '.db'

  if LOG_FILE:
    logging.basicConfig(filename=LOG_FILE, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='w', level=logging.DEBUG)

  log('Configured options:', level='DEBUG')
  log(' - Output Debug:  {}'.format(__DEBUG__), level='DEBUG')
  log(' - Log File:      {}'.format(LOG_FILE), level='DEBUG')
  log(' - IDLE Timeout:  {} sec.'.format(IDLE_TIMEOUT), level='DEBUG')
  log(' - Config. File:  {}'.format(CONFIG_FILE), level='DEBUG')

  try:
    log('Reading configuration from file {} ...'.format(CONFIG_FILE), level='DEBUG')
    read_config()
  except Exception as e:
    log('Configuration failed with error: {}. Abort'.format(str(e)), level='ERROR')
    sys.exit(1)

  log(' - Configuration successful', level='DEBUG')
  log(' - Accounts:      {}'.format(', '.join([account['name'] for account in ACCOUNTS])), level='DEBUG')
  log(' - Attachments of types {} sent from {} will be saved in {}'.format(', '.join(ATTACHMENTS['type']), ', '.join(ATTACHMENTS['from']), ATTACHMENTS['path']), level='DEBUG')

  #mydb = Database(DB_FILE)

  for account in ACCOUNTS:
    count = 0

    while count < 3:
      try:
        log('Connecting to mail account {} ...'.format(account['name']), level='DEBUG')
        account['connection'] = MailBox(account['imap_host'], account['user'],
                                  account['password'], port=account['imap_port'],
                                  ssl=account['imap_ssl'], updated=account['updated'],
                                  **account['oauth2_parms'])
        break

      except OAUTH2_TOKEN_ERROR:
        account['oauth2_parms']['refresh_token'] = ''
        count += 1
        continue

      except Exception as e:
        log(' - An error occured while initializing account {}: {} --> Skip.'.format(account['name'], str(e)), level='ERROR')
        break

    if 'connection' in account:
      account['connection'].monitor('Inbox', callback=show, catchup=args.update)
      sleep(1)

  try:
    while(True):
      # Check if processes are still alive:
      for account in ACCOUNTS:
        if 'connection' in account and not account['connection'].is_idle():
          log('Mailbox {} disconnected. Reconnecting ...'.format(account['name']), level='ERROR')
          try:
            account['connection'].reconnect()
          except:
            raise
          account['connection'].monitor('Inbox', callback=show)
        sleep(1)

  except (KeyboardInterrupt, SystemExit):
    # Overwrite output of '^C' in case of KeyboardInterrupt:
    sys.stderr.write('\r')
    log('Abort requested by user or system', level='DEBUG')

  # Handle any unexpected error:
  except Exception as e:
    log('Error: {}, {}. Abort.'.format(type(e).__name__, str(e)), level='ERROR')
    sys.exit(1)

  finally:
    for account in ACCOUNTS:
      if 'connection' in account:
        account['connection'].close()

  sys.exit(0)
