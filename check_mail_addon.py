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

MIN_WAIT_TIME = 300
MAX_REAUTHS = 2

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
  for account in ACCOUNTS:
    if 'client_id' in account['oauth2_parms'] and account['oauth2_parms']['client_id'] in verification_url:
      account_name = account['name']
      break

  log('[{}] Sending notification to kodi host(s) {}'.format(account_name, ', '.join(KODI['host'])), level='DEBUG')
  for host in KODI['host']:
    if host_is_up(host, KODI['port']):
      kodi_request(host, 'GUI.ShowNotification', params={'title': LOCALE['auth_required'].format(account_name),
        'message': LOCALE['device_auth_message'].format(verification_url, user_code),
        'displaytime': 5000},
        port=KODI['port'], user=KODI['user'], password=KODI['password'])
    else:
      log('[{}] Kodi host {} is down or unreachable'.format(account_name, host), level='DEBUG')

  if MAILER:
    log('[{}] Sending notification to mail recipient(s) {}'.format(account_name, ', '.join(OAUTH2['notify'])), level='DEBUG')
    MAILER.send(OAUTH2['notify'], LOCALE['auth_required'].format(account_name),
      LOCALE['device_auth_message_text'].format(verification_url, user_code),
      html=LOCALE['device_auth_message_html'].format(verification_url, user_code))

  return OAUTH2['wait']


def auth_get(authorization_url, redirect_uri):
  authorization_code = ''

  for account in ACCOUNTS:
    if 'client_id' in account['oauth2_parms'] and account['oauth2_parms']['client_id'] in authorization_url:
      account_name = account['name']
      break

  log('[{}] Sending notification to kodi host(s) {}'.format(account_name,', '.join(KODI['host'])), level='DEBUG')
  for host in KODI['host']:
    if host_is_up(host, KODI['port']):
      kodi_request(host, 'GUI.ShowNotification', params={'title': LOCALE['auth_required'].format(account_name),
       'message': LOCALE['auth_message'].format(authorization_url),
       'displaytime': 5000},
       port=KODI['port'], user=KODI['user'], password=KODI['password'])
    else:
      log('[{}] Kodi host {} is down or unreachable'.format(account_name, host), level='DEBUG')

  if MAILER:
    log('[{}] Sending notification to mail recipient(s) {}'.format(account_name, ', '.join(OAUTH2['notify'])), level='DEBUG')
    MAILER.send(OAUTH2['notify'], LOCALE['auth_required'].format(account_name),
      LOCALE['auth_message_text'].format(authorization_url),
      html=LOCALE['auth_message_html'].format(authorization_url))

    s = redirect_uri.rsplit(':', maxsplit=1)[1].strip('/')
    redirect_port = int(s) if s.isdigit() else 443

    log('[{}] ***** Starting local web server to receive authorization code *******************'.format(account_name), level='INFO')
    log('[{}] ***** Make sure your router/firewall accepts https requests on port {} {}*******'.format(account_name, redirect_port, (5 - len(str(redirect_port))) * '*'), level='INFO')
    try:
      authorization_code = run_server(redirect_port, timeout=OAUTH2['wait'])
    except:
      log('[{}] ***** Local web server failed or timed out: no authorization code received ******'.format(account_name), level='ERROR')
      #authorization_code = ''
      raise
    else:
      log('[{}] ***** Local web server stopped: authorization code received *********************'.format(account_name), level='INFO')

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
      # created DATETIME DEFAULT CURRENT_TIMESTAMP # DATETIME('now'))
      self.cursor.execute("""CREATE UNIQUE INDEX sender_subject ON email(sender, subject)""")

    except sqlite3.OperationalError:
      log('Database already exists', level='DEBUG')

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


def read_value(section, option, type='str', default=None, config=None):
  try:
    if config is None:
      config = configparser.ConfigParser()
      config.read([os.path.abspath(CONFIG_FILE)])

    if not config.has_section(section):
      #raise Exception('Invalid section')
      log('There\'s no section [{}] in file {}'.format(section, CONFIG_FILE), level='ERROR')
      return default

    if type == 'int':
      default = default or 0
      return int(config.get(section, option))

    elif type == 'str':
      default = default or ''
      return config.get(section, option)

    elif type == 'list':
      default = default or []
      return [p.strip(' "\'').lower() for p in config.get(section, option).split(',')]

    elif type == 'csv':
      default = default or []
      return [int(p) for p in config.get(section, option).split(',')]

    elif type == 'bool':
      default = default or False
      return config.get(section, option) == 'yes'

    elif type == 'date':
      default = default or datetime.min
      return datetime.strptime(config.get(section, option), TIME_FMT)

  except:
    pass

  return default


def save_value(section, option, value):
  try:
    config = configparser.ConfigParser(delimiters=('='))
    config.read([os.path.abspath(CONFIG_FILE)])

    if not config.has_section(section):
      log('There\'s no section [{}] in file {}'.format(section, CONFIG_FILE), level='ERROR')
      return False

    if value is False:
      if config.has_option(section, option):
        config.remove_option(section, option)
      else:
        log('There\'s no option {} in section [{}] of file {}'.format(option, section, CONFIG_FILE), level='DEBUG')
        return False
    else:
      config.set(section, option, value)

    with open(os.path.abspath(CONFIG_FILE), 'w') as configfile:
      config.write(configfile, space_around_delimiters=True)

  except Exception as e:
    log('Updating option \'{}\' in section [{}] of file {} failed: {}'.format(option, section, CONFIG_FILE, str(e)), level='ERROR')
    return False

  log('Option \'{}\' in section [{}] of file {} {}'.format(option, section, CONFIG_FILE, 'removed' if value is False else 'updated'), level='DEBUG')

  return True


def save_timestamp(section, timestamp):
  return save_value(section, 'updated', timestamp)


def save_token(section, token):
  return save_value(section, 'refresh_token', token)


def remove_token(section):
  return save_value(section, 'refresh_token', False)


def reload_token(section):
  return read_value(section, 'refresh_token')


def reload_timestamp(section):
  return read_value(section, 'updated', type='date')


def read_section(section, options, config):
  section_cfg = {}

  for option, value in options.items():
    if config is None:
      section_cfg[option] = value.get('default')
    else:
      section_cfg[option] = read_value(section, option, value.get('type'), value.get('default'), config)

    if value.get('mandatory') and not section_cfg[option]:
      log('Missing mandatory config value; section: [{}], option: {}'. format(section, option), level='ERROR')
      raise Exception('Missing value')

    if value.get('test') and section_cfg[option]:
      if value['type'] in ['list', 'csv']:
        test = section_cfg[option]
      else:
        test = [section_cfg[option]]

      for element in test:
        if element and not value['test'](element):
          log('Invalid config value; section: [{}], option: {}, value: {}'. format(section, option, config.get(section, option)), level='ERROR')
          raise Exception('Invalid value')

  return section_cfg


def read_locale():
  global LOCALE

  try:
    if os.path.exists(LOCALE_FILE):
      config = configparser.ConfigParser()
      config.read([os.path.abspath(LOCALE_FILE)])
    else:
      log(' - Missíng localization file {}. Using defaults ...'.format(LOCALE_FILE), level='ERROR')
      config = None

    locale_options = {
      'new_message_for':          {'type': 'str', 'default': 'New message for'},
      'from':                     {'type': 'str', 'default': 'From'},
      'subject':                  {'type': 'str', 'default': 'Subject'},
      'auth_required':            {'type': 'str', 'default': 'Authorization required for email account {}'},
      'auth_message':             {'type': 'str', 'default': 'Use a web browser to open the page {} to authorize your application to read email messages.'},
      'device_auth_message':      {'type': 'str', 'default': 'Use a web browser to open the page {} and enter the code {} to authorize your device.'},
      'auth_message_text':        {'type': 'str', 'default': AUTH_TEXT},
      'device_auth_message_text': {'type': 'str', 'default': DEVICE_AUTH_TEXT},
      'auth_message_html':        {'type': 'str', 'default': AUTH_HTML},
      'device_auth_message_html': {'type': 'str', 'default': DEVICE_AUTH_HTML}
      }
    LOCALE = read_section('Localization', locale_options, config)

    log(' - Done', level='DEBUG')

  except:
    raise


def read_config():
  global KODI, ACCOUNTS, ATTACHMENTS, MAILER, OAUTH2

  if not os.path.exists(CONFIG_FILE):
    log(' - Missíng configuration file {}'.format(CONFIG_FILE), level='ERROR')
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

    oauth2_options = {
      'notify': {'type': 'list', 'test': is_mailaddress},
      'wait':   {'type': 'int', 'default': 300}
      }
    OAUTH2 = read_section('OAuth2', oauth2_options, config)

    kodi_options = {
      'host': {'type': 'list', 'test': is_hostname},
      'port': {'type': 'int', 'test': is_int, 'default': 8080},
      'user': {'type': 'str', 'default': 'kodi'},
      'password': {'type': 'str'}
      }
    KODI = read_section('KODI JSON-RPC', kodi_options, config)

    attachments_options = {
      'path': {'type': 'str'},
      'type': {'type': 'list'},
      'from': {'type': 'list'}
      }
    ATTACHMENTS = read_section('Attachments', attachments_options, config)

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
        #'updated':   {'type': 'date'}
        }
      account.update(read_section(account['name'], account_options, config))

      if account['smtp_host']:
        SMTP.append(account)

      if config.has_option(account['name'], 'client_id'):
        oauth2_parms = {
          'client_id':     {'type': 'str', 'mandatory': True},
          'client_secret': {'type': 'str'},
          'refresh_token': {'type': 'str'},
          'tenant_id':     {'type': 'str', 'default': 'consumers' if account['name'].split('@')[1].split('.')[0] in MICROSOFT_DOMAINS else ''},
          'redirect_uri':  {'type': 'str', 'test': is_https}
          }
        account['oauth2_parms'] = read_section(account['name'], oauth2_parms, config)

        if config.has_option(account['name'], 'redirect_uri'):
          if 'auth_get' in globals():
            account['oauth2_parms']['callback'] = auth_get
        else:
          if 'device_auth_get' in globals():
            account['oauth2_parms']['callback'] = device_auth_get
      else:
        account['oauth2_parms'] = {}

    if SMTP:
      log(' - SMTP data found', level='DEBUG')
      MAILER = Mailer(SMTP[0]['smtp_host'], SMTP[0]['smtp_port'], SMTP[0]['user'], SMTP[0]['password'])
    else:
      log(' - No SMTP data', level='DEBUG')
      MAILER = None

    log(' - Done', level='DEBUG')

  except:
    raise


class MailBox(object):
  def __init__(self, name, server, user, password, port=None, ssl=True, **oauth2_parms):
    self.name     = name
    self.server   = server
    self.user     = user
    self.password = password
    self.port     = port
    self.ssl      = ssl

    self.last_updated = reload_timestamp(self.name)

    if oauth2_parms:
      #for attr in oauth2_parms.keys():
      for attr in ['client_id', 'client_secret', 'refresh_token', 'redirect_uri', 'callback', 'tenant_id']:
        setattr(self, attr, oauth2_parms.get(attr))


  def monitor(self, folder, callback=None, delay=None):
    self.mon = Process(target=self.update, args=(folder, callback, delay,))
    self.mon.start()


  def is_idling(self):
    return self.mon.is_alive()


  def close(self):
    log('[{}] Closing connection ...'.format(self.name), level='DEBUG')

    if hasattr(self, 'imap') and self.imap:
      try:
        self.imap.done(debug=debug)
        self.imap.close()

      except:
        pass

      finally:
        try:
          self.imap.logout()

        except:
          pass

    try:
      if hasattr(self, 'mon') and self.mon:
        self.mon.terminate()

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
    #status, data = self.imap.uid('fetch', uid, 'UID RFC822.SIZE FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (From To Cc Bcc Subject Date In-Reply-To Content-Type Reply-To)]'
    status, data = self.imap.uid('fetch', uid, '(BODY.PEEK[])')
    if status == 'OK' and data[0]:
      email_msg = email.message_from_bytes(data[0][1])
      return email_msg
    else:
      return None


  def num2uid(self, num):
    status, data = self.imap.fetch(num, 'UID')
    if status == 'OK' and data:
      #return data[0].split()[-1].strip(b'()')
      for item in data:
        resp = [i.strip(b'()') for i in item.split()]
        if resp[0] == num and resp[1] == b'UID':
          return resp[2]
    else:
      return None


  def connect(self):
    if not self.port:
      self.port = 993 if self.ssl else 143

    access_token = ''
    refresh_token = ''

    try:
      if hasattr(self, 'client_id') and self.client_id:
        if self.refresh_token:
          log('[{}] Requesting access (authorization by refresh token) ...'.format(self.name), level='DEBUG')
          access_token, refresh_token = auth_refresh(self.client_id, self.client_secret, self.refresh_token, tenant_id=self.tenant_id)

        else:
          log('[{}] Requesting access (explicit authorization required) ...'.format(self.name), level='DEBUG')

          if not self.callback:
            raise Exception('OAuth2 callback not set')

          if self.redirect_uri:
            authorization_code = auth_code(self.client_id, self.redirect_uri, offline=True, callback=self.callback, tenant_id=self.tenant_id)
            if authorization_code:
              access_token, refresh_token = auth_request(self.client_id, self.client_secret, self.redirect_uri, authorization_code, tenant_id=self.tenant_id)
            else:
              raise Exception('No OAuth2 authorization code')

          else:
            device_code, expires_in, interval = device_auth_code(self.client_id, callback=self.callback, tenant_id=self.tenant_id)
            if device_code:
              access_token, refresh_token = device_auth_request(self.client_id, self.client_secret, device_code, expires_in=expires_in, interval=interval, tenant_id=self.tenant_id)
            else:
              raise Exception('No OAuth2 device code')

        if refresh_token:
          log('[{}] New refresh token received'.format(self.name), level='DEBUG')
          self.refresh_token = refresh_token
          save_token(self.name, self.refresh_token)

      else:
        log('[{}] Authenticating with username, password ...'.format(self.name), level='DEBUG')

      if self.ssl:
        self.imap = imaplib.IMAP4_SSL(self.server, self.port)
      else:
        self.imap = imaplib.IMAP4(self.server, self.port)

      log('[{}] Connected to IMAP server {} on port {}'.format(self.name, self.server, self.port), level='DEBUG')

      #self.imap.debug = 4 # 10

      if access_token:
        auth_string = generate_xoauth2(self.user, access_token)
        self.imap.authenticate('XOAUTH2', lambda x: auth_string.encode())

      elif self.password:
        self.imap.login(self.user, self.password)

      else:
         raise Exception('Insufficient login/auth data')

    except socket_error as e:
      log('[{}] Connection failed: {}'.format(self.name, e_decode(e)), level='ERROR')
      raise IMAP_CONNECT_ERROR(e_decode(e))

    except Exception as e:
      log('[{}] Login failed: {}'.format(self.name, e_decode(e)), level='ERROR')

      if any(['expired' in e_decode(e), 'revoked' in e_decode(e)]) and hasattr(self, 'refresh_token') and self.refresh_token:
        log('[{}] Removing invalid token from configuration ...'.format(self.name), level='DEBUG')

        remove_token(self.name)
        self.refresh_token = ''

        raise OAUTH2_TOKEN_ERROR(e_decode(e))

      raise IMAP_AUTH_ERROR(e_decode(e))

    log('[{}] Login successful'.format(self.name), level='DEBUG')


  def select(self, folder):
    if folder:
      status, data = self.imap.select(folder, readonly=True)
      if status == 'OK':
        log('[{}] {}: {} message{}'.format(self.name, folder, int(data[0]), 's' if int(data[0]) > 1 else ''), level='DEBUG')
        return int(data[0])
      else:
        log('[{}] Selection of {} failed'.format(self.name, folder), level='ERROR')
        raise Exception('Mailbox folder selection failed')
    else:
      log('[{}] Mailbox folder unnamed'.format(self.name), level='ERROR')
      raise Exception('Mailbox folder unnamed')


  def update(self, folder, callback, delay=None):

    def evaluate(last_seq_num, callback):
      start_uid = self.num2uid(str(last_seq_num + 1).encode())

      if not start_uid:
        return None

      uid_list = self.search('UID {}:*'.format(int(start_uid)))

      if uid_list:
        log('[{}] Found {} new UID{}: {}'.format(self.name, len(uid_list), 's' if len(uid_list) > 1 else '', ', '.join([u.decode('utf-8') for u in uid_list])), level='DEBUG')

        for uid in uid_list:
          email_msg = self.fetch(uid)

          if email_msg:
            try:
              timestamp = email_msg['received'].split(';')[-1].strip()
              timestamp = ''.join(timestamp.split('\r\n'))
            except:
              timestamp = datetime.now().astimezone().strftime("%a, %d %b %Y %H:%M:%S %z")
            received = datetime.fromtimestamp(mktime_tz(parsedate_tz(timestamp)))
            if received > self.last_updated:
              self.last_updated = received

            if callback:
              callback(self.user, email_msg)

        save_timestamp(self.name, self.last_updated.strftime(TIME_FMT))

        return uid

      else:
        log('[{}] No new UID'.format(self.name), level='DEBUG')
        return None

    try:
      #if delay is set, calculate wait time before next connect attempt
      if delay:
        wait = (((MIN_WAIT_TIME // 60) ** delay.value) - 1) * 60
        if wait > 0:
          log('[{}] Waiting {} secs. before reconnecitng ...'.format(self.name, wait), level='DEBUG')
          sleep(wait)

      if hasattr(self, 'refresh_token'):
        log('[{}] Reloading refresh token ...'.format(self.name), level='DEBUG')
        self.refresh_token = reload_token(self.name)
      self.connect()

    except Exception as e:
      self.close()
      log('[{}] Disconnected'.format(self.name), level='ERROR')

     # increment delay value after failed connect
      if delay:
        delay.value += 1

      return

    # re-init delay value after successful connect
    if delay:
      delay.value = 0

    try:
      total_msgs = self.select(folder)

    except Exception as e:
      log('[{}] Error: {}'.format(self.name, str(e)), level='ERROR')
      return

    self.last_updated = reload_timestamp(self.name)
    log('[{}] Retrieving unread messages since last update on {}...'.format(self.name, self.last_updated.strftime(TIME_FMT).split()[0]), level='DEBUG')

    # Fetch all unread messages since last update:
    date = self.last_updated.strftime("%d-%b-%Y")

    # Fetch all unread messages of past x days:
    #date = (date.today() - timedelta(x)).strftime("%d-%b-%Y")

    uid_list = self.search('SENTSINCE', date)
    saved = self.last_updated

    try:
      if uid_list:
        log('[{0}] Found {1} unread message{2}. UID{2}: {3}'.format(self.name, len(uid_list), 's' if len(uid_list) > 1 else '', ', '.join([u.decode('utf-8') for u in uid_list])), level='DEBUG')

        for uid in uid_list:
          email_msg = self.fetch(uid)

          if 'received' in email_msg:
            timestamp = email_msg['received'].split(';')[-1].strip()
          else:
            timestamp = email_msg['Date']

          timestamp = ''.join(timestamp.split('\r\n'))
          received = datetime.fromtimestamp(mktime_tz(parsedate_tz(timestamp)))

          if received > self.last_updated:
            log('[{}] Found new unread message. Received on {}. UID: {}'.format(self.name, received.strftime(TIME_FMT), uid.decode('utf-8')), level='DEBUG')
            self.last_updated = received

            if callback:
              callback(self.user, email_msg)

        if self.last_updated > saved:
          save_timestamp(self.name, self.last_updated.strftime(TIME_FMT))

      if self.last_updated == saved:
        log('[{}] No missed messages'.format(self.name), level='DEBUG')

    except Exception as e:
      log('[{}] Update failed: {}'.format(self.name, str(e)), level='DEBUG')

    while(True):
      try:
        new_msgs = 0

        for num, msg in self.imap.idle(timeout=IDLE_TIMEOUT, debug=debug):
          if msg == b'EXISTS':
            new_msgs = int(num) - total_msgs
            log('[{}] {} updated: {} {} message{}'.format(self.name, folder, abs(new_msgs), 'deleted' if new_msgs < 0 else 'new', 's' if abs(new_msgs) > 1 else ''), level='DEBUG')

            #total_msgs = int(num)
            total_msgs += new_msgs

            if new_msgs > 0:
              self.imap.done(debug=debug)

        if new_msgs > 0 and not self.imap.is_idle():
          last_uid = evaluate(total_msgs - new_msgs, callback)
          log('[{}] Last UID: {}'.format(self.name, last_uid.decode('utf-8')), level='DEBUG')

        log('[{}] Restarting IDLE ...'.format(self.name), level='DEBUG')

      except Exception as e:
        log('[{}] IDLE stopped: {}'.format(self.name, str(e)), level='DEBUG')
        break


#imaplib.Debug = 4
imaplib.IMAP4.idle = idle
imaplib.IMAP4.done = done
imaplib.IMAP4.is_idle = is_idle


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

  log('New message:')

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
          log('Message text body:   {} bytes'.format(len(msg['text'])), level='DEBUG')

        if part.get_content_type() == 'text/html':
          charset = part.get_content_charset('iso-8859-1')
          msg['html'] = part.get_payload(decode=True).decode(charset, 'replace') #.decode('raw-unicode-escape')
          log('Message html body:   {} bytes'.format(len(msg['html'])), level='DEBUG')
          if not msg.get('text'):
            msg['text'] = html2text(msg['html'])
            log('Message text body:   {} bytes (converted from html)'.format(len(msg['text'])), level='DEBUG')

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

  if DB_FILE:
    try:
      mydb.save([msg])
      #mydb.execute("DELETE FROM email WHERE created < DATETIME('now', '-7 day')")
      log('Message saved', level='DEBUG')
    except Exception as e:
      log('Unexpected error while saving message: {}, {}'.format(type(e).__name__, str(e)), level='ERROR')


if __name__ == '__main__':
  global CONFIG_FILE, LOG_FILE, IDLE_TIMEOUT, __DEBUG__, DB_FILE

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host when a new email is received')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  #parser.add_argument('-u', '--update', dest='update', action='store_true', help="Show messages since last recorded update (Default: False)")
  parser.add_argument('-l', '--logfile', dest='log_file', default=None, help="Path to log file (Default: None=stdout)")
  parser.add_argument('-t', '--timeout', dest='timeout', default=840, help="Connection Timeout (Default: 840 sec. = 14 min.)")
  parser.add_argument('-c', '--config', dest='config_file', default=os.path.splitext(os.path.basename(__file__))[0] + '.ini', help="Path to config file (Default: <Script Name>.ini)")
  parser.add_argument('-s', '--save', dest='save_file', nargs='?', const=os.path.splitext(os.path.basename(__file__))[0] + '.db', default=None, help="Path to message database (Default: None)")

  args = parser.parse_args()

  DB_FILE      = args.save_file
  CONFIG_FILE  = args.config_file
  LOG_FILE     = args.log_file
  IDLE_TIMEOUT = int(args.timeout)
  __DEBUG__    = args.debug

  LOCALE_FILE  = os.path.splitext(os.path.basename(__file__))[0] + '.loc'

  if LOG_FILE:
    #logging.basicConfig(filename=LOG_FILE, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='w', level=logging.DEBUG)
    logging.basicConfig(filename=LOG_FILE, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='a', level=logging.DEBUG)

  log('***** {} started *****'.format(os.path.basename(__file__)), level='INFO')

  log('Arguments:', level='DEBUG')
  log(' - Output Debug:  {}'.format(__DEBUG__), level='DEBUG')
  log(' - IDLE Timeout:  {} sec.'.format(IDLE_TIMEOUT), level='DEBUG')
  log(' - Log File:      {}'.format(os.path.abspath(LOG_FILE)), level='DEBUG')
  log(' - Config File:   {}'.format(os.path.abspath(CONFIG_FILE)), level='DEBUG')
  log(' - Msg. Database: {}'.format(os.path.abspath(DB_FILE) if DB_FILE else '-'), level='DEBUG')

  try:
    log('Reading localization file {} ...'.format(os.path.abspath(LOCALE_FILE)), level='DEBUG')
    read_locale()

    log('Reading configuration file {} ...'.format(os.path.abspath(CONFIG_FILE)), level='DEBUG')
    read_config()

  except Exception as e:
    log('Configuration failed with error: {}. Abort'.format(str(e)), level='ERROR')
    sys.exit(1)

  log('Configuration successful:', level='DEBUG')
  log(' - Accounts:      {}'.format(', '.join([account['name'] for account in ACCOUNTS])), level='DEBUG')
  log(' - Attachments of types {} sent from {} will be saved in {}'.format(', '.join(ATTACHMENTS['type']), ', '.join(ATTACHMENTS['from']), ATTACHMENTS['path']), level='DEBUG')

  if DB_FILE:
    try:
      mydb = Database(os.path.abspath(DB_FILE))

    except Exception as e:
      log('An error occured while initializing message database {}: {}, {}'.format(DB_FILE, type(e).__name__, str(e)), level='ERROR')
      DB_FILE = None

  # Initialize
  for account in ACCOUNTS:
    try:
      log('[{}] Connecting ...'.format(account['name']), level='DEBUG')
      account['connection'] = MailBox(account['name'], account['imap_host'], account['user'],
                                account['password'], port=account['imap_port'],
                                ssl=account['imap_ssl'], **account['oauth2_parms'])

      account['connection'].monitor('Inbox', callback=show)
      account['reauths'] = Value('i', 0)

    except:
      log('[{}] Initialization error. Skip'.format(account['name']), level='ERROR')
      continue

    sleep(2)

  try:
    while(True):
      # Check if processes are still alive:
      for account in ACCOUNTS:
        if 'connection' in account and not account['connection'].is_idling() and account['reauths'].value < MAX_REAUTHS:
          log('[{}] Reconnecting ...'.format(account['name']), level='DEBUG')
          account['connection'].monitor('Inbox', callback=show, delay=account['reauths'])

        sleep(5)

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
