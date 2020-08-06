#!/usr/bin/python
# -*- coding: utf-8 -*-

import imaplib
import email
import time
import datetime
import requests
import json
import HTMLParser

import logging
import ConfigParser
import os
import sys

from socket import error as socket_error, create_connection as create_connection

from multiprocessing import *
from email.header import decode_header
from email.utils import parseaddr

import argparse

import signal


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
       #print '[' + level + ']: ' + message
       print '[{:^5s}]: {}'.format(level,  message)


def read_config():
  global _kodi_, _accounts_, _notification_title_

  if not os.path.exists(_config_file_):
    log('Could not find configuration file \'{}\''.format(_config_file_), level='ERROR')
    return False

  try:
    # Read the config file
    config = ConfigParser.ConfigParser()

    config.read([os.path.abspath(_config_file_)])

    _kodi_ = {}
    _accounts_ = []
    _notification_title_ = 'New Message for'

    for section_name in config.sections():
      if is_mailaddress(section_name):
        _accounts_.append({'name': section_name})
      if section_name == 'Customization':
        _notification_title_ = config.get('Customization', 'newmessagefor')

    _kodi_['hosts']   = [p.strip(' "\'') for p in config.get('KODI JSON-RPC', 'hostname').split(',')]
    _kodi_['port']    = int(config.get('KODI JSON-RPC', 'port'))
    _kodi_['user']    = config.get('KODI JSON-RPC', 'username')
    _kodi_['passwd']  = config.get('KODI JSON-RPC', 'password')

    for host in _kodi_['hosts']:
      if not is_hostname(host):
        log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC])', level='ERROR')
        return False

    if not is_int(_kodi_['port']):
      log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC])', level='ERROR')
      return False

    for account in _accounts_:
      account['server'] = config.get(account['name'], 'server')
      if config.has_option(account['name'], 'ssl'):
        account['ssl']  = bool(config.get(account['name'], 'ssl') == 'yes')
      else:
        account['ssl']  = True
      if config.has_option(account['name'], 'ssl'):
        account['port'] = int(config.get(account['name'], 'port'))
      else:
        account['port'] = 993
      account['user']   = config.get(account['name'], 'user')
      account['passwd'] = config.get(account['name'], 'password')

      if not is_hostname(account['server']) or not account['user'] or not account['passwd']:
        log('Wrong or missing value(s) in configuration file (section [Mail Account])', level='ERROR')
        return False

  except:
    log('Could not process configuration file', level='ERROR')
    return False

  return True


class MailBox(object):
  def __init__(self, server, user, password, port=None, ssl=True):
    self.server = server
    self.user = user
    self.password = password
    self.ssl = ssl
    self.port = port

    try:
       self.connect()
    except:
       raise

  def monitor(self, folder='Inbox', callback=None):
    self.isRunning = False
    self.mon = Process(target=self.update, args=(folder, callback,))
    self.mon.start()

  def is_idle(self):
    return self.mon.is_alive()

  def close(self):
    self.mon.terminate()
    self.isRunning = False
    try:
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

  def fetch(self, uid):
    status, data = self.imap.uid('fetch', uid, '(BODY.PEEK[HEADER])')
    if status == 'OK' and data[0]:
      email_msg = email.message_from_string(data[0][1])
      return email_msg
    else:
      return None

  def num2uid(self, num):
    status, data = self.imap.fetch(num, 'UID')
    if status == 'OK' and data:
      for item in data:
        resp = [i.strip('()') for i in item.split()]
        if resp[0] == num and resp[1] == 'UID':
          return resp[2]
    return None

  def connect(self, folder=None):
    try:
      if self.ssl:
        if not self.port:
          self.port = 993
        self.imap = imaplib.IMAP4_SSL(self.server, self.port)
      else:
        if not self.port:
          self.port = 143
        self.imap = imaplib.IMAP4(self.server, self.port)

    except Exception as e:
      log('Error: \'{}\' while connecting to \'{}:{}\'; Check name or IP address and port'.format(e, self.server, self.port), level='DEBUG')
      raise Exception('Connection failure')

    log('Connected to \'{}\''.format(self.server), level='DEBUG')
    try:
      self.imap.login(self.user, self.password)

    except self.imap.error as e:
      log('Error: \'{}\' while logging in \'{}\'; Check username and password'.format(e, self.user), level='DEBUG')
      raise Exception('Authentication failure')

    log('\'{}\' logged in'.format(self.user), level='DEBUG')

    if folder:
      status, data = self.imap.select(folder, readonly=True)
      if status == 'OK':
        log('Mailbox folder \'{}\' of \'{}\' with {} messages selected'.format(folder, self.user, int(data[0])), level='DEBUG')
        return int(data[0])
      else:
        log('Unable to select mailbox folder \'{}\' of \'{}\''.format(folder, self.user), level='DEBUG')
        raise Exception('Mailbox failure')

    return None

  def update(self, folder, callback):
    total_msgs = 0

    status, data = self.imap.select(folder, readonly=True)
    if status == 'OK':
      log('Mailbox folder \'{}\' of \'{}\' with {} messages selected'.format(folder, self.user, int(data[0])), level='DEBUG')
      total_msgs = int(data[0])
    else:
      log('Unable to select mailbox folder \'{}\' of \'{}\''.format(folder, self.user), level='ERROR')
      return

    self.isRunning = True
    while(self.isRunning):
      try:
        for num, msg in self.imap.idle():
          if msg == 'EXISTS' and int(num) > total_msgs:
            self.imap.done()
            total_msgs = int(num)

            uid = self.num2uid(num)
            email_msg = self.fetch(uid)
            if email_msg and callback:
              callback(self.user, email_msg)

          elif msg == 'EXPUNGE':
            total_msgs -= 1
            log('Mail deleted. {} messages remaining in \'{}\''.format(total_msgs, folder), level='DEBUG')

      except Exception as e:
        log('An error occured: \'{}\'. Re-connecting to \'{}\'.'.format(e, self.server), level='ERROR')
        try:
          total_msgs = self.connect(folder=folder)
        except Exception as e:
          log('Error: \'{}\' while connecting to \'{}\'. Abort.'.format(e, self.server), level='ERROR')
          break

    self.isRunning = False

def idle(connection):
  socket = None
  connection.loop = False
  connection.tag = None
  try:
    socket = connection.socket()
    connection.tag = connection._new_tag()
    connection.send(b'{} IDLE\r\n'.format(connection.tag))
    response = connection.readline().strip()
    log('Initializing \'{} IDLE\'; Response: \'{}\''.format(connection.tag, response.replace('\r\n', '')), level='DEBUG')
    if not response.startswith('+'):
      log('{} IDLE: Unexpected Response'.format(connection.tag), level='ERROR')
      raise Exception('While initializing IDLE: \'{}\''.format(response.replace('\r\n', '')))
    socket.settimeout(_socket_timeout_)
    connection.loop = True
    while connection.loop:
      try:
        response = connection.readline().strip()
        log('{} IDLE; Response: \'{}\''.format(connection.tag, response.replace('\r\n', '')), level='DEBUG')
        if response.startswith('* OK'):
          continue
        if response.startswith('* BYE '):
          log('{} IDLE: Connection closed'.format(connection.tag), level='DEBUG')
          raise Exception("Connection closed: \'{}\'".format(response.replace('\r\n', '')))
        if response.endswith('EXISTS') or response.endswith('EXPUNGE'):
          num, message = response.split()[1:3]
          yield num, message
      except socket_error as e:
        if 'timed out' in str(e).lower():
          log('{} IDLE: Connection timed out'.format(connection.tag), level='DEBUG')
          connection.done()
        else:
          raise
      except:
        raise
  except:
    raise


def done(connection):
  connection.send(b'DONE\r\n')
  connection.loop = False
  try:
    response = connection.readline().strip()
    log('Terminating \'{} IDLE\'; Response: \'{}\''.format(connection.tag, response.replace('\r\n', '')), level='DEBUG')
    if response.startswith('*'):
      response = connection.readline().strip()
      log('Terminating \'{} IDLE\'; Response: \'{}\''.format(connection.tag, response.replace('\r\n', '')), level='DEBUG')
    if not response.startswith('{} OK'.format(connection.tag)):
      log('{} IDLE: Unexpected Response'.format(connection.tag), level='ERROR')
      raise Exception('While terminating IDLE: \'{}\''.format(response.replace('\r\n', '')))
  except:
    raise

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
    base64str = base64.encodestring('{}:{}'.format(user, password))[:-1]
    header['Authorization'] = 'Basic {}'.format(base64str)

  try:
    response = requests.post(url, data=json.dumps(data), headers=headers, timeout=10)
  except:
    return False

  data = response.json()
  return (data['result'] == 'OK')


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
  notification_text = '{}: {}'.format(sender, subject)

  for host in _kodi_['hosts']:
    if host_is_up(host, _kodi_['port']):
      log('Notfying host {}'.format(host), level='DEBUG')
      kodi_request(host, 'GUI.ShowNotification', params={'title': notification_title, 'message': notification_text, 'displaytime': 2000}, port=_kodi_['port'], user=_kodi_['user'], password=_kodi_['passwd'])
    else:
      log('Host {} is down; Requests canceled'.format(host), level='DEBUG')


def show(user, message):
  if not message:
    return False

  try:
    from_name, from_address = parseaddr(message['From'])
    if not from_address:
      log('Could not parse sender\'s mail address from header', level='ERROR')
      return False

    name, encoding = decode_header(from_name)[0]
    if encoding:
      from_name = name.decode(encoding).encode('utf-8')
    else:
      from_name = name
  except:
    from_name = ''
    pass

  try:
    line = []
    for subject, encoding in decode_header(message['Subject']):
      if encoding:
        line.append(subject.decode(encoding).encode('utf-8'))
      else:
        line.append(subject)
    subject = ' '.join([l for l in line])
  except:
    subject = ''
    pass

  if from_name:
    log('From: {} <{}> | Subject: {}'.format(from_name, from_address, subject))
    notify(user, from_name, subject)
  else:
    log('From: {} | Subject: {}'.format(from_address, subject))
    notify(user, from_address, subject)

  return True


if __name__ == '__main__':
  global _config_file_, _log_file_, _debug_, _notification_title_, _socket_timeout_

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host when a new email is received')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  parser.add_argument('-l', '--logfile', dest='log_file', default=None, help="Path to log file (Default: None=stdout)")
  parser.add_argument('-t', '--timeout', dest='timeout', default=1500, help="Connection Timeout (Default: 1500)")
  parser.add_argument('-c', '--config', dest='config_file', default=os.path.splitext(os.path.basename(__file__))[0] + '.ini', help="Path to config file (Default: <Script Name>.ini)")

  args = parser.parse_args()

  _config_file_ = args.config_file
  _log_file_ = args.log_file
  _debug_ = args.debug
  _socket_timeout_ = int(args.timeout)

  if _log_file_:
    logging.basicConfig(filename=_log_file_, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='w', level=logging.DEBUG)

  log('Output Debug:  {}'.format(_debug_), level='DEBUG')
  log('Log File:      {}'.format(_log_file_), level='DEBUG')
  log('Conn. Timeout: {}'.format(_socket_timeout_), level='DEBUG')
  log('Config. File:  {}'.format(_config_file_), level='DEBUG')

  log('Reading configuration from file ...', level='DEBUG')
  if not read_config():
    sys.exit(1)

  log('Configuration: OK', level='DEBUG')
  log('Notif. Title:  \'{}\''.format(_notification_title_), level='DEBUG')

  Failure = False

  for account in _accounts_:
    log('Processing mail account \'{}\' ...'.format(account['name']), level='DEBUG')
    try:
      account['connection'] = MailBox(account['server'], account['user'], account['passwd'])

    except Exception as e:
      log('A fatal error occured: \'{}\'. Abort.'.format(e), level='ERROR')
      Failure = True
      break

    # Fetch unread mails only for today:
    #today = datetime.date.today().strftime("%d-%b-%Y")
    #uid_list = account['connection'].search('ON', today)

    #if uid_list:
    #  for uid in uid_list:
    #    msg = account['connection'].fetch(uid)
    #    show(account['user'], msg)

    account['connection'].monitor(callback=show)
    time.sleep(1)

  while(not Failure):
    try:
      # Check if processes are still alive:
      for account in _accounts_:
        if 'connection' in account and not account['connection'].is_idle():
          log('Idle process appears to be dead. Re-connecting to \'{}\'.'.format(account['server']), level='ERROR')
          try:
            account['connection'].connect()
          except Exception as e:
            log('Error: \'{}\' while connecting to \'{}\'. Abort.'.format(e, account['server']), level='ERROR')
            Failure = True
            break
          account['connection'].monitor(callback=show)
        time.sleep(1)

    except (KeyboardInterrupt, SystemExit):
      # Overwrite output of '^C' in case of KeyboardInterrupt:
      sys.stderr.write('\r')
      log('Abort requested by user or system', level='DEBUG')
      break

    # Handle any unexpected error:
    except Exception as e:
      log('An unexpected error occured: \'{}\'. Abort.'.format(e), level='ERROR')
      Failure = True
      # Explicit break isn't neccessary here, but doesn't hurt either:
      break

  for account in _accounts_:
    if 'connection' in account:
      account['connection'].close()

  status = 1 if Failure else 0
  sys.exit(status)
