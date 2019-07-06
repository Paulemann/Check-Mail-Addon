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

from socket import error as socket_error

from threading import *
from multiprocessing import *
from email.header import decode_header
from email.utils import parseaddr

import signal
import argparse

class GracefulExit(Exception):
    pass


def signal_handler(signum, frame):
    raise GracefulExit()

signal.signal(signal.SIGTERM, signal_handler)


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
       print '[' + level + ']: ' + message


def read_config():
  global _kodi_, _accounts_

  if not os.path.exists(_config_file_):
    log('Could not find configuration file \'{}\'.'.format(_config_file_), level='ERROR')
    return False

  log('Reading configuration from file {} ...'.format(_config_file_), level='DEBUG')

  try:
    # Read the config file
    config = ConfigParser.ConfigParser()

    config.read([os.path.abspath(_config_file_)])

    _kodi_ = {}
    _accounts_ = []

    for section_name in config.sections():
      if is_mailaddress(section_name):
        _accounts_.append({'name': section_name})

    _kodi_['hosts']   = [p.strip(' "\'') for p in config.get('KODI JSON-RPC', 'hostname').split(',')]
    _kodi_['port']    = int(config.get('KODI JSON-RPC', 'port'))
    _kodi_['user']    = config.get('KODI JSON-RPC', 'username')
    _kodi_['passwd']  = config.get('KODI JSON-RPC', 'password')

    for host in _kodi_['hosts']:
      if not is_hostname(host):
        log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC]).')
        return False
    if not is_int(_kodi_['port']):
      log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC]).')
      return False

    for account in _accounts_:
      account_name = account['name']
      account['server'] = config.get(account_name, 'server')
      if config.has_option(account_name, 'ssl'):
        account['ssl']  = bool(config.get(account_name, 'ssl') == 'yes')
      else:
        account['ssl']  = True
      if config.has_option(account_name, 'ssl'):
        account['port'] = int(config.get(account_name, 'port'))
      else:
        account['port'] = 993
      account['user']   = config.get(account_name, 'user')
      account['passwd'] = config.get(account_name, 'password')

      if not is_hostname(account['server']) or not account['user'] or not account['passwd']:
        log('Wrong or missing value(s) in configuration file (section [Mail Account]).')
        return False

  except:
    log('Could not process configuration file.', level='ERROR')
    return False

  log('Configuration OK.', level='DEBUG')

  return True


class MailBox(object):
  def __init__(self, server, user, password, port=None, ssl=True):
    self.server = server
    self.user = user
    self.password = password
    self.ssl = ssl
    self.port = port

    try:
      if self.ssl:
        if not self.port:
          self.port = 993
        self.imap = imaplib.IMAP4_SSL(self.server, self.port)
      else:
        if not self.port:
          self.port = 143
        self.imap = imaplib.IMAP4(self.server, self.port)
      self.imap.login(self.user, self.password)
      self.imap.select('Inbox', readonly=True)
    except self.imap.error as e:
      if 'authentication failed' in str(e):
        log('Authentication failure. Check username and password.')
        raise Exception('Authentication failure')
      else:
        log('Error: \"{}\"'.format(e))
        raise

  def monitor(self, callback=None):
    self.isRunning = True

    self.mon = Process(target=self.update, args=(callback,))
    self.mon.start()

  def close(self):
    if self.isRunning:
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

  def reconnect(self):
    try:
      self.imap.close()
      self.imap.logout()
    except:
      pass

    if self.ssl:
      self.imap = imaplib.IMAP4_SSL(self.server, self.port)
    else:
      self.imap = imaplib.IMAP4(self.server, self.port)

    try:
      self.imap.login(self.user, self.password)
      status, data = self.imap.select('Inbox', readonly=True)
      if status == 'OK':
        log('Connection reset: Successfully reconnected', level='DEBUG')
        return int(data[0])
    except:
      pass

    log('Connection reset: Couldn\'t reconnect', level='DEBUG')
    return None

  def update(self, callback):
    total_msgs = 0
    status, data = self.imap.select('Inbox', readonly=True)
    if status == 'OK':
      total_msgs = int(data[0])
      log('There are {} messages in INBOX'.format(total_msgs), level='DEBUG')
    else:
      raise Exception('Mailbox \'INBOX\' does not exist')

    while(self.isRunning):
      try:
        for num, msg in self.imap.idle():
          if msg == 'EXISTS' and int(num) > total_msgs:
            self.imap.done()
            total_msgs = int(num)

            uid = self.num2uid(num)
            email_msg = self.fetch(uid)
            if email_msg and callback:
              callback(email_msg)

          #elif msg == 'EXISTS':
          #  total_msgs = int(num)

          elif msg == 'EXPUNGE':
            total_msgs -= 1
            log('Mail deleted. {} messages remaining in INBOX'.format(total_msgs), level='DEBUG')

      except (KeyboardInterrupt, SystemExit, GracefulExit):
        log('Abort requested by user or system.', level='DEBUG')
        break

      except Exception as e:
        log('Abort due to exception: \"{}\"'.format(e), level='DEBUG')
        if 'connection reset by peer' in str(e.args[0]).lower():
          log('Connection reset: Trying to reconnect', level='DEBUG')
          total_msgs = self.reconnect()
          if not total_msgs:
            raise Exception('Unable to reconnect')
            break
        else:
          break


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
          break # -> raise Exception("While IDLE: \'{}\'".format(response.replace('\r\n', '')))
        if response.endswith('EXISTS') or response.endswith('EXPUNGE'):
          num, message = response.split()[1:3]
          yield num, message
      except socket_error as e:
        if 'timed out' in str(e.args[0]).lower():
          log('{} IDLE: Connection timed out'.format(connection.tag), level='DEBUG')
          connection.done()
        else:
          log('{} IDLE: Connection error (\'{}\')'.format(connection.tag, e), level='DEBUG')
          raise
      except connection.abort:
        log('{} IDLE: Connection abort'.format(connection.tag), level='DEBUG')
        raise Exception("While IDLE: \'{}\'".format(response.replace('\r\n', '')))
      except (KeyboardInterrupt, SystemExit, GracefulExit):
        raise
      except:
        log('{} IDLE: Unknown error'.format(connection.tag), level='DEBUG')
        pass
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
      log('{} IDLE: Unexpected Response'.format(connection.tag), level='DEBUG')
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

  #try:
  #  response = requests.post(url, data=json.dumps(data), headers=headers, timeout=10)
  #except:
  #  return False
  return False

  data = response.json()
  return (data['result'] == 'OK')


def host_is_up(host, port):
  try:
    sock = socket.create_connection((host, port), timeout=3)
  except:
    return False

  return True


def notify(sender, subject):
  if not sender or not subject:
    return

  notification_title = _notification_title_
  notification_text = '{}: {}'.format(sender, subject)

  for host in _kodi_['hosts']:
    if host_is_up(host, _kodi_['port']):
      log('Notfying host {}'.format(host))
      kodi_request(host, 'GUI.ShowNotification', params={'title': notification_title, 'message': notification_text, 'displaytime': 2000}, port=_kodi_['port'], user=_kodi_['user'], password=_kodi_['passwd'])
    else:
      log('Host {} is down. Requests canceled.'.format(host))


def show(message):
  if not message:
    return False

  try:
    from_name, from_address = parseaddr(message['From'])
    if not from_address:
      log('Could not parse sender\'s mail address from header.', level='DEBUG')
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
    notify(from_name, subject)
  else:
    log('From: {} | Subject: {}'.format(from_address, subject))
    notify(from_address, subject)

  return True


if __name__ == '__main__':
  global _config_file_, _log_file_, _debug_, _notification_title_, _socket_timeout_

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host when a new email is received')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  parser.add_argument('-l', '--logfile', dest='log_file', default=None, help="Path to log file (Default: None=stdout)")
  parser.add_argument('-t', '--timeout', dest='timeout', default=1500, help="Connection Timeout (Default: 1500)")
  parser.add_argument('-n', '--notify', dest='notify_title', default='New Message', help="Notification Title (Default: New Message)")
  parser.add_argument('-c', '--config', dest='config_file', default=os.path.splitext(os.path.basename(__file__))[0] + '.ini', help="Path to config file (Default: <Script Name>.ini)")

  args = parser.parse_args()

  _config_file_ = args.config_file
  _log_file_ = args.log_file
  _notification_title_ = args.notify_title
  _debug_ = args.debug
  _socket_timeout_ = int(args.timeout)

  if _log_file_:
    logging.basicConfig(filename=_log_file_, format='%(asctime)s [%(levelname)s]: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='w', level=logging.DEBUG)

  log('Output Debug:  {}'.format(_debug_), level='DEBUG')
  log('Log File:      {}'.format(_log_file_), level='DEBUG')
  log('Config File:   {}'.format(_config_file_), level='DEBUG')
  log('Conn. Timeout: {}'.format(_socket_timeout_), level='DEBUG')
  log('Notif. Title:  {}'.format(_notification_title_), level='DEBUG')

  if not read_config():
    sys.exit(1)

  for account in _accounts_:
    try:
      account['connection'] = MailBox(account['server'], account['user'], account['passwd'])

    except Exception as e:
      log('Error \'{}\' occured'.format(e))
      sys.exit(1)

    except:
      log('Unknown Error occured')
      sys.exit(1)

    today = datetime.date.today().strftime("%d-%b-%Y")
    uid_list = account['connection'].search('ON', today)

    if uid_list:
      for uid in uid_list:
        msg = account['connection'].fetch(uid)
        show(msg)

    account['connection'].monitor(show)

  while(True):
    try:
      raw_input("Press Enter to continue...")
      break

    except (KeyboardInterrupt, SystemExit, GracefulExit):
      log('Abort', level='DEBUG')
      break

    except Exception as e:
      log('Error \'{}\' occured.'.format(e), level='DEBUG')
      break

  for account in _accounts_:
    account['connection'].close()

  sys.exit()
