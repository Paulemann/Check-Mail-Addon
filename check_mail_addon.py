#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import email
import time
import datetime
import requests
import json
import html.parser

import logging
import configparser
import os
import sys

from socket import error as socket_error, create_connection as create_connection
#import errno

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
       #print('[' + level + ']: ' + message)
       print('[{:^5s}]: {}'.format(level,  message))


def read_config():
  global _kodi_, _accounts_, _attachments_, _notification_title_, _msg_from_, _msg_subject_

  if not os.path.exists(_config_file_):
    log('Could not find configuration file \'{}\''.format(_config_file_), level='ERROR')
    return False

  try:
    # Read the config file
    config = configparser.ConfigParser()

    config.read([os.path.abspath(_config_file_)])

    _kodi_               = {}
    _attachments_        = {}
    _accounts_           = []
    _notification_title_ = 'New Message for'
    _msg_from_           = 'From'
    _msg_subject_        = 'Subject'

    for section_name in config.sections():
      if is_mailaddress(section_name):
        _accounts_.append({'name': section_name})

      if section_name == 'Customization':
        _notification_title_ = config.get('Customization', 'newmessagefor')
        _msg_from_           = config.get('Customization', 'from')
        _msg_subject_        = config.get('Customization', 'subject')

    _kodi_['hosts']  = [p.strip(' "\'') for p in config.get('KODI JSON-RPC', 'hostname').split(',')]
    _kodi_['port']   = int(config.get('KODI JSON-RPC', 'port'))
    _kodi_['user']   = config.get('KODI JSON-RPC', 'username')
    _kodi_['passwd'] = config.get('KODI JSON-RPC', 'password')

    for host in _kodi_['hosts']:
      if not is_hostname(host):
        log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC])', level='ERROR')
        return False

    if not is_int(_kodi_['port']):
      log('Wrong or missing value(s) in configuration file (section: [KODI JSON-RPC])', level='ERROR')
      return False

    _attachments_['path'] = config.get('Attachments', 'path')
    _attachments_['type'] = [p.strip(' "\'') for p in config.get('Attachments', 'type').split(',')]
    _attachments_['from'] = [p.strip(' "\'') for p in config.get('Attachments', 'from').split(',')]

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
    #status, data = self.imap.uid('fetch', uid, '(BODY.PEEK[HEADER])')
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
      log('Error: \'{}\' while logging in user \'{}\'; Check username and password'.format(e, self.user), level='DEBUG')
      raise Exception('Authentication failure')

    log('Mailbox user \'{}\' logged in'.format(self.user), level='DEBUG')

    if folder:
      status, data = self.imap.select(folder, readonly=True)
      if status == 'OK':
        log('Mailbox folder \'{}\' of user \'{}\' selected: {} messages'.format(folder, self.user, int(data[0])), level='DEBUG')
        return int(data[0])
      else:
        log('Unable to select mailbox folder \'{}\' of user \'{}\''.format(folder, self.user), level='DEBUG')
        raise Exception('Mailbox failure')

    return None

  def update(self, folder, callback):
    total_msgs = 0

    status, data = self.imap.select(folder, readonly=True)
    if status == 'OK':
      log('Mailbox folder \'{}\' of user \'{}\' selected: {} messages'.format(folder, self.user, int(data[0])), level='DEBUG')
      total_msgs = int(data[0])
    else:
      log('Unable to select mailbox folder \'{}\' of user \'{}\''.format(folder, self.user), level='ERROR')
      return

    self.isRunning = True
    while(self.isRunning):
      try:
        for num, msg in self.imap.idle():
          if msg == b'EXISTS' and int(num) > total_msgs:
            self.imap.done()
            total_msgs = int(num)

            uid = self.num2uid(num)
            email_msg = self.fetch(uid)
            if email_msg and callback:
              callback(self.user, email_msg)

          elif msg == b'EXPUNGE':
            total_msgs -= 1
            log('Mail deleted. {} messages remaining in \'{}\''.format(total_msgs, folder), level='DEBUG')

      except Exception as e:
        if any(s in str(e).lower() for s in ['timed out', 'timeout']):
          log('Connection timed out for user \'{}\'. Re-connecting to \'{}\'.'.format(self.user, self.server), level='DEBUG')
        else:
          log('An error occured: \'{}\'. Re-connecting to \'{}\'.'.format(e, self.server), level='DEBUG')

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
  response = b''

  try:
    socket = connection.socket()
    connection.tag = connection._new_tag()
    connection.send(connection.tag + b' IDLE\r\n')
    response = connection.readline().strip()
    log('Initializing \'{} IDLE\'; Response: \'{}\''.format(connection.tag.decode('utf-8'), response.replace(b'\r\n', b'').decode('utf-8')), level='DEBUG')
    if not response.startswith(b'+'):
      log('{} IDLE: Unexpected response'.format(connection.tag.decode('utf-8')), level='ERROR')
      raise Exception('While initializing IDLE: \'{}\''.format(response.replace(b'\r\n', b'').decode('utf-8')))
    socket.settimeout(_socket_timeout_)
    connection.loop = True
    while connection.loop:
      try:
        response = connection.readline().strip()
        log('{} IDLE; Response: \'{}\''.format(connection.tag.decode('utf-8'), response.replace(b'\r\n', b'').decode('utf-8')), level='DEBUG')
        if response.startswith(b'* OK'):
          continue
        if response.startswith(b'* BYE '):
          log('{} IDLE: Connection closed'.format(connection.tag.decode('utf-8')), level='DEBUG')
          raise Exception('Connection closed: \'{}\''.format(response.replace(b'\r\n', b'').decode('utf-8')))
        if response.endswith(b'EXISTS') or response.endswith(b'EXPUNGE'):
          num, message = response.split()[1:3]
          yield num, message
      except (socket_error, OSError) as e:
        if 'timed out' in str(e).lower():
          log('{} IDLE: Connection timed out'.format(connection.tag.decode('utf-8')), level='DEBUG')
          connection.done()
        #elif e.errno == errno.ECONNRESET:
        #  log('{} IDLE: Connection reset by peer'.format(connection.tag.decode('utf-8')), level='DEBUG')
        #  raise Exception('Connection reset by peer')
        else:
          log('{} IDLE: Unexpected exception \'{}\' due to socket or OS error in inner loop of function \'idle()\''.format(connection.tag.decode('utf-8')), e, level='DEBUG')
          raise
      except Exception as e:
        log('{} IDLE: Unexpected exception \'{}\' in inner loop of function \'idle()\''.format(connection.tag.decode('utf-8'), e), level='DEBUG')
        raise
  except Exception as e:
    log('{} IDLE: Unexpected exception \'{}\' at start of function \'idle()\''.format(connection.tag.decode('utf-8'), e), level='DEBUG')
    raise


def done(connection):
  connection.send(b'DONE\r\n')
  connection.loop = False
  try:
    response = connection.readline().strip()
    log('Terminating \'{} IDLE\'; Response: \'{}\''.format(connection.tag.decode('utf-8'), response.replace(b'\r\n', b'').decode('utf-8')), level='DEBUG')
    if response.startswith(b'*'):
      response = connection.readline().strip()
      log('Terminating \'{} IDLE\'; Response: \'{}\''.format(connection.tag.decode('utf-8'), response.replace(b'\r\n', b'').decode('utf-8')), level='DEBUG')
    if not response.startswith(connection.tag + b' OK'):
      log('{} IDLE: Unexpected Response'.format(connection.tag.decode('utf-8')), level='ERROR')
      raise Exception('While terminating IDLE: \'{}\''.format(response.replace(b'\r\n', b'').decode('utf-8')))
  except Exception as e:
    log('{} IDLE: Unexpected exception \'{}\' in function \'done()\''.format(connection.tag.decode('utf-8'), e), level='DEBUG')
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
  notification_text = '{}: {} | {}: {}'.format(_msg_from_, sender, _msg_subject_, subject)

  for host in _kodi_['hosts']:
    if host_is_up(host, _kodi_['port']):
      log('Notfying host \'{}\''.format(host), level='DEBUG')
      kodi_request(host, 'GUI.ShowNotification', params={'title': notification_title, 'message': notification_text, 'displaytime': 2000}, port=_kodi_['port'], user=_kodi_['user'], password=_kodi_['passwd'])
    else:
      log('Host \'{}\' is down; Requests canceled'.format(host), level='DEBUG')


def show(user, message):
  if not message:
    return

  try:
    name, address = parseaddr(message['From'])
    if not address:
      log('Could not parse sender\'s mail address from header', level='ERROR')
      return

    name, encoding = decode_header(name)[0]
    if isinstance(name, bytes):
      name = name.decode(encoding or 'utf-8')

  except Exception as e:
    log('Error: \'{}\' while extracting sender\'s name and address from header'.format(e), level='ERROR')
    name = ''
    pass

  try:
    line = []
    for subject, encoding in decode_header(message['Subject']):
      if isinstance(subject, bytes):
        subject = subject.decode(encoding or 'utf-8')
      line.append(subject)
    #subject = ' '.join([l for l in line])
    subject = ''.join([l.replace('\r\n', '') for l in line])
  except Exception as e:
    log('Error: \'{}\' while extracting subject from header'.format(e), level='ERROR')
    subject = ''
    pass

  if name:
    log('From: {} <{}> | Subject: {}'.format(name, address, subject))
    notify(user, name, subject)
  else:
    log('From: {} | Subject: {}'.format(address, subject))
    notify(user, address, subject)


  #if '*' not in _attachments_['from'] and (not bool(name) or name not in _attachments_['from']):
  if _attachments_['from'] != ['*'] and (not any(n in name for n in _attachments_['from']) and not any(a in address for a in _attachments_['from'])):
    return

  dnldFolder = os.path.join(_attachments_['path'], name if name else address)

  try:
    fileName = ''

    for part in message.walk():
      if part.get_content_maintype() == 'multipart':
        continue

      if part.get('Content-Disposition') is None:
        continue

      fileName, encoding = decode_header(part.get_filename() or '')[0]
      if isinstance(fileName, bytes):
        fileName = fileName.decode(encoding or 'utf-8')

      if bool(fileName):
        fileExt = os.path.splitext(fileName)[1]
        log('Processing attachment \'{}\''.format(fileName), level='DEBUG')

        if '*' not in _attachments_['type'] and (not bool(fileExt) or fileExt not in _attachments_['type']):
          log('Attachment type \'{}\' is not configured for download'.format(fileExt), level='DEBUG')
          return

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
  except Exception as e:
    log('Unexpected exception: \'{}\' while saving attachment \'{}\''.format(e, fileName), level='ERROR')
    pass


if __name__ == '__main__':
  global _config_file_, _log_file_, _debug_, _notification_title_, _msg_from_, _msg_subject_, _socket_timeout_

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host when a new email is received')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  parser.add_argument('-u', '--unseen', dest='unseen', action='store_true', help="Show today's unseen messages (Default: False)")
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
  log('Customization: \'New Message for\': \'{}\' | \'From\': \'{}\' | \'Subject\': \'{}\''.format(_notification_title_, _msg_from_, _msg_subject_), level='DEBUG')

  log('Attachments of types \'{}\' sent from \'{}\' will be saved in \'{}\''.format(','.join(_attachments_['type']), ','.join(_attachments_['from']), _attachments_['path']), level='DEBUG')

  Failure = False

  for account in _accounts_:
    log('Processing mail account \'{}\' ...'.format(account['name']), level='DEBUG')
    try:
      account['connection'] = MailBox(account['server'], account['user'], account['passwd'])

    except Exception as e:
      log('A fatal error occured: \'{}\'. Abort.'.format(e), level='ERROR')
      Failure = True
      break

    if args.unseen:
      log('Fetching unread messages for \'{}\''.format(account['user']))
      today = datetime.date.today().strftime("%d-%b-%Y")
      account['connection'].connect('Inbox')

      # Fetch all unread messages:
      #uid_list = account['connection'].search(None, '(UNSEEN)')

      # Fetch unread messages only for today:
      uid_list = account['connection'].search('ON', today)

      if uid_list:
        for uid in uid_list:
          msg = account['connection'].fetch(uid)
          show(account['user'], msg)

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
