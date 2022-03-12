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
#from html2text import html2text

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
    _attachments_['type'] = [p.strip(' "\'').lower() for p in config.get('Attachments', 'type').split(',')]
    _attachments_['from'] = [p.strip(' "\'').lower() for p in config.get('Attachments', 'from').split(',')]

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

  def monitor(self, folder, callback=None, catchup=False):
    self.isRunning = False
    self.mon = Process(target=self.update, args=(folder, callback, catchup,))
    self.mon.start()

  def is_idle(self):
    return self.mon.is_alive()

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
      log(' - Connection to \'{}:{}\' failed with error \'{}\''.format(self.server, self.port, e), level='DEBUG')
      raise Exception('Connection failure')

    log(' - Connected to \'{}\''.format(self.server), level='DEBUG')
    try:
      self.imap.login(self.user, self.password)
    except self.imap.error as e:
      log(' - Login of user \'{}\' failed with error \'{}\''.format(self.user, e), level='DEBUG')
      raise Exception('Authentication failure')

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
          if email_msg and callback:
            callback(self.user, email_msg)
      else:
        log('No new UID', level='DEBUG')

    try:
      total_msgs = self.select(folder)
    except Exception as e:
      log('A fatal error occured: {}. Abort.'.format(e), level='ERROR')
      return

    if catchup:
      log('Retrieving unread messages ...', level='DEBUG')
      # Fetch all unread messages of past x days:
      #date = (datetime.date.today() - datetime.timedelta(x)).strftime("%d-%b-%Y")
      #uid_list = self.search('SENTSINCE', date)

      # Fetch unread messages only for today:
      today = datetime.date.today().strftime("%d-%b-%Y")
      uid_list = self.search('ON', today)

      if uid_list:
        log(' - Found {} unread messages'.format(len(uid_list)), level='DEBUG')
        for uid in uid_list:
          email_msg = self.fetch(uid)
          callback(self.user, email_msg)
      else:
        log(' - No unread messages', level='DEBUG')

    self.isRunning = True

    while(self.isRunning):
      try:
        for num, msg in self.imap.idle():
          if msg == b'EXISTS':
            log('Size of \'{}\' has changed. {} messages (current) --> {} messages (new)'.format(folder, total_msgs, int(num)), level='DEBUG')
            counter = int(num)
            if counter > total_msgs:
              self.imap.done()
              evaluate(total_msgs, counter, callback)

            total_msgs = counter
            log('Size of \'{}\' updated: {} messages'.format(folder, total_msgs), level='DEBUG')

      except Exception as e:
        log('Exception captured: \'{}\'. Reconnecting to \'{}\' ...'.format(e, self.server), level='DEBUG')

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


def idle(connection):
  socket = None
  connection.loop = False
  connection.tag = None
  response = b''

  try:
    socket = connection.socket()
    if socket and _socket_timeout_ > 0:
      socket.settimeout(_socket_timeout_)

    connection.tag = connection._new_tag()
    connection.send(connection.tag + b' IDLE\r\n')

    response = connection.readline().strip()

    if response.startswith(b'+'):
      log('{} IDLE started'.format(connection.tag.decode('utf-8')), level='DEBUG')
    else:
      log('{} IDLE; Response: \'{}\''.format(connection.tag.decode('utf-8'), response.replace(b'\r\n', b'').decode('utf-8')), level='DEBUG')
      raise Exception('Failed to IDLE')

    connection.loop = True

    while connection.loop:
      try:
        response = connection.readline().strip()
        log('{} IDLE; Response: \'{}\''.format(connection.tag.decode('utf-8'), response.replace(b'\r\n', b'').decode('utf-8')), level='DEBUG')

        if response.startswith(b'* OK'):
          continue

        elif response.startswith(b'* BYE '):
          raise Exception('Connection closed')

        else:
          num, message = response.split(maxsplit=2)[1:]
          if num.isdigit():
            yield num, message
      # Let's add this except block to catch the socket timeouts
      except (socket_error, OSError):
        raise Exception('Connection timed out')
      except:
        raise
  except:
    raise


def done(connection):
  connection.send(b'DONE\r\n')
  connection.loop = False
  try:
    response = connection.readline().strip()
    if response.startswith(b'*'):
      response = connection.readline().strip()
    if response.split(maxsplit=2)[1] == b'OK':
      log('{} IDLE completed'.format(connection.tag.decode('utf-8')), level='DEBUG')
  except:
    pass


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
      log('KODI host \'{}\' is down; Skip sending notification'.format(host), level='DEBUG')


def show(user, message):
  if not message:
    return

  try:
    name, address = parseaddr(message['From'])
    if not address:
      log('Could not parse sender\'s mail address from header', level='ERROR')
      return

    line = []
    for name, encoding in decode_header(name):
      if isinstance(name, bytes):
        name = name.decode(encoding or 'utf-8')
      line.append(name)
    name = ''.join([l.replace('\r\n', '') for l in line])
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


  if _attachments_['from'] != ['*'] and (not any(n in name.lower() for n in _attachments_['from']) and not any(a in address.lower() for a in _attachments_['from'])):
    return

  dnldFolder = os.path.join(_attachments_['path'], name if name else address)

  try:
    fileName = ''
    body = ''

    for part in message.walk():
      log('Content-Type:        {}'.format(part.get_content_type()), level='DEBUG')
      log('Content-Disposition: {}'.format(part.get('Content-Disposition')), level='DEBUG')

      if part.get_content_maintype() == 'multipart':
        continue

      if part.get('Content-Disposition') is None:
      #if "attachment" not in part.get('Content-Disposition'):
        #if part.get_content_type() == 'text/plain':
        #  body = part.get_payload(decode=True).decode('utf-8')
        #if part.get_content_type() == 'text/html' and not body::
        #  body = html2text(part.get_payload(decode=True).decode('utf-8'))
        continue

      fileName, encoding = decode_header(part.get_filename() or '')[0]
      if isinstance(fileName, bytes):
        fileName = fileName.decode(encoding or 'utf-8')

      if bool(fileName):
        fileExt = os.path.splitext(fileName)[-1]
        log('Processing attachment \'{}\''.format(fileName), level='DEBUG')

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
  except Exception as e:
    log('Unexpected exception: \'{}\' while saving attachment \'{}\''.format(e, fileName), level='ERROR')
    pass


if __name__ == '__main__':
  global _config_file_, _log_file_, _debug_, _notification_title_, _msg_from_, _msg_subject_, _socket_timeout_

  parser = argparse.ArgumentParser(description='Sends a notification to a kodi host when a new email is received')

  parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Output debug messages (Default: False)")
  parser.add_argument('-u', '--unseen', dest='unseen', action='store_true', help="Show today's unseen messages (Default: False)")
  parser.add_argument('-l', '--logfile', dest='log_file', default=None, help="Path to log file (Default: None=stdout)")
  parser.add_argument('-t', '--timeout', dest='timeout', default=840, help="Connection Timeout (Default: 840 sec. = 14 min.)")
  parser.add_argument('-c', '--config', dest='config_file', default=os.path.splitext(os.path.basename(__file__))[0] + '.ini', help="Path to config file (Default: <Script Name>.ini)")

  args = parser.parse_args()

  _config_file_ = args.config_file
  _log_file_ = args.log_file
  _debug_ = args.debug
  _socket_timeout_ = int(args.timeout)

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

  for account in _accounts_:
    log('Processing mail account \'{}\' ...'.format(account['name']), level='DEBUG')
    try:
      account['connection'] = MailBox(account['server'], account['user'], account['passwd'])
    except Exception as e:
      log('A fatal error occured: \'{}\'. Abort.'.format(e), level='ERROR')
      Failure = True
      break

    account['connection'].monitor('Inbox', callback=show, catchup=args.unseen)
    time.sleep(1)

  while(not Failure):
    try:
      # Check if processes are still alive:
      for account in _accounts_:
        if 'connection' in account and not account['connection'].is_idle():
          log('Idle process appears to be dead. Reconnecting to \'{}\'.'.format(account['server']), level='DEBUG')
          try:
            account['connection'].connect()
          except Exception as e:
            log('A fatal error occured: \'{}\'. Abort.'.format(e), level='ERROR')
            Failure = True
            break
          account['connection'].monitor('Inbox', callback=show)
        time.sleep(1)

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
