#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import select
import ssl

from socket import error as socket_error, create_connection as create_connection

# User defined Exceptions
class IDLE_FAILED(Exception):
  pass

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


def done(connection, debug=None):
  if connection.state == 'IDLE':
    if debug:
      debug('Sending \'DONE\' to terminate {} IDLE process'.format(connection.tag.decode()))
    connection.send(b'DONE' + imaplib.CRLF)


def readsock(sock, timeout=60):
  while True:
    try:
      readable = select.select([sock], [], [], timeout)[0]

      if readable:
        try:
          data = sock.recv(1024)

        except ssl.SSLError as e:
          if e.errno != ssl.SSL_ERROR_WANT_READ:
            raise
          continue

        if not data:
          break

        data_left = sock.pending()
        while data_left:
          data += sock.recv(data_left)
          data_left = sock.pending()

        return [response.strip() for response in data.split(imaplib.CRLF) if response]

      #else:
      #  pass

    except:
      raise

  return []


def idle(connection, timeout=840, debug=None):
  try:
    connection.state_before_idle = connection.state
    connection.tag = connection._new_tag()

    connection.send(connection.tag + b' IDLE' + imaplib.CRLF)

    connection.sock.setblocking(False)
    #connection.state = 'IDLE'

    #while connection.state == 'IDLE':
    while True:
      try:
        readable = select.select([connection.sock], [], [], timeout)[0]

        if readable:
          #for response in iter(connection.readline, b''):
          #  response = response.strip()

          # Alternative start
          try:
            data = connection.sock.recv(1024)

          except ssl.SSLError as e:
            if e.errno == ssl.SSL_ERROR_WANT_READ:
              continue
            raise

          if not data:
            break

          data_left = connection.sock.pending()
          while data_left:
            data += connection.sock.recv(data_left)
            data_left = connection.sock.pending()

          responses = [response.strip() for response in data.split(imaplib.CRLF) if response]

          #if debug:
          #  debug('{} IDLE: {}'.format(connection.tag.decode(), responses))

          for response in responses:
          # Alternative end

            if debug:
              debug('{} IDLE: {}'.format(connection.tag.decode(), response.decode()))

            if response.startswith(b'+'):
              connection.state = 'IDLE'

            if response.startswith(connection.tag + b' OK'):
              raise IDLE_COMPLETE('IDLE completed (\'{}\')'.format(response.decode()))

            elif response.startswith(b'* BYE '):
              raise IDLE_DISCONNECT('Connection closed by server (\'{}\')'.format(response.decode()))

            elif len(response.split(maxsplit=2)) == 3:
              num, message = response.split(maxsplit=2)[1:]
              if num.isdigit():
                yield num, message

        else:
          if debug:
            debug('{} IDLE: User defined timeout'.format(connection.tag.decode()))
          connection.done(debug=debug)

      except ssl.SSLError as e:
        #if  e.errno == ssl.SSL_ERROR_WANT_READ:
        #  continue
        raise IDLE_DISCONNECT('Connection closed by server (\'{}\')'.format(str(e)))

      except (socket_error, OSError) as e:
        raise IDLE_TIMEOUT('Connection timed out (\'{}\')'.format(str(e)))

      except:
        raise

  except:
    raise

  finally:
    connection.state = connection.state_before_idle
    connection.sock.setblocking(True)


#imaplib.Debug = 4
#imaplib.IMAP4.idle = idle
#imaplib.IMAP4.done = done
