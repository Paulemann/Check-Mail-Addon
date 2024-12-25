#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import select
import ssl

from socket import error as socket_error, create_connection as create_connection

# User defined Exceptions
class IMAP_IDLE_FAILED(Exception):
  pass

class IMAP_IDLE_DISCONNECT(Exception):
  pass

class IMAP_IDLE_TIMEOUT(Exception):
  pass

class IMAP_IDLE_COMPLETE(Exception):
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


def idle(connection, timeout=840, debug=None):
  try:
    connection.state_before_idle = connection.state
    connection.tag = connection._new_tag()

    connection.send(connection.tag + b' IDLE' + imaplib.CRLF)

    connection.sock.setblocking(False)
    connection.state = 'IDLE'

    buffer = b''

    while True:
      try:
        readable = select.select([connection.sock], [], [], timeout)[0]

        if readable:

          """
          for response in iter(connection.readline, b''):
            response = response.strip()
          """

          try:
            data = buffer + connection.sock.recv(1024)

          except ssl.SSLError as e:
            if e.errno == ssl.SSL_ERROR_WANT_READ:
              continue
            raise

          if not data:
            if debug:
              debug('{} IDLE: No data'.format(connection.tag.decode()))
            break

          data_left = connection.sock.pending()
          while data_left:
            data += connection.sock.recv(data_left)
            data_left = connection.sock.pending()

          if data.endswith(imaplib.CRLF):
            buffer = b''
          else:
            buffer = data
            continue

          responses = [response.strip() for response in data.split(imaplib.CRLF) if response]

          for response in responses:

            if debug:
              debug('{} IDLE: {}'.format(connection.tag.decode(), response.decode()))

            #if response.startswith(b'+'):
            #  connection.state = 'IDLE'

            if response.startswith(connection.tag + b' OK'):
              raise IMAP_IDLE_COMPLETE('IDLE completed (\'{}\')'.format(response.decode()))

            elif response.startswith(b'* BYE '):
              raise IMAP_IDLE_DISCONNECT('Connection closed by server (\'{}\')'.format(response.decode()))

            elif len(response.split(maxsplit=2)) == 3:
              num, message = response.split(maxsplit=2)[1:]
              if num.isdigit():
                yield num, message

        else:
          if debug:
            debug('{} IDLE: User defined timeout'.format(connection.tag.decode()))
          connection.done(debug=debug)

      except ssl.SSLError as e:
        """
        if  e.errno == ssl.SSL_ERROR_WANT_READ:
          continue
        """
        raise IMAP_IDLE_DISCONNECT('Connection closed by server (\'{}\')'.format(str(e)))

      except (socket_error, OSError) as e:
        raise IMAP_IDLE_TIMEOUT('Connection timed out (\'{}\')'.format(str(e)))

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
