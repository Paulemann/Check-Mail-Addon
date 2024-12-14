#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import select
import ssl

from socket import error as socket_error, create_connection as create_connection


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


def done(connection, debug=None):
  if connection.state == 'IDLE':
    if debug:
      debug('Sending \'DONE\' for {}'.format(connection.tag.decode()))
    connection.send(b'DONE' + imaplib.CRLF)


def idle(connection, timeout=840, debug=None):
  try:
    connection.state_before_idle = connection.state
    connection.tag = connection._new_tag()

    connection.send(connection.tag + b' IDLE' + imaplib.CRLF)
    response = connection.readline().strip()

    if not response.startswith(b'+'):
      raise Exception('Failed to IDLE')

    if debug:
      debug('{} IDLE started: \'{}\''.format(connection.tag.decode(), response.decode()))

    connection.sock.setblocking(False)
    connection.state = 'IDLE'

    while connection.state == 'IDLE':
      try:
        readable = select.select([connection.sock], [], [], timeout)[0]

        if readable:
          for response in iter(connection.readline, b''):
            response = response.strip()
            if debug:
              debug('{} IDLE; Response: \'{}\''.format(connection.tag.decode(), response.decode()))

            if response.startswith(connection.tag + b' OK'):
              raise IDLE_COMPLETE('IDLE completed')

            elif response.startswith(b'* BYE '):
              raise IDLE_DISCONNECT('Connection closed by server')

            else:
              num, message = response.split(maxsplit=2)[1:]
              if num.isdigit():
                yield num, message

        else:
          if debug:
            debug('{} IDLE; User defined timeout'.format(connection.tag.decode()))
          connection.done(debug=debug)

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
#imaplib.IMAP4.idle = idle
#imaplib.IMAP4.done = done
