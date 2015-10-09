POODLE proof-of-concept
=======================

Python framework that implements a working PoC for exploiting the POODLE vulnerability. This is a preemtive move so that I can use this code as reference if this flaw ever comes up in a CTF.

What does it do?
----------------

The `poodle` module contains a POODLE class which implements the logic
for exploiting the POODLE vulnerability.

How does it work?
-----------------

We'll look at `poodle-sample-1.py` as an example to explain how this PoC works and
make parallel with how this would be exploited in the real world.

There are 3 components to this attack: a client, a server and
an attacker-controlled MitM proxy.

The server, implemented by `SecureTCPHandler` here, is a perfectly normal
SSL server. This would typically be a HTTP server which accepts requests
from any client. The attacker cannot "read" the data being exchanged between
the server and the client.

The client, implemented by `POODLE_Client` here, would typically be a web
browser. The client holds a secret, which in reality would be a HTTP cookie,
which the attacker wants to read. The attacker does not have access to read
the client requests nor the server's responses, but it does have the ability
to influence the client to make arbitrary requests. If the attacker is in a
Man-in-the-Middle situation between the client and the server, this could be
done by injecting a small snippet of javascript on any HTTP website
visited by the client which forces the client to makes AJAX POST requests to
the victim server. All requests would contain the HTTP cookie that the attacker
wants to recover. In `poodle-sample-1.py`, this exact situation is replicated
by sending messages in which the attacker controls two fields:

```python
s.send('%s|secret=%s|%s' % (prefix, secret, suffix))
```

`prefix` takes the role of the URI path, and `suffix` takes the role of the
request body. The attack revolves around the fact that these two fields can
be made to change lengths by the attacker.

A MitM proxy, sitting between the client and the SSLv3 server, implemented
by `MitmTCPHandler` here. The attacker cannot decrypt the SSL traffic, but
he can modify parts of the message.

The actual attack is started by calling `POODLE.run()`. A subclass of `POODLE`
has to implement the logic in `trigger()`. This method has to force the client to
make a request to the server, which goes through the MitM proxy. The implementor
also has the responsibility of extracting the encrypted Application Data message
from the SSL stream and call `POODLE.message_callback()` with the data. The method
will return the altered data that the implementor must forward via the MitM
proxy. One of the two methods `POODLE.mark_error()` or `POODLE.mark_success()`
has to be called depending on whether the SSL connection terminated early,
indicating a decryption failure (error), or continued as normal (success).
This all has to be done before the call to `trigger()` returns. Provided these
conditions are met, the `POODLE` class will handle the rest.

More Resources
---------------
1. https://www.openssl.org/~bodo/ssl-poodle.pdf
2. http://googleonlinesecurity.blogspot.ca/2014/10/this-poodle-bites-exploiting-ssl-30.html
3. https://www.imperialviolet.org/2014/10/14/poodle.html
