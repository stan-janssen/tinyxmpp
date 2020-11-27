# tinyXMPP

tinyXMPP is a small XMPP client for Python applications. It allows developer to easily connect to XMPP servers and exchange messages in a fast and secure way.

## Getting Started

```
pip install tinyxmpp
```

To connect to an XMPP server:

```python
from tinyxmpp import XMPPClient

async def main():
    client = XMPPClient(jid='user@xmppserver.net/python',
                        password='mypassword')
    client.on_message = on_message
    client.on_iq = on_iq
    client.on_presence = on_presence
    await client.connect(host_addr='xmppserver.net')
    await client.send_message(to='someuser@xmppserver.net/Resource',
                              message='Hello There')

async def on_message(message):
    print(message)

async def on_presence(element):
    print(element)

async def on_iq(element):
    print(element)

loop = asyncio.get_event_loop()
loop.create_task(main())
loop.run_forever()

```

## License

This project is made available under the Apache 2.0 License.

## Contruibu