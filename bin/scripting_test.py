import asyncio
import logging

from pyrdp.logging import log

from pyrdp.core import defer
from pyrdp.scripting import RDPClient

from twisted.internet import asyncioreactor

asyncioreactor.install(asyncio.get_event_loop())

from twisted.internet import reactor

async def main():
    rdp = RDPClient()
    await rdp.connect("127.0.0.1", 3390, "test", "test")

async def startMain():
    try:
        await main()
    except:
        import traceback
        traceback.print_exc()
        raise

    reactor.stop()

if __name__ == "__main__":
    log.prepare_pyrdp_logger(logging.DEBUG)
    log.prepare_ssl_session_logger()
    defer(startMain())
    reactor.run()