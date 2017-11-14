import sys
import signal as sig
import threading as thr

from dht.stateless import LOG, DHTScraper


def main():
    LOG.info('started main')
    scraper = DHTScraper()
    scraper.run()


if __name__ == '__main__':
    main()
