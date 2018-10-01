import signal as sig
import sys
import threading as thr

from dht.dht import LOG, DHTScraper


def main():
    LOG.info('started main')
    scraper = DHTScraper()
    scraper.run()


if __name__ == '__main__':
    main()
