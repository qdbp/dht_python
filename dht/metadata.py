'''
Gets metadata for torrents found through dht.
'''

# md: fixed strings
MD_HS_HEAD = b'\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x00'
MD_HS_TAIL = '-酔生夢死-'.encode('utf-8') + b'\x77' * 6

def get_metadata(self, addr, info_hash):
    ix = self.av_socks.pop()
    s = self.md_sock_pool[ix]
    try:
        s.create_connection(addr, MD_SOCK_TO)
        hs = MD_HS_HEAD + info_hash + MD_HS_TAIL
        s.send(hs)
        m = s.recv(67)
        print(m)

    except Exception:
        self.cnt['md_sc_err'] += 1
    finally:
        s.detach()
        self.av_socks.add(ix)

