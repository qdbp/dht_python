from time import time
from numpy.random import randint, random
import numpy as np

from dht.test_hooks import LRUCacheDummy


def test_lru_basic():

    lru = LRUCacheDummy(10)

    assert len(lru) == 0
    lru.poptail()
    lru.pophead()
    lru.poptail()
    assert len(lru) == 0

    lru.insert(0, 10)
    lru.insert(1, 11)
    lru.insert(0, 100)

    assert lru.pophead() == (0, 100)
    assert len(lru) == 1

    for i in range(20):
        lru.insert(i, 10 * i)

    assert lru.pophead() == (19, 190)
    assert len(lru) == 9
    assert lru.poptail() == (10, 100)
    assert len(lru) == 8

    for i in range(10):
        lru.insert(0, i)

    assert lru.pophead() == (0, 9)
    assert len(lru) == 8


def test_lru_fuzz():

    for i in np.logspace(1, 4, num=10, dtype=np.uint64):
        c = LRUCacheDummy(i)

        for k, v in zip(randint(0, 10, 1000), randint(0, 10, 1000)):
            poptail = random() < 0.005
            pophead = random() < 0.005
            print(i, k, v, pophead, poptail)
            c.traverse()

            c.insert(k, v)
            c.get(v)
            if poptail:
                c.poptail()
            if pophead:
                c.pophead()
