from time import time
from numpy.random import randint, random
import numpy as np

from dht.test_hooks import LRUCacheDummy, get_lru_none, get_lru_empty


def test_lru_basic():

    lru = LRUCacheDummy(10)

    assert len(lru) == 0
    lru.poptail()
    lru.pophead()
    assert lru.poptail() is get_lru_empty()
    assert len(lru) == 0

    lru.insert(0, 10)
    lru.insert(1, 11)
    lru.insert(0, 100)
    lru.traverse()

    assert lru.pophead() == (0, 100)
    assert len(lru) == 1

    for i in range(20):
        lru.insert(i, 10 * i)
    lru.traverse()

    assert lru.pop(15) == 150
    assert lru.pop(17) == 170
    assert lru.pop(5) is get_lru_none()

    assert lru.pophead() == (19, 190)
    assert len(lru) == 7
    assert lru.poptail() == (10, 100)
    assert len(lru) == 6

    for i in range(10):
        lru.insert(0, i)
    lru.traverse()

    assert lru.pophead() == (0, 9)
    assert len(lru) == 6


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
