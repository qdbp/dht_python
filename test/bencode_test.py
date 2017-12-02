#FIXME : need real examples to test bdecode_st
# from dht.bencode import bencode, bdecode

# def test_decode():
#     assert bdecode(b'1:f') == b'f'
#     assert bdecode(b'10:fooooooooo') == b'fooooooooo'
# 
#     assert bdecode(b'i0e') == 0
#     assert bdecode(b'i11e') == 11
#     assert bdecode(b'i10e') == 10
#     assert bdecode(b'i111e') == 111
#     assert bdecode(b'i-10e') == -10
# 
#     assert bdecode(b'de') == {}
#     assert bdecode(b'le') == []
# 
#     assert bdecode(b'di1elee') == {1: []}
#     assert bdecode(b'd1:k1:v2:dkd3:fooli10ei20eeee') == {
#         b'k': b'v',
#         b'dk': {
#             b'foo': [10, 20]
#         }
#     }


# def test_encode():
#     pass
