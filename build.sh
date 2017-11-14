cd dht

for i in *.pyx; do
    bn="${i%.pyx}"
    cython "${i}" -o "${bn}.c"
    gcc -Wall -shared -pthread -fwrapv -I/usr/include/python3.6m \
        -fPIC -O3 -march=native -mtune=native "${bn}.c" \
        -o "${bn}.so"
    rm "${bn}.c"
done
