# Block 16 - image of one scale-test node: Ubuntu 24.04 (same as the client VMs) + the PQC runtime of
# block 09 (OpenSSL 3.4.0 + oqs-provider) + phc-client (phc-bench, phc-verify) + certdist-client.
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY pqc-runtime.tgz /tmp/
RUN tar -xzf /tmp/pqc-runtime.tgz -C / --exclude=usr/lib/ssl/openssl.cnf && ldconfig
COPY phc-client /src/phc-client
RUN cmake -S /src/phc-client -B /src/phc-client/build >/dev/null && cmake --build /src/phc-client/build -j 4
COPY certdist-client.c /src/
# certdist-client: the client of block 10 as is (60 s I/O timeout);
# certdist-client-long: same code with a 1800 s timeout, for the "retry" policy of 16-scale.sh
RUN gcc -O2 -Wall -Wextra -o /usr/local/bin/certdist-client /src/certdist-client.c \
    && sed 's/^#define IO_TIMEOUT_S 60$/#define IO_TIMEOUT_S 1800/' /src/certdist-client.c > /src/certdist-client-long.c \
    && grep -q '^#define IO_TIMEOUT_S 1800$' /src/certdist-client-long.c \
    && gcc -O2 -Wall -Wextra -o /usr/local/bin/certdist-client-long /src/certdist-client-long.c

FROM ubuntu:24.04
COPY pqc-runtime.tgz /tmp/
RUN tar -xzf /tmp/pqc-runtime.tgz -C / --exclude=usr/lib/ssl/openssl.cnf && ldconfig && rm /tmp/pqc-runtime.tgz \
    && LD_LIBRARY_PATH=/opt/openssl32/lib64:/opt/openssl32/lib /opt/openssl32/bin/openssl list -providers | grep -q oqsprovider
COPY --from=build /src/phc-client/build/phc-bench /src/phc-client/build/phc-verify /usr/local/bin/
COPY --from=build /usr/local/bin/certdist-client /usr/local/bin/certdist-client-long /usr/local/bin/
COPY ca-certs /pki/ca-certs
COPY scale-node.sh /usr/local/bin/scale-node.sh
ENTRYPOINT ["/usr/local/bin/scale-node.sh"]
