#!/bin/bash
# создаём пары: /dev/ttyS10<->S11, 12<->13, 14<->15, 16<->17
for base in 11 13 15 17; do
  socat -d -d \
    PTY,link=/dev/ttyS${base},raw,echo=0 \
    PTY,link=/dev/ttyS$((base+1)),raw,echo=0 \
    &
done
