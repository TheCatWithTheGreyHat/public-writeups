FROM ubuntu AS app
FROM pwn.red/jail

COPY --from=app / /srv
COPY chall /srv/app/chall
COPY run.sh /srv/app/run
COPY lib /srv/app/lib
COPY ld.so.2 /srv/app/ld.so.2
COPY flag.txt /srv/app/flag.txt