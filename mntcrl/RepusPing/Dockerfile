FROM pwn.red/jail
COPY --from=debian:bookworm / /srv/

COPY --chmod=755 run.sh /srv/app/run
COPY --chmod=755 chall /srv/app/chall

COPY ./lib/ /srv/app/lib

EXPOSE 5000

#ENV JAIL_ENV_FLAG=mntcrl{fake_flag_for_testing}
ENV JAIL_MEM=200M JAIL_TMP_SIZE=10M JAIL_PIDS=100 JAIL_CPU=100 JAIL_TIME=180
ENV JAIL_ENV_PATH=/usr/local/bin:/usr/bin:/bin

ENV JAIL_BIN=/app/run 
