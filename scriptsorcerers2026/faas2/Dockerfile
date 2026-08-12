FROM ubuntu:latest

RUN apt update &&  apt install -y socat && apt install -y curl && useradd -m -s /bin/bash chall
USER chall
COPY fetch srv/REDACTED
COPY REDACTED.txt srv/REDACTED.txt

WORKDIR /srv

ENTRYPOINT ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:\"./REDACTED `cat REDACTED.txt`\""] # What do you mean this does not work????
