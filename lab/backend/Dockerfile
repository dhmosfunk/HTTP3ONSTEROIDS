FROM debian:latest

RUN apt update && apt upgrade && apt install -y \
    socat \
    bash

RUN mkdir /www
WORKDIR /www

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 8080

CMD ["./entrypoint.sh"]
