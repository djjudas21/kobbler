FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt .

ENV GIT_SSL_NO_VERIFY=true

ARG etcdversion=v3.5.0

RUN apk add --no-cache coreutils

RUN apk add --no-cache --virtual .build-deps curl ca-certificates \
    && curl -L https://github.com/etcd-io/etcd/releases/download/$etcdversion/etcd-$etcdversion-linux-amd64.tar.gz | \
        tar xz etcd-$etcdversion-linux-amd64/etcdctl --strip-components=1 -C /usr/bin \
    && chmod +x /usr/bin/etcdctl \
    && apk del .build-deps

RUN apk add --no-cache --virtual .build-deps gcc musl-dev git rust cargo libffi-dev openssl-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

RUN apk add --no-cache -X http://dl-cdn.alpinelinux.org/alpine/edge/testing words-gb

COPY artifact-backer-upper.py .

ENTRYPOINT [ "python", "./artifact-backer-upper.py" ]
