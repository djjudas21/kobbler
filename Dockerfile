FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt .

ENV GIT_SSL_NO_VERIFY=true

RUN apk add --no-cache coreutils

RUN apk add --no-cache --virtual .build-deps gcc musl-dev git rust cargo libffi-dev openssl-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY artifact-backer-upper.py .

ENTRYPOINT [ "python", "./artifact-backer-upper.py" ]
