FROM python:3-alpine

WORKDIR /usr/src/app

COPY requirements.txt .

ENV GIT_SSL_NO_VERIFY=true

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

RUN apk add --no-cache coreutils curl gnupg ca-certificates

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

RUN apk add --no-cache --virtual .build-deps gcc musl-dev linux-headers \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-deps

COPY artifact-backup.py .

ENTRYPOINT [ "python", "-u", "./artifact-backup.py" ]
