# pg_dump has to match the server's major version, so build on the same image
# the database runs from and add the AWS CLI for the upload.
FROM docker.io/pgvector/pgvector:pg16

RUN apt-get update \
    && apt-get install -y --no-install-recommends awscli \
    && rm -rf /var/lib/apt/lists/*

COPY backup.sh /usr/local/bin/cloudguard-backup
RUN chmod 755 /usr/local/bin/cloudguard-backup

USER postgres
ENTRYPOINT ["cloudguard-backup"]
