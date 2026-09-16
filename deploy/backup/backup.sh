#!/bin/sh
# Dumps the database to S3 once at startup and then every
# BACKUP_INTERVAL_SECONDS (default one day). Connection settings come from the
# standard PGHOST / PGUSER / PGPASSWORD / PGDATABASE variables.
#
#   cloudguard-backup          run forever
#   cloudguard-backup --once   single backup, exit non-zero on failure
set -eu

: "${S3_BUCKET_NAME:?S3_BUCKET_NAME is required}"
interval="${BACKUP_INTERVAL_SECONDS:-86400}"
prefix="${BACKUP_PREFIX:-backups}"

log() {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"
}

aws_s3() {
    if [ -n "${AWS_ENDPOINT_URL:-}" ]; then
        aws --endpoint-url "$AWS_ENDPOINT_URL" s3 "$@"
    else
        aws s3 "$@"
    fi
}

backup() {
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    dump="/tmp/cloudguard-${stamp}.dump"
    key="${prefix}/cloudguard-${stamp}.dump"

    # Dump to a local file first so a failed dump never replaces a good backup
    # with a truncated one.
    if ! pg_dump --format=custom --no-owner --file="$dump"; then
        log "backup failed: pg_dump exited non-zero"
        rm -f "$dump"
        return 1
    fi

    size=$(wc -c < "$dump")
    if ! aws_s3 cp "$dump" "s3://${S3_BUCKET_NAME}/${key}" --only-show-errors; then
        log "backup failed: upload to s3://${S3_BUCKET_NAME}/${key}"
        rm -f "$dump"
        return 1
    fi

    rm -f "$dump"
    log "backup ok: s3://${S3_BUCKET_NAME}/${key} (${size} bytes)"
}

if [ "${1:-}" = "--once" ]; then
    backup
    exit $?
fi

log "starting, interval ${interval}s"
until pg_isready --quiet; do
    sleep 2
done

while true; do
    backup || true
    sleep "$interval"
done
