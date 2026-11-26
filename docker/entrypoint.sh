#!/bin/sh
# Prepares the data volume, then runs mailbridge as the unprivileged "bridge" user.
set -eu

DATA="${HOME:-/data}"
export HOME="$DATA"

# Started as root (the default): fix ownership of the volume, then drop privileges.
if [ "$(id -u)" = "0" ]; then
    RUN_UID="${PUID:-1000}"
    RUN_GID="${PGID:-1000}"
    if [ "$RUN_UID" = "0" ]; then
        echo "[entrypoint] PUID must not be 0: bridge and the mail server do not run as root" >&2
        exit 1
    fi
    # Dovecot (MAILBRIDGE_DOVECOT=on) only serves mail for a user it finds in
    # /etc/passwd, so the "bridge" user follows PUID and PGID.
    if [ "$(id -g bridge)" != "$RUN_GID" ]; then
        groupmod --non-unique --gid "$RUN_GID" bridge
    fi
    if [ "$(id -u bridge)" != "$RUN_UID" ]; then
        usermod --non-unique --uid "$RUN_UID" bridge 2>/dev/null
    fi
    mkdir -p "$DATA"
    if [ "$(stat -c '%u:%g' "$DATA")" != "$RUN_UID:$RUN_GID" ]; then
        echo "[entrypoint] fixing ownership of $DATA"
        chown -R "$RUN_UID:$RUN_GID" "$DATA"
    fi
    # tini goes after the privilege drop so that it may signal its child
    # without needing CAP_KILL.
    exec setpriv --reuid "$RUN_UID" --regid "$RUN_GID" --clear-groups -- /usr/bin/tini -- "$0" "$@"
fi

# Started directly as an unprivileged user (docker run --user): still put an
# init in front, gpg-agent leaves children behind that need reaping.
if [ "$$" = "1" ]; then
    exec /usr/bin/tini -- "$0" "$@"
fi

umask 077
export GNUPGHOME="$DATA/.gnupg"
export PASSWORD_STORE_DIR="$DATA/.password-store"

# Bridge keeps the key that encrypts its vault in a keychain. Inside a container
# that is "pass", backed by a GPG key without passphrase that lives in the volume.
# Whoever can read the volume can read the mail credentials: protect it accordingly.
if ! gpg --batch --list-secret-keys "mailbridge" >/dev/null 2>&1; then
    echo "[entrypoint] first start: creating the keychain"
    mkdir -p "$GNUPGHOME"
    chmod 700 "$GNUPGHOME"
    gpg --batch --quiet --passphrase '' --quick-generate-key "mailbridge" default default never
fi
if [ ! -f "$PASSWORD_STORE_DIR/.gpg-id" ]; then
    pass init "mailbridge" >/dev/null
fi

# gRPC socket files of a previous run are left behind when the container is killed.
rm -f /tmp/bridge[0-9][0-9][0-9][0-9] 2>/dev/null || true

exec /usr/local/bin/mailbridge "$@"
