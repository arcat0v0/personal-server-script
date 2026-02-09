#!/bin/sh
# Host-side launcher: spins up Alpine container, runs init script, then validates.
# Usage: ./test-alpine-init.sh [--keep] [--shell] [--image alpine:latest]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER_NAME="alpine-init-test-$$"
ALPINE_IMAGE="alpine:latest"
KEEP_CONTAINER=false
OPEN_SHELL=false
CONTAINER_ENGINE=""

for arg in "$@"; do
    case "$arg" in
        --keep)  KEEP_CONTAINER=true ;;
        --shell) OPEN_SHELL=true; KEEP_CONTAINER=true ;;
        --image=*) ALPINE_IMAGE="${arg#--image=}" ;;
    esac
done

if command -v podman >/dev/null 2>&1; then
    CONTAINER_ENGINE="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_ENGINE="docker"
else
    printf "\033[0;31mNeither podman nor docker found.\033[0m\n"
    exit 1
fi

cleanup() {
    if [ "$KEEP_CONTAINER" = true ]; then
        printf "\n\033[1;36mContainer kept: %s\033[0m\n" "$CONTAINER_NAME"
        printf "  Attach: %s exec -it %s /bin/sh\n" "$CONTAINER_ENGINE" "$CONTAINER_NAME"
        printf "  Remove: %s rm -f %s\n" "$CONTAINER_ENGINE" "$CONTAINER_NAME"
        return
    fi
    printf "\n\033[1;36mCleaning up container: %s\033[0m\n" "$CONTAINER_NAME"
    $CONTAINER_ENGINE rm -f "$CONTAINER_NAME" 2>/dev/null || true
}
trap cleanup EXIT

printf "\033[1;36mEngine: %s | Image: %s | Container: %s\033[0m\n" \
    "$CONTAINER_ENGINE" "$ALPINE_IMAGE" "$CONTAINER_NAME"

printf "\n\033[1;36m>>> Phase 1: Starting container with OpenRC\033[0m\n"
$CONTAINER_ENGINE run -d \
    --name "$CONTAINER_NAME" \
    --hostname alpine-test \
    --privileged \
    "$ALPINE_IMAGE" \
    /bin/sh -c "
        apk add --no-cache openrc openssh >/dev/null 2>&1
        mkdir -p /run/openrc
        touch /run/openrc/softlevel
        rc-status --manual 2>/dev/null || true
        touch /tmp/.bootstrap-done
        tail -f /dev/null
    "

printf "  Waiting for container bootstrap..."
for _i in $(seq 1 30); do
    if $CONTAINER_ENGINE exec "$CONTAINER_NAME" test -f /tmp/.bootstrap-done 2>/dev/null; then
        printf " done\n"
        break
    fi
    sleep 1
    printf "."
done

printf "\n\033[1;36m>>> Phase 2: Copying scripts into container\033[0m\n"
$CONTAINER_ENGINE cp "$SCRIPT_DIR/server-init-alpine.sh" "$CONTAINER_NAME:/tmp/server-init-alpine.sh"
$CONTAINER_ENGINE cp "$SCRIPT_DIR/test-validate.sh" "$CONTAINER_NAME:/tmp/test-validate.sh"

printf "\n\033[1;36m>>> Phase 3: Running server-init-alpine.sh (FORCE_CN=0, non-interactive)\033[0m\n"
$CONTAINER_ENGINE exec -e FORCE_CN=0 "$CONTAINER_NAME" \
    /bin/sh /tmp/server-init-alpine.sh </dev/null
init_exit=$?

if [ "$init_exit" -ne 0 ]; then
    printf "\033[0;31mInit script exited with code %d\033[0m\n" "$init_exit"
fi

printf "\n\033[1;36m>>> Phase 4: Running validation tests\033[0m\n"
$CONTAINER_ENGINE exec "$CONTAINER_NAME" /bin/sh /tmp/test-validate.sh
validate_exit=$?

if [ "$OPEN_SHELL" = true ]; then
    printf "\n\033[1;36m>>> Opening interactive shell in container\033[0m\n"
    $CONTAINER_ENGINE exec -it "$CONTAINER_NAME" /bin/sh
fi

exit $validate_exit
