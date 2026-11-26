# Builds the headless Proton Mail Bridge binary used by the container image.
# See docker/README.md for how to build and run the container.

export GO111MODULE=on
export CGO_ENABLED=1

ROOT_DIR:=$(realpath .)

# Keep version hardcoded so app build works also without Git repository.
BRIDGE_APP_VERSION?=3.27.2+git
APP_VERSION:=${BRIDGE_APP_VERSION}
APP_FULL_NAME:=Proton Mail Bridge
REVISION:=$(shell "${ROOT_DIR}/utils/get_revision.sh" rev 2>/dev/null)
TAG:=$(shell "${ROOT_DIR}/utils/get_revision.sh" tag 2>/dev/null)
BUILD_TIME:=$(shell date +%FT%T%z)
BUILD_ENV?=dev
IMAGE?=mailbridge

CONSTANTS:=github.com/ProtonMail/proton-bridge/v3/internal/constants
GO_LDFLAGS:=$(addprefix -X ${CONSTANTS}., Version=${APP_VERSION} Revision=${REVISION} Tag=${TAG} BuildTime=${BUILD_TIME} BuildEnv=${BUILD_ENV})
GO_LDFLAGS+=-X "${CONSTANTS}.FullAppName=${APP_FULL_NAME}"

.PHONY: build build-nogui gofiles docker test clean

build: build-nogui

# Needs gcc, pkg-config and the libsecret, libfido2, libcbor and libssl headers.
build-nogui: gofiles
	CGO_LDFLAGS="-lfido2 -lcbor -lssl -lcrypto" \
		go build -tags='${BUILD_TAGS}' -ldflags '${GO_LDFLAGS}' -o bridge ./cmd/Desktop-Bridge/

gofiles: ./internal/bridge/credits.go
./internal/bridge/credits.go: ./utils/credits.sh go.mod
	cd ./utils/ && ./credits.sh bridge

docker:
	docker build -f docker/Dockerfile -t ${IMAGE} .

test: gofiles
	go test -short ./...

clean:
	rm -f bridge ./internal/bridge/credits.go
