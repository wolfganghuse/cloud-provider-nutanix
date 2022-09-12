# Image URL to use all building/pushing image targets
IMG ?= quay.io/wolfgangntnx/nutanix-cloud-controller-manager:lb004
VERSION = 0.1.0

build: vendor
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -ldflags="-w -s -X 'main.version=${VERSION}'" -o=bin/nutanix-cloud-controller-manager main.go

vendor:
	go mod tidy
	go mod vendor
	go mod verify

docker-image:
	docker build -t ${IMG} -f ./Dockerfile .

docker-push:
	docker push ${IMG}

## --------------------------------------
## Unit tests
## --------------------------------------

.PHONY: unit-test
unit-test:
	go test --cover -v ./... -coverprofile cover.out
	
.PHONY: unit-test-html
unit-test-html: unit-test
	go tool cover -html=cover.out

## --------------------------------------
## OpenShift specific include
## --------------------------------------

include ./openshift/openshift.mk
