FROM golang:1.20 AS builder

WORKDIR /build
COPY . .
RUN make build

FROM scratch

LABEL description="Nutanix Cloud Controller Manager"

COPY --from=builder /build/bin/nutanix-cloud-controller-manager /bin/nutanix-cloud-controller-manager

ENTRYPOINT [ "/bin/nutanix-cloud-controller-manager" ]
