# builder image
FROM golang:alpine as builder
RUN mkdir /build
ADD *.go /build/
ADD go.mod /build/
ADD go.sum /build/
WORKDIR /build
RUN CGO_ENABLED=0 GOOS=linux go build -a -o app .


# generate clean, final image for end users
FROM alpine
COPY --from=builder /build/app .
RUN mkdir html
ADD html/* html/

# executable
ENTRYPOINT [ "./app" ]
