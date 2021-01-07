FROM scratch
COPY build/linux/kh-tls-check /
ENTRYPOINT ["/kh-tls-check"]