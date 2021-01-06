FROM scratch
COPY build/kh-tls-check /
ENTRYPOINT ["/kh-tls-check"]