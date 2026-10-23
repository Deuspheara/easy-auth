FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS packages
RUN apt-get update && apt-get install -y --no-install-recommends nginx-light ca-certificates \
    && rm -rf /var/lib/apt/lists/* && mkdir /out \
    && dpkg-query -s nginx libcrypt1 libpcre2-8-0 > /out/native-status
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf
COPY --from=packages /usr/sbin/nginx /usr/sbin/nginx
COPY --from=packages /usr/lib/*-linux-gnu/libcrypt.so.1* /usr/lib/
COPY --from=packages /usr/lib/*-linux-gnu/libpcre2-8.so.0* /usr/lib/
COPY --from=packages /out/native-status /var/lib/dpkg/status.d/easy-auth-proxy
COPY --from=packages /usr/share/doc/nginx/copyright /usr/share/doc/nginx/copyright
COPY --from=packages /usr/share/doc/libcrypt1/copyright /usr/share/doc/libcrypt1/copyright
COPY --from=packages /usr/share/doc/libpcre2-8-0/copyright /usr/share/doc/libpcre2-8-0/copyright
COPY deploy/saml/nginx.conf /etc/nginx/nginx.conf
ARG SOURCE_REVISION
LABEL org.opencontainers.image.revision="$SOURCE_REVISION" \
      io.easy-auth.saml-activation="configuration-required"
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/sbin/nginx", "-g", "daemon off;"]
