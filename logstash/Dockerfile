# syntax=docker/dockerfile:1
ARG STACK_VERSION
FROM docker.elastic.co/logstash/logstash:${STACK_VERSION}

# Driver JDBC do PostgreSQL (Maven Central). Confira o SHA-256 publicado ao trocar a versão.
ARG PGJDBC_VERSION=42.7.4
ARG PGJDBC_SHA256=
USER root
RUN mkdir -p /usr/share/logstash/jdbc \
 && curl -fsSL -o /usr/share/logstash/jdbc/postgresql.jar \
      "https://repo1.maven.org/maven2/org/postgresql/postgresql/${PGJDBC_VERSION}/postgresql-${PGJDBC_VERSION}.jar" \
 && if [ -n "${PGJDBC_SHA256}" ]; then echo "${PGJDBC_SHA256}  /usr/share/logstash/jdbc/postgresql.jar" | sha256sum -c -; fi \
 && chmod 644 /usr/share/logstash/jdbc/postgresql.jar
USER logstash
