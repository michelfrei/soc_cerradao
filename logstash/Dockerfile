# syntax=docker/dockerfile:1
ARG STACK_VERSION
FROM docker.elastic.co/logstash/logstash:${STACK_VERSION}

# Driver JDBC do PostgreSQL (Maven Central). Ao trocar a versão, atualize o SHA-256
# (calculado sobre o jar cujo SHA-1 confere com o .sha1 publicado no Maven Central).
ARG PGJDBC_VERSION=42.7.4
ARG PGJDBC_SHA256=188976721ead8e8627eb6d8389d500dccc0c9bebd885268a3047180274a6031e
USER root
RUN mkdir -p /usr/share/logstash/jdbc \
 && curl -fsSL -o /usr/share/logstash/jdbc/postgresql.jar \
      "https://repo1.maven.org/maven2/org/postgresql/postgresql/${PGJDBC_VERSION}/postgresql-${PGJDBC_VERSION}.jar" \
 && echo "${PGJDBC_SHA256}  /usr/share/logstash/jdbc/postgresql.jar" | sha256sum -c - \
 && chmod 644 /usr/share/logstash/jdbc/postgresql.jar
USER logstash
