FROM alpine:latest

MAINTAINER dmitrysl <dmitrysl@github.com>

WORKDIR "/opt"

ADD .docker_build/web-app /opt/bin/web-app
ADD ./ui /opt/ui

CMD ["/opt/bin/web-app"]

