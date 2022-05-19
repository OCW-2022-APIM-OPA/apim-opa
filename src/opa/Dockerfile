FROM openpolicyagent/opa:latest-debug

COPY ./rego /rego
COPY ./config /config

CMD ["run", "--server", "--skip-verify", "--watch", "--log-level", "debug", "--config-file", "/config/config.yaml",  "/rego"]
