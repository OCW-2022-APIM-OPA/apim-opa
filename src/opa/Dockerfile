FROM openpolicyagent/opa:latest-debug

COPY ./rego /rego

CMD ["run", "--server", "--skip-verify", "--watch", "--log-level", "debug", "/rego"]