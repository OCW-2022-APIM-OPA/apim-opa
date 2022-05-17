# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.191.1/containers/typescript-node/.devcontainer/base.Dockerfile

ARG VARIANT=3.1
FROM mcr.microsoft.com/vscode/devcontainers/dotnet:0-${VARIANT}

# [Option] Install zsh
ARG INSTALL_ZSH="true"
# [Option] Upgrade OS packages to their latest versions
ARG UPGRADE_PACKAGES="false"
# [Option] Enable non-root Docker access in container
ARG ENABLE_NONROOT_DOCKER="true"

# Install needed packages and setup non-root user. Use a separate RUN statement to add your
# own dependencies. A user of "automatic" attempts to reuse an user ID if one already exists.
ARG USERNAME="automatic"
ARG USER_UID=1000
ARG USER_GID=$USER_UID
COPY library-scripts/*.sh /tmp/library-scripts/
RUN apt-get update \
    && apt-get install -y dos2unix \
    && dos2unix /tmp/library-scripts/*.sh \
    && /bin/bash /tmp/library-scripts/common-debian.sh "${INSTALL_ZSH}" "${USERNAME}" "${USER_UID}" "${USER_GID}" "${UPGRADE_PACKAGES}" "true" "true" \
    # Use Docker script from script library to set things up
    && /bin/bash /tmp/library-scripts/docker-debian.sh "${ENABLE_NONROOT_DOCKER}" "/var/run/docker-host.sock" "/var/run/docker.sock" "${USERNAME}" \
    # Clean up
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* /tmp/library-scripts/

# Install OPA
RUN \
    curl -L -o opa-binary https://openpolicyagent.org/downloads/v0.37.0/opa_linux_amd64_static && \
    sudo mv opa-binary /usr/bin/opa && \
    sudo chmod 755 /usr/bin/opa

# Customize bash
RUN \
    # Install bash completion
    apt-get update && \
    apt-get -y install bash-completion && \
    echo "source /usr/share/bash-completion/bash_completion" >> ~/.bashrc

# Setting the ENTRYPOINT to docker-init.sh will configure non-root access
# to the Docker socket. The script will also execute CMD as needed.
ENTRYPOINT [ "/usr/local/share/docker-init.sh" ]
CMD [ "sleep", "infinity" ]
