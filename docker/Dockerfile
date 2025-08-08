#FROM l4t-release:32.5.2 AS l4t-32.5.2
#FROM l4t-release:32.7.4 AS l4t-32.7.4
#FROM l4t-release:35.4.1 AS l4t-35.4.1
#FROM l4t-release:35.5.0 AS l4t-35.5.0
#FROM l4t-release:35.6.0 AS l4t-35.6.0
FROM l4t-release:36.4.0 AS l4t-36.4.0
FROM l4t-release:36.4.3 AS l4t-36.4.3
FROM ubuntu:20.04 AS mkimage

# Dependencies for building u-boot tools
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    gcc-aarch64-linux-gnu \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Download u-boot source
#RUN git clone https://github.com/madisongh/u-boot-rockchip-downstream.git -b patches-2024.04-rockchip-v2017.09 --depth 1 u-boot
#WORKDIR /u-boot
#RUN make rk3568_defconfig && \
#    echo CONFIG_FIT_SIGNATURE=y >> .config && \
#    make olddefconfig && \
#    make CROSS_COMPILE=aarch64-linux-gnu- tools

FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

RUN apt-get update && apt-get install -y \
  device-tree-compiler \
  liblz4-tool \
  python2.7 \
  python3.9 \
  python3.9-dev \
  python3-pip \
  sbsigntool \
  && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python  python  /usr/bin/python2.7 1
RUN update-alternatives --install /usr/bin/python2 python2 /usr/bin/python2.7 1
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1

RUN pip3 install --upgrade pip

RUN pip3 install \
  PyYAML \
  cryptograpy \
  pycryptodome

ENV DIGSIGSERVER=/digsigserver
ENV DIGSIGSERVER_KEYFILE_URI=${DIGSIGSERVER}

WORKDIR ${DIGSIGSERVER}

#COPY --from=l4t-32.5.2 /opt/nvidia /opt/nvidia
#COPY --from=l4t-32.7.4 /opt/nvidia /opt/nvidia
#COPY --from=l4t-35.4.1 /opt/nvidia /opt/nvidia
#COPY --from=l4t-35.5.0 /opt/nvidia /opt/nvidia
#COPY --from=l4t-35.6.0 /opt/nvidia /opt/nvidia
COPY --from=l4t-36.4.0 /opt/nvidia /opt/nvidia
COPY --from=l4t-36.4.3 /opt/nvidia /opt/nvidia
# Rockchip
#ARG ROCKCHIP_TOOLS_REPO_URL=https://github.com/rockchip-linux/rkbin/raw/829d7a6a2272938aac67dfe9f807277fa617809b/
#ENV DIGSIGSERVER_RK_TOOLS_PATH=/opt
#ADD --chmod=755 ${ROCKCHIP_TOOLS_REPO_URL}/tools/rk_sign_tool ${DIGSIGSERVER_RK_TOOLS_PATH}/rkbin-tools/
#ADD --chmod=755 ${ROCKCHIP_TOOLS_REPO_URL}/tools/setting.ini ${DIGSIGSERVER_RK_TOOLS_PATH}/rkbin-tools/
#ADD --chmod=755 ${ROCKCHIP_TOOLS_REPO_URL}/tools/boot_merger ${DIGSIGSERVER_RK_TOOLS_PATH}/rkbin-tools/
#COPY --from=mkimage /u-boot/tools/mkimage /usr/local/bin/

# Include any nxp tool archives in docker/nxp_tools
RUN mkdir -p /opt/NXP
COPY digsigserver/docker/nxp_tools/* /opt/NXP/

# Add opensc and pkcs11 etc.
RUN apt-get update && apt-get install -y \
  p11-kit \
  opensc \
  libengine-pkcs11-openssl \
  libcurl4 \
  wget \
  libedit2 \
  && rm -rf /var/lib/apt/lists/*

# Setup paths for openssl (found from running cst --version)
RUN cd /opt && \
    ln -s /usr/lib/ssl cst-ssl && \
    cd cst-ssl && \
    mkdir lib && \
    cd lib && \
    ln -s /usr/lib/x86_64-linux-gnu/engines-1.1 engines-1.1

RUN apt-get update && apt-get install -y \
  net-tools \
  iproute2 \
  && rm -rf /var/lib/apt/lists/*

# Install Caddy
RUN apt-get update && \
    apt-get install -yq --no-install-recommends \
    debian-keyring debian-archive-keyring apt-transport-https curl && \
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list && \
    apt-get update && \
    apt-get install -yq caddy && \
    rm -rf /var/lib/apt/lists/*


COPY digsigserver/digsigserver ${DIGSIGSERVER}/digsigserver
COPY digsigserver/requirements.txt ${DIGSIGSERVER}
COPY digsigserver/setup.cfg ${DIGSIGSERVER}
COPY digsigserver/setup.py ${DIGSIGSERVER}

RUN pip3 install -e .

COPY sbk.txt $DIGSIGSERVER_KEYFILE_URI/jetson-orin-pandas-ind/tegrasign/
COPY rsa_priv.pem $DIGSIGSERVER_KEYFILE_URI/jetson-orin-pandas-ind/tegrasign/
COPY server_certs ${DIGSIGSERVER}/server_certs/
COPY Caddyfile ${DIGSIGSERVER}/Caddyfile

COPY server/ ${DIGSIGSERVER}/wrapper/


CMD [ "/bin/bash", "/digsigserver/wrapper/start.sh" ]