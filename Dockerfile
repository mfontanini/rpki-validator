FROM ekidd/rust-musl-builder:1.29.2

ENV APP_DIRECTORY /rpki-validator
ENV TAL_PATH ${APP_DIRECTORY}/tal
ENV CACHE_PATH ${APP_DIRECTORY}/cache
ENV API_ENDPOINT 0.0.0.0:8080

# Create the directory where the rsync'd repos will go
RUN sudo mkdir -p ${APP_DIRECTORY}/cache

# Copy the tal files
COPY tal ${APP_DIRECTORY}/tal

# Copy the source code
ADD src ./build/src
ADD benches ./build/benches
ADD Cargo.lock Cargo.toml ./build/

# Fix permissions
RUN sudo chown -R rust:rust .

# Now build and install the app
RUN cd build && \
    cargo build --release && \
    sudo mv ./target/x86_64-unknown-linux-musl/release/rpki-validator ${APP_DIRECTORY} && \
    sudo chown -R rust:rust ${APP_DIRECTORY} && \
    cd .. && rm -rf ./build

# Copy the config file
COPY config/config.toml ${APP_DIRECTORY}

# Install rsync and nc
RUN sudo apt-get update && \
    sudo apt-get install -y rsync netcat-openbsd && \
    sudo apt-get clean

ENTRYPOINT ${APP_DIRECTORY}/rpki-validator --config ${APP_DIRECTORY}/config.toml
