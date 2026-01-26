FROM debian:12

RUN apt-get update
RUN apt-get install git curl gcc g++ make libclang-dev yq -y

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN cd /root && git clone --recursive https://github.com/nervosnetwork/ckb

RUN cd /root/ckb && /root/.cargo/bin/cargo build --release && cp target/release/ckb /

COPY ./dev.toml /
COPY ./contracts /contracts
RUN echo 111
RUN /ckb init --import-spec /dev.toml -c dev

RUN sed -i 's/127\.0\.0\.1:8114/0.0.0.0:8114/g' /ckb.toml
RUN echo [block_assembler]  >> ckb.toml
RUN echo code_hash = \"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8\"  >> ckb.toml
RUN echo args = \"0x7184c9779c6163ff63a86985f61769d600cbef8b\"  >> ckb.toml
RUN echo hash_type = \"type\"  >> ckb.toml
RUN echo message = \"0x\" >> ckb.toml
RUN sed -i 's/modules = \[/modules = ["Indexer" ,"Miner", /' ckb.toml

COPY ./run.sh /
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
