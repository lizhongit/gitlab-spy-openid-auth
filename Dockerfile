FROM u32lxivt.mirror.aliyuncs.com/library/rust:1.49 AS builder

WORKDIR /usr/src/myapp
COPY . .

RUN cargo build --release

FROM u32lxivt.mirror.aliyuncs.com/library/debian:latest
ENV TZ=Asia/Shanghai

WORKDIR /root/
RUN apt update && apt install libssl-dev -y && apt install ca-certificates -y
COPY --from=0 /usr/src/myapp/target/release/auth .
EXPOSE 80
CMD ["./auth"]
