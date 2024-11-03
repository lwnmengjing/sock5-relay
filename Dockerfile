# 使用 Go 的官方镜像作为基础镜像
FROM golang AS builder

# 设置工作目录
WORKDIR /app

# 复制 Go 模块文件并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制项目源代码
COPY . .

# 构建 Go 应用
RUN CGO_ENABLED=0 GOOS=linux go build -o sock5-relay .

# 创建一个更小的镜像用于运行
FROM alpine:latest

# 将构建好的二进制文件复制到新镜像
COPY --from=builder /app/sock5-relay /usr/local/bin/sock5-relay

# 设置容器启动命令
ENTRYPOINT ["sock5-relay"]

# 公开服务端口（根据需要修改）
EXPOSE 8080
