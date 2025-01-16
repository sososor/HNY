# 基本となるGoイメージを使用
FROM golang:1.20

# 作業ディレクトリを設定
WORKDIR /app

# Goの依存関係をインストール
COPY go.mod go.sum ./
RUN go mod download

# アプリケーションのソースコードをコピー
COPY . .

# Goアプリケーションをビルド
RUN go build -o app

# アプリケーションの実行
CMD ["./app"]
