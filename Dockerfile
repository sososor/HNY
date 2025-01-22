# 基本となるGoイメージを使用
FROM golang:1.21

# 作業ディレクトリを設定
WORKDIR /app

# Goの依存関係をインストール
COPY go.mod go.sum ./
RUN go mod tidy && go mod download

# アプリケーションのソースコードをコピー
COPY . .

# Goアプリケーションをビルド
RUN go build -o app

# アプリケーションの実行
CMD ["./app"]
