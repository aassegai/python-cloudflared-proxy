ARCH=$(dpkg --print-architecture)
CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ARCH}"
CLOUDFLARED_PATH="./cloudflared"

echo "Download cloudflared..."
wget -O $CLOUDFLARED_PATH $CLOUDFLARED_URL

echo "Make cloudflared executable..."
chmod +x $CLOUDFLARED_PATH

echo "Check installation finish..."
./cloudflared --version