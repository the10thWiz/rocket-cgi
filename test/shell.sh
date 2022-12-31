echo "Content-Type: text/plain"
echo ""
# I'm not proud of this, but apparently `$SHELL` doesn't provide this info
echo "$(ps -o cmd --no-headers $$ | grep -o '^\w*')"
