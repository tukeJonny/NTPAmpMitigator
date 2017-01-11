# Build
```
docker build -f ./Dockerfile --no-cache .
```

# Run
```
docker run -it -d --name ntpd -p 123:123/udp <image id>
```