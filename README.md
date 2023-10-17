# Private cloud client-server app

This application is an illustration of idea of using ed25519 signature for authenticating access 
and checking integrity of files.

## Sample config files:

server_config.json
```json
{
  "listen_addr": "127.0.0.1:3030",
  "max_file_size": 10000000000,
  "storage_path": "/home/user/private-cloud"
}
```

client-config.json
```json
{
  "server_url": "http://127.0.0.1:3030",
  "download_dir": "/home/user/private-cloud-downloads"
}
```
