# Nginx JSON log parser

Add this to your Nginx config:

```
    log_format json
        '{'
        '"time":"$time_iso8601", '
        '"remote_addr":"$remote_addr", '
        '"remote_user":"$remote_user", '
        '"host":"$http_host", '
        '"status":"$status", '
        '"method":"$request_method", '
        '"uri":"$request_uri", '
        '"protocol":"$server_protocol", '
        '"body_bytes_sent":"$body_bytes_sent", '
        '"referer":"$http_referer", '
        '"user_agent":"$http_user_agent", '
        '"request_time":"$request_time", '
        # Next line depends on Cloudflare sending a country code
        '"country":"$http_cf_ipcountry", '
        '"port":"$server_port"'
        '}';

    access_log /var/log/nginx/access.log json;
```
