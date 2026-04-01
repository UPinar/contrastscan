server {
    listen 443 ssl;
    listen [::]:443 ssl ipv6only=on;
    server_name contrastcyber.com www.contrastcyber.com;

    ssl_certificate /etc/letsencrypt/live/contrastcyber.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/contrastcyber.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    include /etc/nginx/snippets/security-headers.conf;
    include /etc/nginx/snippets/block-exploits.conf;

    location /scan {
        limit_req zone=scan burst=3 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }

    location /api/scan {
        limit_req zone=scan burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }

    location / {
        limit_req zone=general burst=20 nodelay;
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }

}

server {
    listen 80;
    listen [::]:80;
    server_name contrastcyber.com www.contrastcyber.com;
    return 301 https://$host$request_uri;
}
