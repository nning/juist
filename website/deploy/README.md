# Following main on a member

Builds the site whenever `website/` or `design/` changes on `main` and serves
it on `127.0.0.1:8181`. Needs the user `juist-build`, with read access to the
repository, as `juist-follow-main` sets it up. As root, from this directory:

```sh
install -d -m 755 /usr/local/lib/juist-site /var/lib/juist-site
install -m 755 build install /usr/local/lib/juist-site/
install -m 644 juist-site.service juist-site-follow-main.service juist-site-follow-main.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable juist-site.service
systemctl enable --now juist-site-follow-main.timer
```

The first build compiles Hugo and takes a while; `journalctl -fu
juist-site-follow-main` shows it. Then publish it from that member:
`juist publish add docs 127.0.0.1:8181 --http2`. `journalctl -u juist-site` shows a
line for each request: host, path, status, bytes, referrer and User-Agent;
the client's address is in the ingress's log.
