# Following main on a member

Builds a website instance whenever `website/`, `design/` or
`android/app/screenshots/` changes on `main` and serves it on a port of
`127.0.0.1`. `/etc/juist-site/NAME` configures the instance NAME: `ADDR` to
listen on, `FLAGS` for the server (`-noindex` for a preview), and `REPO`, a
repository to build from other than the public one. Needs the user
`juist-build`, as `packaging/follow-main/setup` sets it up, whose
credentials also read a private `REPO`. As root, from this directory:

```sh
install -d -m 755 /usr/local/lib/juist-site /var/lib/juist-site /etc/juist-site
install -m 755 build install /usr/local/lib/juist-site/
install -m 644 juist-site@.service juist-site-follow-main@.service juist-site-follow-main@.timer /etc/systemd/system/
install -m 644 docs /etc/juist-site/
systemctl daemon-reload
systemctl enable juist-site@docs.service
systemctl enable --now juist-site-follow-main@docs.timer
```

The first build compiles Hugo and takes a while; `journalctl -fu
juist-site-follow-main@docs` shows it. Then publish it from that member:
`juist publish add docs 127.0.0.1:8181 --http2`. `journalctl -u juist-site@docs` shows a
line for each request: host, path, status, bytes, referrer and User-Agent;
the client's address is in the ingress's log.
