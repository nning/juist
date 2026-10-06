# Packaging for a locally built test RPM: `make rpm` compiles the binaries with
# the project's own toolchain and CGO disabled, and this spec only installs
# them. That keeps the package buildable offline and without a Go toolchain in
# the build root, at the cost of not being a from-source Fedora package.
%global debug_package %{nil}
%global _build_id_links none
%global __brp_strip %{nil}
%global __brp_strip_static_archive %{nil}
%global __brp_strip_comment_note %{nil}

%{!?ver: %global ver 0}
%{!?rel: %global rel 1}
%{!?license_tag: %global license_tag BSD-3-Clause}

Name:           juist
Version:        %{ver}
Release:        %{rel}%{?dist}
Summary:        Peer-to-peer mesh VPN with no coordination server
License:        %{license_tag}
URL:            https://github.com/nning/juist
Source0:        %{name}-%{version}.tar.gz
Source1:        juist.sysusers

BuildRequires:  systemd-rpm-macros
%{?sysusers_requires_compat}

# The daemon programs addresses and routes over netlink, so it needs no
# iproute2 at runtime. ip6tables is a real dependency and an easy one to miss:
# the embedded router asks its firewall runner whether IPv6 is usable at all,
# and that runner decides by looking the ip6tables binary up on PATH. Without
# it the router silently skips every v6 address and route — and the overlay's
# primary family is the v6 ULA, so the package would install a half-working
# tunnel and say nothing.
# See docs/07-embedding-notes.md, "IPv6 is programmed conditionally".
#
# Depend on the virtual `iptables` provide rather than on the binary's path:
# both backends carry that provide and both ship ip6tables beside iptables,
# whereas a path is not portable across releases. Fedora 42 merged /usr/sbin
# into /usr/bin, so the binary is /usr/bin/ip6tables there, and the compat
# `Provides: /usr/sbin/...` that iptables-nft carries covers iptables only —
# `Requires: /usr/sbin/ip6tables` fails to resolve on Fedora 42 and later.
Requires:       iptables
# Runs the rule that lets juistd route the network's DNS through resolved.
Recommends:     polkit

%description
juist is a Tailscale-like mesh VPN with a WireGuard data plane and no central
control plane: membership, key distribution, revocation and rendezvous are
peer-to-peer. This package installs the CLI, the node daemon, and a systemd
unit that runs the daemon as a dedicated unprivileged user holding
CAP_NET_ADMIN and nothing else.

%prep
%autosetup

%build
# Nothing to build; `make rpm` staged the binaries into the source archive.

%install
install -D -m 0755 juist  %{buildroot}%{_bindir}/juist
install -D -m 0755 juistd %{buildroot}%{_bindir}/juistd
install -D -m 0644 juistd.service %{buildroot}%{_unitdir}/juistd.service
install -D -m 0644 juistd@.service %{buildroot}%{_unitdir}/juistd@.service
install -D -m 0644 juist-ingress.service %{buildroot}%{_unitdir}/juist-ingress.service
install -D -m 0644 juist-serve.service %{buildroot}%{_unitdir}/juist-serve.service
install -D -m 0644 juist-serve.path %{buildroot}%{_unitdir}/juist-serve.path
install -D -m 0644 juist-ingress-ports.path %{buildroot}%{_unitdir}/juist-ingress-ports.path
install -D -m 0644 juist-ingress-ports.service %{buildroot}%{_unitdir}/juist-ingress-ports.service
install -D -m 0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/%{name}.conf
install -D -m 0755 firewall.sh %{buildroot}%{_prefix}/lib/juist/firewall.sh
install -D -m 0755 exit-node.sh %{buildroot}%{_prefix}/lib/juist/exit-node.sh
install -D -m 0755 ingress.sh %{buildroot}%{_prefix}/lib/juist/ingress.sh
install -D -m 0755 serve.sh %{buildroot}%{_prefix}/lib/juist/serve.sh
install -D -m 0644 juist.rules %{buildroot}%{_datadir}/polkit-1/rules.d/60-juist.rules
install -D -m 0644 juist.1 %{buildroot}%{_mandir}/man1/juist.1
install -D -m 0644 juistd.8 %{buildroot}%{_mandir}/man8/juistd.8
for f in juist juist-relay juist-invite juist-ingress; do
	install -D -m 0644 $f.xml %{buildroot}%{_prefix}/lib/firewalld/services/$f.xml
done
install -D -m 0644 juist.bash %{buildroot}%{_datadir}/bash-completion/completions/juist
install -D -m 0644 _juist %{buildroot}%{_datadir}/zsh/site-functions/_juist
install -D -m 0644 juist.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/juist.fish
install -d -m 0700 %{buildroot}%{_sharedstatedir}/%{name}

# The units in the repository name the path a manual install uses; a packaged
# binary lives in %{_bindir}. The grep is the guard: a rewrite that silently
# missed would ship a unit pointing at a file this package does not install.
for u in juistd.service juistd@.service juist-ingress.service juist-serve.service; do
	sed -i 's|^ExecStart=/usr/local/bin/juistd |ExecStart=%{_bindir}/juistd |' %{buildroot}%{_unitdir}/$u
	grep -q '^ExecStart=%{_bindir}/juistd ' %{buildroot}%{_unitdir}/$u
done

%pre
%sysusers_create_compat %{SOURCE1}

%post
%systemd_post juistd.service
# Traffic on juist0 is let through an active firewalld, and the service runs
# from installation, in no network, as the deb's does; see firewall.sh.
%{_prefix}/lib/juist/firewall.sh reload
if [ $1 -eq 1 ]; then
	%{_prefix}/lib/juist/firewall.sh allow
	systemctl enable --now juistd.service >/dev/null 2>&1 || :
	systemctl enable --now juist-serve.path >/dev/null 2>&1 || :
elif systemctl is-enabled --quiet juist-serve.service 2>/dev/null; then
	# A terminator enabled before juist-serve.path came is started by it.
	systemctl disable --quiet juist-serve.service >/dev/null 2>&1 || :
	systemctl enable --now juist-serve.path >/dev/null 2>&1 || :
fi
# An ingress enabled before juist-ingress-ports.path came has the firewall
# follow its ports by it.
if [ $1 -gt 1 ] && systemctl is-enabled --quiet juist-ingress.service 2>/dev/null; then
	systemctl enable --now juist-ingress-ports.path >/dev/null 2>&1 || :
fi

%preun
%systemd_preun juistd.service
# Every other network's instance goes with the package, and its device's
# rule with it; their state directories stay, as the default's does.
if [ $1 -eq 0 ]; then
	for i in 1 2 3 4 5 6 7 8 9; do
		systemctl --no-reload disable --now juistd@juist$i.service >/dev/null 2>&1 || :
	done
	%{_prefix}/lib/juist/firewall.sh revoke
	# An ingress stops, and its ports close.
	%{_prefix}/lib/juist/ingress.sh off
	%{_prefix}/lib/juist/serve.sh off
	# Forwarding for an exit node goes back as it was, and nothing a
	# juistd that failed left refusing the internet stays.
	%{_prefix}/lib/juist/exit-node.sh off
	%{_prefix}/lib/juist/exit-node.sh clear
fi

%postun
%systemd_postun_with_restart juistd.service
for u in juist-ingress juist-serve; do
	if systemctl is-active --quiet $u.service 2>/dev/null; then
		%systemd_postun_with_restart $u.service
	fi
done
# The instances that run take the upgraded juistd too, restarted the way the
# default is: marked here, restarted once systemd has reloaded the units.
for i in 1 2 3 4 5 6 7 8 9; do
	if systemctl is-active --quiet juistd@juist$i.service 2>/dev/null; then
		%systemd_postun_with_restart juistd@juist$i.service
	fi
done
# The service files are gone; firewalld forgets them only on a reload.
if [ $1 -eq 0 ] && firewall-cmd --state >/dev/null 2>&1; then
	firewall-cmd --reload >/dev/null 2>&1 || :
fi
# Kept on purpose, and said: the terminator's ACME account, which CAA
# records may name.
if [ $1 -eq 0 ] && [ -d /var/lib/juist-serve ]; then
	echo "juist: kept /var/lib/juist-serve, the terminator's ACME account, which CAA records may name" >&2
fi

%files
%doc README.md
%license LICENSE THIRD_PARTY_LICENSES
%{_bindir}/juist
%{_bindir}/juistd
%{_unitdir}/juistd.service
%{_unitdir}/juistd@.service
%{_unitdir}/juist-ingress.service
%{_unitdir}/juist-serve.service
%{_unitdir}/juist-serve.path
%{_unitdir}/juist-ingress-ports.path
%{_unitdir}/juist-ingress-ports.service
%{_sysusersdir}/%{name}.conf
%dir %{_prefix}/lib/juist
%{_prefix}/lib/juist/firewall.sh
%{_prefix}/lib/juist/exit-node.sh
%{_prefix}/lib/juist/ingress.sh
%{_prefix}/lib/juist/serve.sh
%{_datadir}/polkit-1/rules.d/60-juist.rules
%{_mandir}/man1/juist.1*
%{_mandir}/man8/juistd.8*
%{_prefix}/lib/firewalld/services/juist.xml
%{_prefix}/lib/firewalld/services/juist-relay.xml
%{_prefix}/lib/firewalld/services/juist-invite.xml
%{_prefix}/lib/firewalld/services/juist-ingress.xml
%{_datadir}/bash-completion/completions/juist
%{_datadir}/zsh/site-functions/_juist
%{_datadir}/fish/vendor_completions.d/juist.fish
# Holds this device's keys and its log. Owned so that an uninstall removes it
# when it is empty and leaves it when it is not: deleting an enrolled device's
# identity behind the operator's back is not something a package should do.
%attr(0700,juist,juist) %dir %{_sharedstatedir}/%{name}
