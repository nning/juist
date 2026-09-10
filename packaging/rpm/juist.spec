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
%{!?license_tag: %global license_tag LicenseRef-unspecified}

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
install -D -m 0644 %{SOURCE1} %{buildroot}%{_sysusersdir}/%{name}.conf
install -d -m 0700 %{buildroot}%{_sharedstatedir}/%{name}

# The unit in the repository names the path a manual install uses; a packaged
# binary lives in %{_bindir}. The grep is the guard: a rewrite that silently
# missed would ship a unit pointing at a file this package does not install.
sed -i 's|^ExecStart=/usr/local/bin/juistd |ExecStart=%{_bindir}/juistd |' \
    %{buildroot}%{_unitdir}/juistd.service
grep -q '^ExecStart=%{_bindir}/juistd ' %{buildroot}%{_unitdir}/juistd.service

%pre
%sysusers_create_compat %{SOURCE1}

%post
%systemd_post juistd.service

%preun
%systemd_preun juistd.service

%postun
%systemd_postun_with_restart juistd.service

%files
%doc README.md
%{_bindir}/juist
%{_bindir}/juistd
%{_unitdir}/juistd.service
%{_sysusersdir}/%{name}.conf
# Holds this device's keys and its log. Owned so that an uninstall removes it
# when it is empty and leaves it when it is not: deleting an enrolled device's
# identity behind the operator's back is not something a package should do.
%attr(0700,juist,juist) %dir %{_sharedstatedir}/%{name}
