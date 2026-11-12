# SPDX-FileCopyrightText: © 2026 Peter Lemenkov and the SeerODBC contributors
#
# SPDX-License-Identifier: CC0-1.0

# RPM spec stub for Fedora.
Name:           seerodbc
Version:        0.2.0
Release:        %autorelease
Summary:        Clean-room ODBC driver for a proprietary database
License:        Apache-2.0
URL:            https://github.com/seerdb/SeerODBC
VCS:            git:%{url}.git
Source:         %{url}/archive/%{version}/%{name}-%{version}.tar.gz
BuildRequires:  gcc
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  pkgconfig(openssl)
BuildRequires:  unixODBC-devel
Requires:       odbcinst-generate

%description
SeerODBC lets ODBC consumers talk to a proprietary database by speaking its
native TNS/TTC wire protocol directly, with no vendor client libraries.
It is an independent, clean-room implementation (see CONTRIBUTING.md and
NOTICE).

%prep
%autosetup -p1 -n %{name}-%{version}

%build
%meson
%meson_build

%install
%meson_install

%files
%license LICENSE
%doc README.md NOTICE packaging/odbcinst.ini.sample docs/*.md
%{_libdir}/odbc/libseerodbc.so
%{_bindir}/seersql

%changelog
%autochangelog
