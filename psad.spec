%define debug_package %{nil}

Summary:	Analyzses iptables log messages for suspect traffic
Name:		psad
Version:	2.2.3
Release:	5
License:	GPLv2+
Group:		System/Servers
Url:		http://www.cipherdyne.org/psad/
Source0:	http://www.cipherdyne.org/psad/download/%{name}-%{version}.tar.bz2
Source1:	http://www.cipherdyne.org/psad/download/%{name}-%{version}.tar.gz.asc
BuildRequires:	perl-devel
BuildRequires:	perl-Unix-Syslog
BuildRequires:	perl-NetAddr-IP
Requires:	perl-Bit-Vector
Requires:	perl-Date-Calc
Requires:	perl-IPTables-ChainMgr
Requires:	perl-IPTables-Parse
Requires:	perl-NetAddr-IP
Requires:	perl-Unix-Syslog
Requires:	sendmail-command
Requires:	userspace-ipfilter
Requires:	whois
Requires(post,preun):	rpm-helper

%description
Port Scan Attack Detector (psad) is a collection of four lightweight
system daemons written in Perl and C that are designed to work with
Linux firewalling code (iptables in the 2.4.x kernels, and ipchains
in the 2.2.x kernels) to detect port scans. It features a set of highly
configurable danger thresholds (with sensible defaults provided),
verbose alert messages that include the source, destination, scanned
port range, begin and end times, TCP flags and corresponding nmap
options (Linux 2.4.x kernels only), email alerting, and automatic
blocking of offending IP addresses via dynamic configuration of
ipchains/iptables firewall rulesets. In addition, for the 2.4.x kernels
psad incorporates many of the TCP, UDP, and ICMP signatures included in
Snort to detect highly suspect scans for various backdoor programs
(e.g. EvilFTP, GirlFriend, SubSeven), DDoS tools (mstream, shaft), and
advanced port scans (syn, fin, Xmas) which are easily leveraged against
a machine via nmap. Psad also uses packet TTL, IP id, TOS, and TCP
window sizes to passively fingerprint the remote operating system from
which scans originate.

%package -n perl-IPTables-Parse
Summary:	Parse iptables rules
Group:		System/Configuration/Networking
License:	GPLv2+ or Artistic

%description -n perl-IPTables-Parse
Psad package provides a IPTables-Parse perl module.

%package -n perl-IPTables-ChainMgr
Summary:	ChainMgr iptables perl module
Group:		System/Configuration/Networking
License:	GPLv2+ or Artistic

%description -n perl-IPTables-ChainMgr
Psad package provides a IPTables-ChainMgr perl module.

%prep
%setup -q

%build
### build psad binaries (kmsgsd, psadwatchd, and diskmond)
%make OPTS="%{optflags}" LDFLAGS="%{ldflags}"

pushd deps/IPTables-Parse
%__perl Makefile.PL INSTALLDIRS=vendor
%make
popd

pushd deps/IPTables-ChainMgr
%__perl Makefile.PL INSTALLDIRS=vendor
%make
popd

%check
pushd deps/IPTables-Parse
%make test
popd

pushd deps/IPTables-ChainMgr
PERL5LIB=../IPTables-Parse/blib/lib %__make test
popd

%install
### log directory
mkdir -p %{buildroot}%{_logdir}/%{name}
### dir for psadfifo
mkdir -p %{buildroot}%{_localstatedir}/lib/%{name}
### dir for pidfiles
mkdir -p %{buildroot}/var/run/%{name}

mkdir -p %{buildroot}%{_mandir}/man8
mkdir -p %{buildroot}%{_sbindir}
### psad config
mkdir -p %{buildroot}%{_sysconfdir}/%{name}
### psad init script
mkdir -p %{buildroot}%{_initrddir}

install -m 700 {psad,kmsgsd,psadwatchd}	%{buildroot}%{_sbindir}/
install -m 500 fwcheck_psad.pl %{buildroot}%{_sbindir}/fwcheck_psad
install -m 755 init-scripts/psad-init.redhat %{buildroot}%{_initrddir}/%{name}
install -m 644 {psad.conf,pf.os} %{buildroot}%{_sysconfdir}/%{name}/
install -m 644 {signatures,icmp_types,icmp6_types,auto_dl,posf,ip_options} %{buildroot}%{_sysconfdir}/%{name}/
install -m 644 *.8 %{buildroot}%{_mandir}/man8/

pushd deps/IPTables-Parse
%makeinstall_std
popd

pushd deps/IPTables-ChainMgr
%makeinstall_std
popd

### install snort rules files
cp -r deps/snort_rules %{buildroot}%{_sysconfdir}/%{name}/

%post
### put the current hostname into the psad C binaries
### (diskmond and psadwatchd).
perl -p -i -e 'use Sys::Hostname; my $hostname = hostname(); s/HOSTNAME(\s+)CHANGE.?ME/HOSTNAME${1}$hostname/' /etc/psad/psad.conf

/bin/touch /var/log/psad/fwdata
chown root.root /var/log/psad/fwdata
chmod 0600 /var/log/psad/fwdata
if [ ! -p /var/lib/psad/psadfifo ];
then [ -e /var/lib/psad/psadfifo ] && /bin/rm -f /var/lib/psad/psadfifo
/bin/mknod -m 600 /var/lib/psad/psadfifo p
fi
chown root.root /var/lib/psad/psadfifo
chmod 0600 /var/lib/psad/psadfifo
### make psad start at boot
%_post_service psad
[ -f /etc/syslog.conf ] || exit 0
### make a backup of /etc/syslog.conf
[ -f /etc/syslog.conf.orig ] || cp -p /etc/syslog.conf /etc/syslog.conf.orig
### add the psadfifo line to /etc/syslog.conf if necessary
if ! grep -v "#" /etc/syslog.conf | grep -q psadfifo;
then echo " .. Adding psadfifo line to /etc/syslog.conf"
echo "kern.info |/var/lib/psad/psadfifo" >> /etc/syslog.conf
fi
if [ -e /var/run/syslogd.pid ];
then
echo " .. Restarting syslogd "
kill -HUP `cat /var/run/syslogd.pid`
fi
if grep -q "EMAIL.*root.*localhost" /etc/psad/psad.conf;
then
echo " .. You can edit the EMAIL_ADDRESSES variable in"
echo "    /etc/psad/psad.conf to have email alerts sent to"
echo "    an address other than root@localhost"
fi

%preun
%_preun_service psad

%files
%{_initrddir}/%{name}
%{_logdir}/%{name}
%{_localstatedir}/lib/%{name}
/var/run/%{name}
%attr (0500,root,root) %{_sbindir}/*
%{_mandir}/man8/*

%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/*.conf
%config(noreplace) %{_sysconfdir}/%{name}/auto_dl
%config(noreplace) %{_sysconfdir}/%{name}/icmp_types
%config(noreplace) %{_sysconfdir}/%{name}/icmp6_types
%config(noreplace) %{_sysconfdir}/%{name}/posf
%config(noreplace) %{_sysconfdir}/%{name}/signatures
%config(noreplace) %{_sysconfdir}/%{name}/pf.os
%config(noreplace) %{_sysconfdir}/%{name}/ip_options

%dir %{_sysconfdir}/%{name}/snort_rules
%config(noreplace) %{_sysconfdir}/%{name}/snort_rules/*

%files -n perl-IPTables-Parse
%{perl_vendorlib}/IPTables/Parse.pm
%{_mandir}/man3/IPTables::Parse*

%files -n perl-IPTables-ChainMgr
%{perl_vendorlib}/IPTables/ChainMgr.pm
%{_mandir}/man3/IPTables::ChainMgr*



