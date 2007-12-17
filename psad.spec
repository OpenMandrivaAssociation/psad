%define name psad
%define version 2.0.1
%define release %mkrel 2

Summary: Psad analyzses iptables log messages for suspect traffic
Name: %name
Version: %version
Release: %release
License: GPL
Group: System/Servers
Url: http://www.cipherdyne.org/psad/
Source: http://www.cipherdyne.org/psad/download/%name-%version.tar.bz2
BuildRequires: perl-devel
BuildRequires: perl-Unix-Syslog
BuildRequires: perl-Net-IPv4Addr
Requires: perl-Unix-Syslog
Requires: perl-Date-Calc
Requires: sendmail-command
Requires: perl-Net-IPv4Addr
Requires: perl-IPTables-Parse
Requires: userspace-ipfilter
Requires: perl-Bit-Vector
Requires(pre): rpm-helper

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
Summary: Parse iptables rules
Group: System/Configuration/Networking

%description -n perl-IPTables-Parse
Psad package provides a IPTables-Parse perl module.

%package -n perl-IPTables-ChainMgr
Summary: ChainMgr iptables perl module
Group: System/Configuration/Networking

%description -n perl-IPTables-ChainMgr
Psad package provides a IPTables-ChainMgr perl module.

%prep
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%setup -q

cd Psad
%__perl Makefile.PL PREFIX=/usr/lib/psad LIB=/usr/lib/psad
%__make

cd ../IPTables-Parse
%__perl Makefile.PL INSTALLDIRS=vendor
%__make

cd ../IPTables-ChainMgr
%__perl Makefile.PL INSTALLDIRS=vendor
%__make

%build
### build psad binaries (kmsgsd, psadwatchd, and diskmond)
%make OPTS="$RPM_OPT_FLAGS"
### build the whois client
%make OPTS="$RPM_OPT_FLAGS" -C whois
### build perl modules used by psad
%make OPTS="$RPM_OPT_FLAGS" -C Psad

%check
cd Psad
%__make test
cd ../IPTables-Parse
%__make test
cd ../IPTables-ChainMgr
PERL5LIB=../IPTables-Parse/blib/lib %__make test

%install
### log directory
mkdir -p $RPM_BUILD_ROOT/var/log/psad
### dir for psadfifo
mkdir -p $RPM_BUILD_ROOT/var/lib/psad
### dir for pidfiles
mkdir -p $RPM_BUILD_ROOT/var/run/psad

### whois_psad binary
mkdir -p $RPM_BUILD_ROOT%_bindir
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man8
mkdir -p $RPM_BUILD_ROOT%_sbindir
### psad config
mkdir -p $RPM_BUILD_ROOT%_sysconfdir/%name
### psad init script
mkdir -p $RPM_BUILD_ROOT%_initrddir

install -m 500 {psad,kmsgsd,psadwatchd} $RPM_BUILD_ROOT%_sbindir/
install -m 500 fwcheck_psad.pl $RPM_BUILD_ROOT%_sbindir/fwcheck_psad
install -m 755 whois/whois $RPM_BUILD_ROOT/usr/bin/whois_psad
install -m 755 init-scripts/psad-init.redhat $RPM_BUILD_ROOT%_initrddir/psad
install -m 644 {psad.conf,kmsgsd.conf,psadwatchd.conf,fw_search.conf} $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 {alert.conf,pf.os} $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 {signatures,icmp_types,auto_dl,posf} $RPM_BUILD_ROOT%_sysconfdir/%name/
install -m 644 *.8 $RPM_BUILD_ROOT%{_mandir}/man8/

cd Psad
%makeinstall_std
rm -rf $RPM_BUILD_ROOT%_libdir/%name/local
rm -rf $RPM_BUILD_ROOT%_libdir/%name/`perl -MConfig -e'print$Config{archname}'`

cd ../IPTables-Parse
%makeinstall_std

cd ../IPTables-ChainMgr
%makeinstall_std

cd ..

### install snort rules files
cp -r snort_rules $RPM_BUILD_ROOT/etc/psad

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%post
### put the current hostname into the psad C binaries
### (diskmond and psadwatchd).
perl -p -i -e 'use Sys::Hostname; my $hostname = hostname(); s/HOSTNAME(\s+)CHANGE.?ME/HOSTNAME${1}$hostname/' /etc/psad/psad.conf
perl -p -i -e 'use Sys::Hostname; my $hostname = hostname(); s/HOSTNAME(\s+)CHANGE.?ME/HOSTNAME${1}$hostname/' /etc/psad/psadwatchd.conf

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
/sbin/chkconfig --add psad
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
echo "    /etc/psad/psad.conf, /etc/psad/psadwatchd.conf, and"
echo "    to have email alerts sent to"
echo "    an address other than root@localhost"
fi

%preun
%_preun_service psad

%files
%defattr(-,root,root)
/var/log/psad
/var/lib/psad
/var/run/psad
%_sbindir/*
%_bindir/*
%{_mandir}/man8/*
%_initrddir/%name
%_prefix/lib/%name

%dir %_sysconfdir/%name
%config(noreplace) %_sysconfdir/%name/*.conf
%config(noreplace) %_sysconfdir/%name/auto_dl
%config(noreplace) %_sysconfdir/%name/icmp_types
%config(noreplace) %_sysconfdir/%name/posf
%config(noreplace) %_sysconfdir/%name/signatures
%config(noreplace) %_sysconfdir/%name/pf.os

%dir %_sysconfdir/%name/snort_rules
%config(noreplace) %_sysconfdir/%name/snort_rules/*

%files -n perl-IPTables-Parse
%defattr(-,root,root)
%{perl_vendorlib}/IPTables/Parse.pm
%{_mandir}/man3/IPTables::Parse*

%files -n perl-IPTables-ChainMgr
%defattr(-,root,root)
%{perl_vendorlib}/IPTables/ChainMgr.pm
%{_mandir}/man3/IPTables::ChainMgr*


