%{?ksrc: 	%{!?kernel:    %{expand: %%define kernel %(cd "%{ksrc}" &> /dev/null && echo "$(cat Makefile 2>/dev/null && echo $'\n'kernelhelper-rel:$'\n'$'\t'@echo \$\(KERNELRELEASE\)$'\n')" 2>/dev/null | make -f - kernelhelper-rel 2>/dev/null || echo "custom" ) }}}
%{!?kernel:             %{expand: %%define kernel %(uname -r)}}

Name:           aodv-uu
Version:        0.9.1
Release:        2
Summary:        An distance vector routing protocol for ad hoc networks.

Vendor:	        Erik Nordström, erikn[AT]it[DOT]uu[DOT]se, Uppsala University.
Group:          System Environment/Base
URL:            http://core.it.uu.se/adhoc
License:        GPL
Source:         %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%define       kversion        %(echo %{kernel} | sed -e s/smp// -)
%define       krelver         %(echo %{kversion} | tr -s '-' '_')

%if %(echo %{kernel} | grep -c smp)
        %{expand:%%define ksmp -smp}
%endif

%description 
AODV-UU is an implementation of the Ad hoc On-demand
Distance Vector routing protocol being standardized within the IETF.

%package -n %{name}-%{kernel}
Summary:        AODV-UU Routing Daemon
Group:          System Environment/Base
Provides:	%{name}
Requires(post):   /sbin/depmod
Requires(postun): /sbin/depmod
%if 0%{!?ksrc:1}
Requires:	 /boot/vmlinuz-%{kernel}
BuildRequires:  kernel-devel = %{kernel}
%endif

%description -n %{name}-%{kernel}
AODV-UU is an implementation of the Ad hoc On-demand
Distance Vector routing protocol being standardized within the IETF.

%prep
%setup -q

%build
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{kernel}/aodv

install -s -m 755 aodvd $RPM_BUILD_ROOT/usr/sbin/aodvd        
install -m 644 kaodv.ko $RPM_BUILD_ROOT/lib/modules/%{kernel}/aodv/kaodv.ko


%clean
rm -rf $RPM_BUILD_ROOT

%post -n %{name}-%{kernel}
%if 0%{!?ksrc:1}
if [ -r /boot/System.map-%{kernel} ] ; then
  /sbin/depmod -e -F /boot/System.map-%{kernel} %{kernel} > /dev/null || :
fi
%else
if [ "$(uname -r)" = "%{kernel}" ] ; then
  /sbin/depmod -a >/dev/null || :
fi
%endif

%postun
%if 0%{!?ksrc:1}
if [ -r /boot/System.map-%{kernel} ] ; then
  /sbin/depmod -e -F /boot/System.map-%{kernel} %{kernel} > /dev/null || :
fi
%else
if [ "$(uname -r)" = "%{kernel}" ] ; then
  /sbin/depmod -a >/dev/null || :
fi
%endif


%files -n %{name}-%{kernel}
%defattr(-,root,root)
%doc README README.ns ChangeLog
%dir /lib/modules/%{kernel}/aodv

/usr/sbin/aodvd
/lib/modules/%{kernel}/aodv/kaodv.ko

%changelog
* Wed Aug 10 2005 Erik Nordstrom <erikn@wormhole.it.uu.se> - 0.9.1-2
- Added support for kernel version dependency

* Wed Jul 27 2005 Erik Nordström <erikn@replicator.mine.nu> - 0.9.1-1
- First spec file
