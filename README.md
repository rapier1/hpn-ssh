# HPNSSH: Based on Portable OpenSSH

HPN-SSH is a high performance soft fork of OpenSSH that can provide significantly faster throughput for bulk data transfers over a wide range of network paths. In some situations we've seen throughput rates more than 100 times faster than OpenSSH. HPN-SSH is able to do this by optimizing the application layer receive buffer to match the TCP receive buffer. Notably, to see performance improvements HPN-SSH only needs to be the data receiver so users can see notable improvements with many other SSH implementations. HPN-SSH also incorporates two parallelized ciphers, AES-CTR and Chacha20 (the default). When using these ciphers a throughput performance increase of 30% is typical. More information on how we do this work and other features of HPN-SSH is available from [https://hpnssh.org](https://hpnssh.org).

Starting with version HPN17v0 there will be significant changes to the naming convention used for executables and installation locations. The last version that does not include these changes is HPN16v1 corresponding to the HPN-8_8_P1 tag on the master branch.

HPNSSH is a variant of OpenSSH. It a complete implementation of the SSH protocol (version 2) for secure remote login, command execution and file transfer. It includes a client ``hpnssh`` and server ``hpnsshd``, file transfer utilities ``hpnscp`` and ``hpnsftp`` as well as tools for key generation (``hpnssh-keygen``), run-time key storage (``hpnssh-agent``) and a number of supporting programs. It includes numerous performance and functionality enhancements focused on high performance networks and computing envrironments. Complete information can be found in the HPN-README file.

It is fully compatible with all compliant implementations of the SSH protocol and OpenSSH in particular.

This version of HPNSSH is significant departure in terms of naming executables and installation locations. Specifically, all executables are now prefixed with ``hpn``. So ``ssh`` becomes ``hpnssh`` and ``scp`` is now ``hpnscp``. Configuation files and host keys can now be found in ``/etc/hpnssh``. By default ``hpnsshd`` now runs on port 2222 but this is configurable. This change was made in order to prevent installations of hpnssh, particularly from package distributions, from interfering with default installations of OpenSSH. HPNSSH is backwards compatible with all versions of OpenSSH including configuration files, keys, and run time options. Additionally, the client will, by default attempt to connect to port 2222 but will automatically fall back to port 22. This is also user configurable.

HPNSSH is based on OpenSSH portable. This is a port of OpenBSD's [OpenSSH](https://openssh.com) to most Unix-like operating systems, including Linux, OS X and Cygwin. Portable OpenSSH polyfills OpenBSD APIs that are not available elsewhere, adds sshd sandboxing for more operating systems and includes support for OS-native authentication and auditing (e.g. using PAM).

This document will be changing over time to reflect new changes and features. This document is built off of the OpenSSH README.md

Current information about release features are available in the HPN-README document.

## Documentation

The official documentation for HPN-SSH are the man pages for each tool.

* [hpnssh(1)](https://man.openbsd.org/ssh.1)
* [hpnsshd(8)](https://man.openbsd.org/sshd.8)
* [hpnssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)
* [hpnssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
* [hpnscp(1)](https://man.openbsd.org/scp.1)
* [hpnsftp(1)](https://man.openbsd.org/sftp.1)
* [hpnssh-keyscan(8)](https://man.openbsd.org/ssh-keyscan.8)
* [hpnsftp-server(8)](https://man.openbsd.org/sftp-server.8)

All options in OpenSSH are respected by HPN-SSH.

## Building HPNSSH

Detailed step by step instructions can be found at https://psc.edu/hpn-ssh-home/

### Dependencies

HPNSSH is built using autoconf and make. It requires a working C compiler, standard library and headers.

``libcrypto`` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) may also be used. HPN-SSH may be built without either of these, but the resulting binaries will have only a subset of the cryptographic algorithms normally available.
The developers of HPN-SSH strongly suggest the use of OpenSSL 3.0 or higher to support the advanced cryptography methods used.

[zlib](https://www.zlib.net/) is optional; without it transport compression is not supported.

FIDO security token support needs [libfido2](https://github.com/Yubico/libfido2) and its dependencies and will be enabled automatically if they are found.

In addition, certain platforms and build-time options may require additional dependencies; see README.platform for details about your platform.

### Building a release

Release tarballs and release branches in git include a pre-built copy of the ``configure`` script and may be built using:

```
tar zxvf hpnssh-X.YpZ.tar.gz
cd hpn-ssh
autoreconf -f -i
./configure # [options]
make && make tests
```

See the [Build-time Customisation](#build-time-customisation) section below for configure options. If you plan on installing OpenSSH to your system, then you will usually want to specify destination paths.

### Building from git

If building from the git master branch, you'll need [autoconf](https://www.gnu.org/software/autoconf/) installed to build the ``configure`` script. The following commands will check out and build HPN-SSH from git:

```
git clone https://github.com/rapier1/hpn-ssh
cd hpn-ssh
autoreconf -f -i
./configure
make && make tests
```

### Build-time Customisation

There are many build-time customisation options available. All Autoconf destination path flags (e.g. ``--prefix``) are supported (and are usually required if you want to install HPN-SSH).

For a full list of available flags, run ``./configure --help`` but a few of the more frequently-used ones are described below. Some of these flags will require additional libraries and/or headers be installed.

Flag | Meaning
--- | ---
``--with-pam`` | Enable [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) support. [OpenPAM](https://www.openpam.org/), [Linux PAM](http://www.linux-pam.org/) and Solaris PAM are supported.
``--with-libedit`` | Enable [libedit](https://www.thrysoee.dk/editline/) support for sftp.
``--with-kerberos5`` | Enable Kerberos/GSSAPI support. Both [Heimdal](https://www.h5l.org/) and [MIT](https://web.mit.edu/kerberos/) Kerberos implementations are supported.
``--with-selinux`` | Enable [SELinux](https://en.wikipedia.org/wiki/Security-Enhanced_Linux) support.
``--with-security-key-builtin`` | Include built-in support for U2F/FIDO2 security keys. This requires [libfido2](https://github.com/Yubico/libfido2) be installed.

## Development

Portable OpenSSH development is discussed on the [openssh-unix-dev mailing list](https://lists.mindrot.org/mailman/listinfo/openssh-unix-dev) ([archive mirror](https://marc.info/?l=openssh-unix-dev)). Bugs and feature requests are tracked on our [Bugzilla](https://bugzilla.mindrot.org/).
HPN-SSH development is discussed on the [hpnssh-community mailing list](https://lists.psc.edu/mailman/listinfo/hpnssh-community) and on the [GitHub Discussions page](https://github.com/rapier1/hpn-ssh/discussions).

## Reporting bugs

_Non-security_ bugs may be reported to the developers via [GitHub Issues]](https://github.com/rapier1/hpn-ssh/issues) or via the mailing list above. Security bugs should be reported to [hpnssh@psc.edu](mailto:hpnssh@psc.edu).
