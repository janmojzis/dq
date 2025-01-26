CC?=cc
CFLAGS+=-O3 -fno-strict-overflow -fwrapv -Wno-parentheses -Wundef -Wunused-value -Wmissing-prototypes -Wmissing-declarations -Wwrite-strings -Wdeclaration-after-statement -Wshadow -Wno-unused-function -Wno-overlength-strings -Wno-long-long -Wall -pedantic -Icryptoint
LDFLAGS?=
CPPFLAGS?=
DESTDIR?=

BINARIES=dq
BINARIES+=dqcache
BINARIES+=dqcache-makekey
BINARIES+=dqcache-start

all: $(BINARIES)

alloc.o: alloc.c e.h uint64_pack.h cryptoint/crypto_uint64.h \
 uint64_unpack.h byte.h purge.h alloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c alloc.c

base32decode.o: base32decode.c base32decode.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c base32decode.c

blocking.o: blocking.c blocking.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c blocking.c

buffer_2.o: buffer_2.c buffer.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c buffer_2.c

buffer.o: buffer.c buffer.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c buffer.c

buffer_put.o: buffer_put.c e.h str.h byte.h buffer.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c buffer_put.c

buffer_write.o: buffer_write.c writeall.h buffer.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c buffer_write.c

byte.o: byte.c byte.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c byte.c

cache.o: cache.c alloc.h byte.h uint64_pack.h cryptoint/crypto_uint64.h \
 uint64_unpack.h cryptoint/crypto_uint32.h seconds.h die.h randombytes.h \
 haslibrandombytes.h buffer.h open.h dns.h stralloc.h \
 crypto_auth_siphash24.h e.h cache.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c cache.c

case.o: case.c case.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c case.c

cleanup.o: cleanup.c cleanup.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c cleanup.c

crypto_auth_siphash24.o: crypto_auth_siphash24.c siphash.h \
 crypto_verify_8.h crypto_auth_siphash24.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_auth_siphash24.c

crypto_box_curve25519xsalsa20poly1305.o: \
 crypto_box_curve25519xsalsa20poly1305.c crypto_core_hsalsa20.h \
 crypto_scalarmult_curve25519.h haslib25519.h \
 crypto_secretbox_xsalsa20poly1305.h randombytes.h haslibrandombytes.h \
 crypto_box_curve25519xsalsa20poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_box_curve25519xsalsa20poly1305.c

crypto_core_hsalsa20.o: crypto_core_hsalsa20.c salsa.h \
 cryptoint/crypto_uint32.h cleanup.h crypto_core_hsalsa20.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_core_hsalsa20.c

crypto_onetimeauth_poly1305.o: crypto_onetimeauth_poly1305.c \
 cryptoint/crypto_int16.h cryptoint/crypto_uint32.h \
 cryptoint/crypto_uint64.h crypto_onetimeauth_poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_onetimeauth_poly1305.c

crypto_scalarmult_curve25519.o: crypto_scalarmult_curve25519.c \
 crypto_scalarmult_curve25519.h haslib25519.h cryptoint/crypto_uint8.h \
 cryptoint/crypto_uint32.h cryptoint/crypto_uint64.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_scalarmult_curve25519.c

crypto_secretbox_xsalsa20poly1305.o: crypto_secretbox_xsalsa20poly1305.c \
 crypto_onetimeauth_poly1305.h crypto_stream_xsalsa20.h cleanup.h \
 crypto_secretbox_xsalsa20poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_secretbox_xsalsa20poly1305.c

crypto_stream_salsa20.o: crypto_stream_salsa20.c salsa.h \
 cryptoint/crypto_uint32.h crypto_stream_salsa20.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_stream_salsa20.c

crypto_stream_xsalsa20.o: crypto_stream_xsalsa20.c crypto_core_hsalsa20.h \
 crypto_stream_salsa20.h cleanup.h crypto_stream_xsalsa20.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_stream_xsalsa20.c

crypto_verify_16.o: crypto_verify_16.c verify.h crypto_verify_16.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_verify_16.c

crypto_verify_32.o: crypto_verify_32.c verify.h crypto_verify_32.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_verify_32.c

crypto_verify_8.o: crypto_verify_8.c verify.h crypto_verify_8.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c crypto_verify_8.c

die.o: die.c alloc.h writeall.h die.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c die.c

dns_base32.o: dns_base32.c byte.h dns.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_base32.c

dns_data.o: dns_data.c stralloc.h alloc.h byte.h dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_data.c

dns_domain.o: dns_domain.c alloc.h byte.h case.h e.h dns.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_domain.c

dns_dtda.o: dns_dtda.c stralloc.h dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_dtda.c

dns_ip.o: dns_ip.c alloc.h byte.h cryptoint/crypto_uint16.h \
 base32decode.h hexdecode.h case.h str.h stralloc.h strtoip.h \
 milliseconds.h dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_ip.c

dns_ipq.o: dns_ipq.c stralloc.h case.h byte.h str.h dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_ipq.c

dns_iptoname.o: dns_iptoname.c byte.h numtostr.h dns.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_iptoname.c

dns_keys.o: dns_keys.c crypto_stream_salsa20.h dns.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_keys.c

dns_nonce.o: dns_nonce.c nanoseconds.h randombytes.h haslibrandombytes.h \
 cryptoint/crypto_uint32.h cryptoint/crypto_uint64.h byte.h purge.h dns.h \
 stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_nonce.c

dns_packet.o: dns_packet.c e.h byte.h dns.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_packet.c

dns_rcip.o: dns_rcip.c milliseconds.h openreadclose.h stralloc.h byte.h \
 env.h strtoip.h strtomultiip.h xsocket.h dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_rcip.c

dns_rcrw.o: dns_rcrw.c milliseconds.h env.h byte.h str.h openreadclose.h \
 stralloc.h dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_rcrw.c

dns_resolve.o: dns_resolve.c milliseconds.h byte.h e.h dns.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_resolve.c

dns_sortip.o: dns_sortip.c randommod.h byte.h dns.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_sortip.c

dns_transmit.o: dns_transmit.c alloc.h milliseconds.h xsocket.h e.h \
 byte.h cryptoint/crypto_uint16.h randombytes.h haslibrandombytes.h \
 randommod.h case.h str.h dns.h stralloc.h \
 crypto_box_curve25519xsalsa20poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_transmit.c

dns_verbosity.o: dns_verbosity.c stralloc.h writeall.h iptostr.h \
 porttostr.h numtostr.h e.h cryptoint/crypto_uint16.h byte.h dns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dns_verbosity.c

dq.o: dq.c dns.h stralloc.h strtonum.h case.h die.h e.h randombytes.h \
 haslibrandombytes.h byte.h printpacket.h writeall.h milliseconds.h str.h \
 cryptoint/crypto_uint16.h portparse.h base32decode.h hexdecode.h \
 strtoip.h keyparse.h typeparse.h purge.h \
 crypto_box_curve25519xsalsa20poly1305.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dq.c

dqcache.o: dqcache.c env.h byte.h xsocket.h strtoip.h randombytes.h \
 haslibrandombytes.h cryptoint/crypto_uint64.h query.h dns.h stralloc.h \
 cryptoint/crypto_uint32.h die.h warn.h e.h numtostr.h strtonum.h cache.h \
 response.h log.h roots.h hexparse.h alloc.h milliseconds.h blocking.h \
 cryptoint/crypto_uint16.h portparse.h droproot.h okclient.h purge.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dqcache.c

dqcache-makekey.o: dqcache-makekey.c randombytes.h haslibrandombytes.h \
 writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dqcache-makekey.c

dqcache-start.o: dqcache-start.c numtostr.h strtonum.h e.h die.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c dqcache-start.c

droproot.o: droproot.c env.h die.h strtonum.h e.h droproot.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c droproot.c

e.o: e.c e.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c e.c

env.o: env.c str.h env.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c env.c

hexdecode.o: hexdecode.c hexdecode.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c hexdecode.c

hexparse.o: hexparse.c hexparse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c hexparse.c

iptostr.o: iptostr.c byte.h iptostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c iptostr.c

keyparse.o: keyparse.c hexdecode.h base32decode.h byte.h str.h keyparse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c keyparse.c

log.o: log.c buffer.h cryptoint/crypto_uint32.h cryptoint/crypto_uint16.h \
 e.h byte.h iptostr.h numtostr.h log.h cryptoint/crypto_uint64.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c log.c

milliseconds.o: milliseconds.c milliseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c milliseconds.c

nanoseconds.o: nanoseconds.c nanoseconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c nanoseconds.c

numtostr.o: numtostr.c numtostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c numtostr.c

okclient.o: okclient.c str.h byte.h iptostr.h okclient.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c okclient.c

open_read.o: open_read.c open.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_read.c

openreadclose.o: openreadclose.c open.h e.h byte.h openreadclose.h \
 stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c openreadclose.c

open_trunc.o: open_trunc.c open.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c open_trunc.c

portparse.o: portparse.c portparse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c portparse.c

porttostr.o: porttostr.c cryptoint/crypto_uint16.h porttostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c porttostr.c

printpacket.o: printpacket.c cryptoint/crypto_uint16.h e.h byte.h dns.h \
 stralloc.h printrecord.h printpacket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c printpacket.c

printrecord.o: printrecord.c cryptoint/crypto_uint16.h \
 cryptoint/crypto_uint32.h e.h byte.h dns.h stralloc.h printrecord.h \
 iptostr.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c printrecord.c

query.o: query.c e.h roots.h log.h cryptoint/crypto_uint64.h case.h \
 cache.h byte.h dns.h stralloc.h cryptoint/crypto_uint32.h \
 cryptoint/crypto_uint16.h alloc.h response.h query.h strtoip.h iptostr.h \
 xsocket.h crypto_scalarmult_curve25519.h haslib25519.h \
 crypto_box_curve25519xsalsa20poly1305.h purge.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c query.c

randombytes.o: randombytes.c randombytes.h haslibrandombytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randombytes.c

randommod.o: randommod.c randombytes.h haslibrandombytes.h randommod.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c randommod.c

response.o: response.c dns.h stralloc.h byte.h cryptoint/crypto_uint16.h \
 cryptoint/crypto_uint32.h response.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c response.c

roots.o: roots.c open.h e.h str.h byte.h direntry.h strtoip.h dns.h \
 stralloc.h openreadclose.h roots.h keyparse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c roots.c

salsa.o: salsa.c cryptoint/crypto_uint64.h cryptoint/crypto_uint32.h \
 salsa.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c salsa.c

seconds.o: seconds.c seconds.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c seconds.c

siphash.o: siphash.c uint64_pack.h cryptoint/crypto_uint64.h \
 uint64_unpack.h siphash.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c siphash.c

stralloc.o: stralloc.c alloc.h e.h stralloc.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c stralloc.c

str.o: str.c str.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c str.c

strtoip.o: strtoip.c byte.h strtoip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtoip.c

strtomultiip.o: strtomultiip.c byte.h str.h strtoip.h strtomultiip.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtomultiip.c

strtonum.o: strtonum.c e.h strtonum.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c strtonum.c

typeparse.o: typeparse.c strtonum.h cryptoint/crypto_uint16.h case.h \
 dns.h stralloc.h byte.h typeparse.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c typeparse.c

uint16_optblocker.o: uint16_optblocker.c cryptoint/crypto_uint16.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint16_optblocker.c

uint32_optblocker.o: uint32_optblocker.c cryptoint/crypto_uint32.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint32_optblocker.c

uint64_optblocker.o: uint64_optblocker.c cryptoint/crypto_uint64.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint64_optblocker.c

uint64_pack.o: uint64_pack.c uint64_pack.h cryptoint/crypto_uint64.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint64_pack.c

uint64_unpack.o: uint64_unpack.c uint64_unpack.h \
 cryptoint/crypto_uint64.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint64_unpack.c

uint8_optblocker.o: uint8_optblocker.c cryptoint/crypto_uint8.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c uint8_optblocker.c

verify.o: verify.c verify.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c verify.c

warn.o: warn.c writeall.h warn.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c warn.c

writeall.o: writeall.c e.h writeall.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c writeall.c

xsocket_accept.o: xsocket_accept.c e.h byte.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_accept.c

xsocket_bind.o: xsocket_bind.c e.h byte.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_bind.c

xsocket_conn.o: xsocket_conn.c e.h byte.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_conn.c

xsocket_listen.o: xsocket_listen.c e.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_listen.c

xsocket_recv.o: xsocket_recv.c e.h byte.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_recv.c

xsocket_send.o: xsocket_send.c e.h byte.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_send.c

xsocket_tcp.o: xsocket_tcp.c blocking.h e.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_tcp.c

xsocket_type.o: xsocket_type.c byte.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_type.c

xsocket_udp.o: xsocket_udp.c blocking.h e.h xsocket.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c xsocket_udp.c

OBJECTS=alloc.o
OBJECTS+=base32decode.o
OBJECTS+=blocking.o
OBJECTS+=buffer_2.o
OBJECTS+=buffer.o
OBJECTS+=buffer_put.o
OBJECTS+=buffer_write.o
OBJECTS+=byte.o
OBJECTS+=cache.o
OBJECTS+=case.o
OBJECTS+=cleanup.o
OBJECTS+=crypto_auth_siphash24.o
OBJECTS+=crypto_box_curve25519xsalsa20poly1305.o
OBJECTS+=crypto_core_hsalsa20.o
OBJECTS+=crypto_onetimeauth_poly1305.o
OBJECTS+=crypto_scalarmult_curve25519.o
OBJECTS+=crypto_secretbox_xsalsa20poly1305.o
OBJECTS+=crypto_stream_salsa20.o
OBJECTS+=crypto_stream_xsalsa20.o
OBJECTS+=crypto_verify_16.o
OBJECTS+=crypto_verify_32.o
OBJECTS+=crypto_verify_8.o
OBJECTS+=die.o
OBJECTS+=dns_base32.o
OBJECTS+=dns_data.o
OBJECTS+=dns_domain.o
OBJECTS+=dns_dtda.o
OBJECTS+=dns_ip.o
OBJECTS+=dns_ipq.o
OBJECTS+=dns_iptoname.o
OBJECTS+=dns_keys.o
OBJECTS+=dns_nonce.o
OBJECTS+=dns_packet.o
OBJECTS+=dns_rcip.o
OBJECTS+=dns_rcrw.o
OBJECTS+=dns_resolve.o
OBJECTS+=dns_sortip.o
OBJECTS+=dns_transmit.o
OBJECTS+=dns_verbosity.o
OBJECTS+=droproot.o
OBJECTS+=e.o
OBJECTS+=env.o
OBJECTS+=hexdecode.o
OBJECTS+=hexparse.o
OBJECTS+=iptostr.o
OBJECTS+=keyparse.o
OBJECTS+=log.o
OBJECTS+=milliseconds.o
OBJECTS+=nanoseconds.o
OBJECTS+=numtostr.o
OBJECTS+=okclient.o
OBJECTS+=open_read.o
OBJECTS+=openreadclose.o
OBJECTS+=open_trunc.o
OBJECTS+=portparse.o
OBJECTS+=porttostr.o
OBJECTS+=printpacket.o
OBJECTS+=printrecord.o
OBJECTS+=query.o
OBJECTS+=randombytes.o
OBJECTS+=randommod.o
OBJECTS+=response.o
OBJECTS+=roots.o
OBJECTS+=salsa.o
OBJECTS+=seconds.o
OBJECTS+=siphash.o
OBJECTS+=stralloc.o
OBJECTS+=str.o
OBJECTS+=strtoip.o
OBJECTS+=strtomultiip.o
OBJECTS+=strtonum.o
OBJECTS+=typeparse.o
OBJECTS+=uint16_optblocker.o
OBJECTS+=uint32_optblocker.o
OBJECTS+=uint64_optblocker.o
OBJECTS+=uint64_pack.o
OBJECTS+=uint64_unpack.o
OBJECTS+=uint8_optblocker.o
OBJECTS+=verify.o
OBJECTS+=warn.o
OBJECTS+=writeall.o
OBJECTS+=xsocket_accept.o
OBJECTS+=xsocket_bind.o
OBJECTS+=xsocket_conn.o
OBJECTS+=xsocket_listen.o
OBJECTS+=xsocket_recv.o
OBJECTS+=xsocket_send.o
OBJECTS+=xsocket_tcp.o
OBJECTS+=xsocket_type.o
OBJECTS+=xsocket_udp.o

dq: dq.o $(OBJECTS) libs
	$(CC) $(CFLAGS) $(CPPFLAGS) -o dq dq.o $(OBJECTS) $(LDFLAGS) `cat libs`

dqcache: dqcache.o $(OBJECTS) libs
	$(CC) $(CFLAGS) $(CPPFLAGS) -o dqcache dqcache.o $(OBJECTS) $(LDFLAGS) `cat libs`

dqcache-makekey: dqcache-makekey.o $(OBJECTS) libs
	$(CC) $(CFLAGS) $(CPPFLAGS) -o dqcache-makekey dqcache-makekey.o $(OBJECTS) $(LDFLAGS) `cat libs`

dqcache-start: dqcache-start.o $(OBJECTS) libs
	$(CC) $(CFLAGS) $(CPPFLAGS) -o dqcache-start dqcache-start.o $(OBJECTS) $(LDFLAGS) `cat libs`


haslib25519.h: tryfeature.sh haslib25519.c libs
	env CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS) `cat libs`" ./tryfeature.sh haslib25519.c >haslib25519.h 2>haslib25519.log
	cat haslib25519.h

haslibrandombytes.h: tryfeature.sh haslibrandombytes.c libs
	env CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS) `cat libs`" ./tryfeature.sh haslibrandombytes.c >haslibrandombytes.h 2>haslibrandombytes.log
	cat haslibrandombytes.h

libs: trylibs.sh
	env CC="$(CC)" ./trylibs.sh -lsocket -lnsl -lrandombytes -l25519 >libs
	cat libs

install: dq dqcache dqcache-makekey dqcache-start
	install -D -m 0755 dq $(DESTDIR)/usr/bin/dq
	install -D -m 0755 dqcache $(DESTDIR)/usr/sbin/dqcache
	install -D -m 0755 dqcache-makekey $(DESTDIR)/usr/sbin/dqcache-makekey
	install -D -m 0755 dqcache-start $(DESTDIR)/usr/sbin/dqcache-start

clean:
	rm -f *.log has*.h $(OBJECTS) $(BINARIES) libs

