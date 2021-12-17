compile: make-dq.sh
	sh -e make-dq.sh
cross-compile: make-dqcc.sh
	sh -e make-dqcc.sh
clean:
	rm -rf build
install:
	sh -e make-install.sh $(DESTDIR)
deb:
	dpkg-buildpackage -b -rfakeroot -us -uc
