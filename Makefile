
tarball: filesystem.tar.gz

filesystem.tar.gz: $(wildcard *.py)
	tar -czf $@ $^

