.PHONY: all clean

all:
	docker build -t transbind-plugin .
	mkdir -p plugin/rootfs/run/docker/plugins
	docker run --rm transbind-plugin \
		cat docker-mountpoint-transbind \
		> plugin/rootfs/docker-mountpoint-transbind
	chmod +x plugin/rootfs/docker-mountpoint-transbind
	cp config.json plugin/
	docker plugin create transbind plugin

clean:
	docker rmi transbind-plugin || true
	docker plugin rm transbind || true
	rm -rf plugin
