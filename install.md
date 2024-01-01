### Debian installation ###
~~~
apt-get install dq
apt-get install dqcache
~~~

###Unix installation ###

#### download ####
~~~
wget https://github.com/janmojzis/dq/releases/download/20240101/20240101.tar.gz.asc
wget https://github.com/janmojzis/dq/archive/20240101.tar.gz
gpg --verify 20240101.tar.gz.asc 20240101.tar.gz
gunzip < 20240101.tar.gz | tar -xf -
cd dq-20240101
~~~

#### compile and install binaries ####
~~~
make
sudo make install
~~~

#### run dqcache ####
~~~
#under root - create dqcache root directory
sudo mkdir -p /etc/dqcache/root/servers /etc/dqcache/env
sudo echo 10000000 > /etc/dqcache/env/CACHESIZE
sudo echo 127.0.0.1 > /etc/dqcache/env/IP
sudo echo "/etc/dqcache/root" > /etc/dqcache/env/ROOT
~~~

~~~
#under root - setup dqcache root servers
sudo sh -c '(
echo "198.41.0.4"
echo "2001:503:ba3e::2:30"
echo "192.228.79.201"
echo "2001:500:84::b"
echo "192.33.4.12"
echo "2001:500:2::c"
echo "199.7.91.13"
echo "2001:500:2d::d"
echo "192.203.230.10"
echo "192.5.5.241"
echo "2001:500:2f::f"
echo "192.112.36.4"
echo "198.97.190.53"
echo "2001:500:1::53"
echo "192.36.148.17"
echo "2001:7fe::53"
echo "192.58.128.30"
echo "2001:503:c27::2:30"
echo "193.0.14.129"
echo "2001:7fd::1"
echo "199.7.83.42"
echo "2001:500:9f::42"
echo "202.12.27.33"
echo "2001:dc3::35"
) > /etc/dqcache/root/servers/@'
~~~

~~~
#under root - create dqcache user
sudo useradd dqcache
~~~

~~~
#under root - run dqcache server
sudo envuidgid dqcache envdir /etc/dqcache/env dqcache
~~~
