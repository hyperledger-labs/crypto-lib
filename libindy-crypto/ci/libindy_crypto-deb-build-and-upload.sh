#!/bin/bash -xe

if [ "$1" = "--help" ] ; then
  echo "Usage: <version> <key> <type> <number>"
  return
fi

version="$1"
key="$2"
type="$3"
number="$4"

[ -z $version ] && exit 1
[ -z $key ] && exit 2
[ -z $type ] && exit 3
[ -z $number ] && exit 4

dpkg-buildpackage -tc

#cat <<EOF | sftp -v -oStrictHostKeyChecking=no -i $key repo@192.168.11.111
#mkdir /var/repository/repos/libindy_crypto/ubuntu/$type/$version-$number
#cd /var/repository/repos/libindy_crypto/ubuntu/$type/$version-$number
#put -r ../libindy-crypto-dev_"$version"_amd64.deb
#put -r ../libindy-crypto_"$version"_amd64.deb
#ls -l /var/repository/repos/libindy_crypto/ubuntu/$type/$version-$number
#EOF

ls ../sovrin-packaging
python3 ../sovrin-packaging/upload_debs.py ../ $type
