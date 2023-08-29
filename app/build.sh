#!/bin/bash

workspace=${1}
app="${workspace}/app"
dockerVolume="/usr/src/app"

mkdir -p ${workspace}
cp -fr ${dockerVolume} ${workspace}
cd ${app}
cargo build
cp -fr "${app}/target" ${dockerVolume}
