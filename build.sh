#!/usr/bin/env bash

set -ex

rm -rf dist && mkdir dist

cd client_mod && make clean && make && /usr/bin/cp -f ./*.ko ../dist/
cd ../server_mod && make clean && make && /usr/bin/cp -f ./*.ko ../dist/
