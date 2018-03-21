#!/usr/bin/env bash

base=$PWD

cd "${base}/js"

if [ -f bower.json ]; then
    bower install
fi

for app in forum admin; do
    cd "${base}/js"

    if [ -d $app ]; then
        cd $app
        if [ -f bower.json ]; then
            bower install
        fi
        npm install
        gulp --production
    fi
done