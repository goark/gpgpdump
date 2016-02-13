#!/bin/bash

DIR=`pwd`
mkdir ./goxdist/dist
for PLATFORM in $(find ./goxdist -mindepth 1 -maxdepth 1 -type d); do
    PLATFORM_NAME=$(basename ${PLATFORM})

    if [ ${PLATFORM_NAME} = "dist" ]; then
        continue
    fi

    cd ${PLATFORM}
    zip ${DIR}/goxdist/dist/${PLATFORM_NAME}.zip ./*
    cd ${DIR}
done
