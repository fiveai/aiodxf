#!/bin/bash
set -e
HERE="$(cd $(dirname "$0"); echo "$PWD")"
cd /tmp

dxf() {
  PYTHONPATH="$HERE/.." python -m aiodxf "$@"
}

cleanup() {
    trap - EXIT
    "$HERE/remove_container.sh" dxf_registry
}
trap cleanup EXIT
docker run -d -p 5000:5000 --name dxf_registry registry:2

export DXF_HOST=localhost:5000
export DXF_INSECURE=1

echo '2015-05 11' > logger.dat


aiodxf push-blob fred/datalogger logger.dat @may15-readings
aiodxf pull-blob fred/datalogger @may15-readings

aiodxf set-alias fred/datalogger may15-readings $(aiodxf push-blob fred/datalogger logger.dat)
aiodxf pull-blob fred/datalogger $(aiodxf get-alias fred/datalogger may15-readings)
