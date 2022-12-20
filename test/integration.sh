#!/bin/bash
#
# This file is part of the PyRDP project.
# Copyright (C) 2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
# We extracted a set of important tests that were run as part of a GitHub
# workflow before. Having them all here makes them easy to run from a
# development environment. The GitHub worfklows can still run them.
#
# NOTE: Running these locally requires the test/files/test_files.zip to be
#       extracted in test/files/.

# Any non-zero exit code becomes an error now
set -e

# Sets how to launch commands. GitHub workflows sets the CI environment variable
if [[ -z "${CI}" ]]; then
	PREPEND=""
else
	PREPEND="coverage run --append bin/"
fi

export QT_QPA_PLATFORM=offscreen

echo ===================================================
echo pyrdp-player.py read a replay in headless mode test
${PREPEND}pyrdp-player.py --headless test/files/test_session.replay
echo

echo ===================================================
echo pyrdp-convert.py to MP4
${PREPEND}pyrdp-convert.py test/files/test_convert.pyrdp -f mp4
echo

echo ===================================================
echo Verify the MP4 file
file test_convert.mp4 | grep "MP4 Base Media"
rm test_convert.mp4
echo

echo ===================================================
echo pyrdp-convert.py replay to JSON
${PREPEND}pyrdp-convert.py test/files/test_convert.pyrdp -f json
echo

echo ===================================================
echo Verify the replay to JSON file
./test/validate_json.sh test_convert.json
rm test_convert.json
echo

echo ===================================================
echo pyrdp-convert.py PCAP to JSON
${PREPEND}pyrdp-convert.py test/files/test_session.pcap -f json
echo

echo ===================================================
echo Verify the PCAP to JSON file
./test/validate_json.sh "20200319000716_192.168.38.1:20989-192.168.38.1:3389.json"
rm "20200319000716_192.168.38.1:20989-192.168.38.1:3389.json"
echo

echo ===================================================
echo pyrdp-convert.py PCAP to replay
${PREPEND}pyrdp-convert.py test/files/test_session.pcap -f replay
echo

echo ===================================================
echo Verify that the replay file exists
file -E "20200319000716_192.168.38.1:20989-192.168.38.1:3389.pyrdp"
rm "20200319000716_192.168.38.1:20989-192.168.38.1:3389.pyrdp"

echo ===================================================
echo pyrdp-convert.py regression issue 428
${PREPEND}pyrdp-convert.py test/files/test_convert_428.pyrdp -f mp4
echo

echo ===================================================
echo Verify the MP4 file
file test_convert_428.mp4 | grep "MP4 Base Media"
rm test_convert_428.mp4
echo
