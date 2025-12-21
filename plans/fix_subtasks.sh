#!/bin/bash
# Fix the nested subtasks
sed -i \
  -e '102,106 s/  - \[ \]/  - [x]/' \
  -e '108,110 s/  - \[ \]/  - [x]/' \
  -e '112,114 s/  - \[ \]/  - [x]/' \
  roadmap.md
