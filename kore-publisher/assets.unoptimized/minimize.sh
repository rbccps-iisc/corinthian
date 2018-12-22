#!/bin/bash
for f in $(ls *.html)
do
	tr -d '\n' < $f | tr -d '\t' | sed 's/  \+/ /g' | sed 's/: /:/g' | sed 's/; /;/g' | sed 's/ {/{/g'> ../assets/$f
done
