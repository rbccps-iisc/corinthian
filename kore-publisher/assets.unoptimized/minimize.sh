for f in `ls *.html`
do
	cat $f | tr -d '\n' | tr -d '\t' | sed 's/  \+/ /g' | sed 's/: /:/g' | sed 's/; /;/g' | sed 's/ {/{/g'> ../assets/$f
done
