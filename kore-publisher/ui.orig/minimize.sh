for f in `ls *.orig.html`
do
	cwd=`pwd`
	dir=`basename $cwd | cut -f1 -d'.'`

	file=`echo $f | cut -f1,3 -d'.'`
	cat $f | tr -d '\n' | tr -d '\t' | sed 's/  \+/ /g' | sed 's/: /:/g' | sed 's/; /;/g' | sed 's/ {/{/g'> ../$dir/$file
done
