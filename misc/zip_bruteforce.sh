#!/usr/bin/env bash

cd dump/
while true; do
	for file in $(ls); do
		echo "$file"
		if [[ $file == *.gz ]]
		then
			gunzip $file
		elif [[ $file == *.tar ]]
		then
			tar xf $file && rm $file
		else
			type=$(file $file | cut -d: -f2)
			if [[ $type == *"tar"* ]] 
			then
				mv $file{,.tar}
				continue
			elif [[ $type == *"gzip"* ]]
			then
				mv $file{,.gz}
				continue
			fi
			zip2john $file > ../hash
			john ../hash -w=../asdf -rules=wordlist
			password=$(john ../hash --show | cut -d: -f2 | sed '1q')
			mv $file{,.zip}
			unzip -q -P ${password} $file.zip && rm $file.zip
		fi
  done;
done;
