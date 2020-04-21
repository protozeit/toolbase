#!/usr/bin/env bash

# assumes that it's being run from inside ~/ctf/ctfname/
ctf_name=`basename $(pwd)`

docker run -d \
	--rm \
	-h ${ctf_name} \
	--name ${ctf_name} \
	-v $HOME/ctf/${ctf_name}:/ctf/work \
	-p 23946:23946 \
	--cap-add=SYS_PTRACE \
	skysider/pwndocker

docker exec -it ${ctf_name} /bin/bash
