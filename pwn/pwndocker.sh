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

# I would like gef not pwndbg plz
docker exec ${ctf_name} sh -c "wget -O ~/.gdbinit-gef.py -q https://github.com/hugsy/gef/raw/master/gef.py"
docker exec ${ctf_name} sh -c "sed -i 's/source \/pwndbg\/gdbinit.py/source ~\/.gdbinit-gef.py/g' ~/.gdbinit"

docker exec -it ${ctf_name} /bin/bash
