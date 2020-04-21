#!/usr/bin/env bash

# assumes that it's being run from inside ~/ctf/ctfname/
ctf_name=`basename $(pwd)`

docker run -d \
	--rm \
	-h ${ctf_name} \
	--name ${ctf_name} \
	-v $HOME/ctf/${ctf_name}:/home/sage/${ctf_name} \
	-p 127.0.0.1:8888:8888 \
	hyperreality/cryptohack

echo 'jupyter is running at 127.0.0.1:8888'

docker exec -it ${ctf_name} /bin/bash
