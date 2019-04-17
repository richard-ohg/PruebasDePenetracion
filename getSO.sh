#!/bin/bash


if [ $# -eq 0 ]
then
      echo "Forma de ejecutarlo: ./getSO -i ip"
      exit 1
fi

while getopts ":i:" opt; do
  case $opt in
    i)
      IP=$OPTARG
      ;;

    :) 
      echo "Le faltan argumentos a la opción -i"
    	exit
			;;
    *)
      echo "Forma de ejecutarlo: ./getSO -i ip"
      exit 1
      ;;
  esac
done

if [ -z $IP ]
    then
        echo "Falta la ip."
        echo "Forma de ejecutarlo: ./getSO -i ip"
        exit 1
  fi

TTL=`ping $IP -c 1 | grep ttl | cut -d ' ' -f 6 | cut -d '=' -f 2`

if [ $TTL -le 64 ]
then
	echo "Es un linux"
elif [ $TTL -le 128 ]
then
	echo "Es un windows"
fi

echo $TTL