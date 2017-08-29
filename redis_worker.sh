#!/bin/bash
function checkIt()
{
    number=$(ps aux | grep $1 | wc -l)

    if [ $number -gt 1 ]; then
        return=true
    else
        return=false
    fi;
}

checkIt "redis-server"
echo $return
if [ "$return" != "true" ]; then
   echo "Run redis"
   redis-server /usr/local/etc/redis.conf &
fi;

checkIt "rqworker"
echo $return
if [ "$return" != "true" ]; then
   echo "Run rqworker"
   /Users/raulbeniteznetto/Projects/python_env/manati/bin/python ./manage.py rqworker high default low &
fi;
