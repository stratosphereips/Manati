# Project ManaTI
[![Build Status](https://travis-ci.org/Piuliss/Manati.svg?branch=master)](https://travis-ci.org/Piuliss/Manati)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/stratosphereips/Manati/issues)
[![GPLv3 license](https://img.shields.io/badge/License-GPLv3-blue.svg)](http://perso.crans.org/besson/LICENSE.html)
[![release](https://img.shields.io/badge/release-v0.9.2a-brightgreen.svg?style=flat)](https://github.com/stratosphereips/Manati/releases/latest)

*Machine Learning for Threat Intuitive Analysis* 

The goal of the ManaTI project is to develop machine learning techniques to assist an intuitive threat analyst to speed the discovery of new security problems. The machine learning will contribute to the analysis by finding new relationships and inferences. The project will include the development of a web interface for the analyst to interact with the data and the machine learning output.

This project is partially supported by Cisco Systems.

## Stable Versions
- Mon Jan 29 00:07:15 CEST 2018: Version 0.9.0a
- Fri Nov 10 19:16:52 CEST 2017: Version 0.8.0.537a
- Fri Mar 31 12:19:00 CEST 2017: Version 0.7.1
- Sun Mar  5 00:04:41 CEST 2017: Version 0.7
- Thu Nov 10 12:30:45 CEST 2016: Version 0.6.2.1
- Wed Oct 12 21:19:21 CEST 2016: Version 0.5.1
- Wed Sep 21 17:56:40 CEST 2016: Version 0.41
- Tue Sep 13 10:52:36 CEST 2016: Version 0.4
- Thu Aug 18 15:44:31 CEST 2016: Version 0.3
- Wed Jun 29 10:44:15 CEST 2016: Version 0.2

## Authors

- **Raúl B. Netto** 
    ([@Piuliss](https://www.twitter.com/Piuliss), <raulbeni@gmail.com>, <benitrau@fit.cvut.cz>)
- **Sebastian García** ([@eldracote](https://www.twitter.com/eldracote), <sebastian.garcia@agents.fel.cvut.cz>, <eldraco@gmail.com>)

## App Screenshot

![manati_screenshot](https://user-images.githubusercontent.com/1384962/36067482-75a78ca4-0ebe-11e8-886a-341adb06508b.png)

## Installation
ManaTI is a Django project with a Postgres database and it works in Linux and MacOS. We recommend using a virtualenv environment to setup it. The installation steps for linux are:

        sudo apt-get update ; sudo apt-get upgrade -y
<ol>
<li>Clone the repository</li> 

        git clone git@github.com:stratosphereips/Manati.git; cd Manati
      
   or if you don't want to use SSH, use HTTPS
   
        git clone https://github.com/stratosphereips/Manati.git; cd Manati

<li> Install Virtualenv to isolate the required python libraries for ManaTI, 
also will be installed python libraries for development </li>

        sudo apt-get install virtualenv python-pip python-dev libpq-dev build-essential libssl-dev libffi-dev
        
<li> Create virtualenv folder </li>
        
        virtualenv .vmanati
        
<li> Active Virtualenv </li>

        source .vmanati/bin/activate
        
<li> Install PostgreSQL DB engine </li>

        sudo apt-get install postgresql-server-dev-all postgresql-9.5 postgresql-client-9.5
        
<li> Create environment variables files. Copy and rename the files <b>.env.example</b> to <b>.env</b>, 
and <b>.env-docker.example</b> to <b>.env-docker</b></li> 
        
        cp .env.example .env
        cp .env-docker.example .env-docker


**OPTIONAL**

You can modify the password and name of database, if you want. 
Remember, reflect the changes in the Postgres database settings below. 
        
<li> Install required python libraries </li>
    
        pip install -r requirements/local.txt
        
   Maybe you will have some issues with permission in the folder ~/.cache, just perform the next command and problem solved:
        
        sudo chmod 777 ~/.cache
        
<li> Start postgresql </li>

        sudo /etc/init.d/postgresql start

## Configure the database
<li> As root: (There should be a user postgres after installing the database) </li>

        su - postgres
         
<li> Create the database: </li> 

        psql

        create user manati_db_user with password 'password';

        create database manati_db;

        grant all privileges on database manati_db to manati_db_user;

        alter role manati_db_user createrole createdb;
        
        CTRL-D (to output the postgres db shell)
        
**OPTIONAL**

To change the password by default of the postgres user (you can put the same password if you want), specially good idea if you want to use pgAdmin3-4 as a postgres client. Remember don't exit of "sudo - postgres"

        psql
        
        \password;

        CTRL-D (to output the postgres db shell)

## Verify that the db was created successfully
<li> As the postgres user </li>

        psql -h localhost -d manati_db -U manati_db_user

        (and put the password)

After putting the password you should be logged in in the postgres.
<li> Install redis-server </li>

        sudo apt-get install redis-server
        
   **OPTIONAL**
   
   If you want to configure the Redis. For example, you are
   interested to change the password, you can:
    
        sudo vi /etc/redis/redis.conf
        
   and find the line *requirepass* and write next it 
   the password that you want. 
        
        requirepass passwodUser
    
   Just remember to update
   the variable environment **REDIS_PASSWORD** in the
   file *.env* in the root of the project.

        
<li> Run migrate files </li>
        
        python ./manage.py makemigrations guardian
        python ./manage.py migrate
        
<li> Registering External modules. 
You must run this command everytime you add or remove 
an External Module</li>

         python ./manage.py check_external_modules

<li> Execute redis_worker.sh file (in background '&' or in another console). </li>
 
        ./utility/redis_worker.sh
        
<li> Create super user for login in the web system if you need </li> 

        python manage.py createsuperuser

## How to run it
It is not recommended to run the server as root, but since only root can open ports numbers less than 1024, it is up to you which user you use. By default it opens the port 8000, so you can run it as root:

    python ./manage.py runserver

After this, just open your browser in [http://localhost:8000/manati_project/manati_ui](http://localhost:8000/manati_project//manati_ui)

If you want to open the server in the network, you can do it with:

    python ./manage.py runserver <ip-address>:8000
</ol>

If you want to see the 
jobs running or enqueued go to 
[http://localhost:8000/manati_project/django-rq/](http://localhost:8000/manati_project/django-rq/)

## Settings: Updating version from master
<ol>
<li>Open project directory</li>

    cd path/to/project_directory
        
<li>Pull the last changes from master</li>

    git pull origin master

<li>Install las libraries installed</li>

    pip install -r requirements/local.txt
        
<li>Install redis-server and execute redis_worker.sh 
file (in background '&' or in another console)</li>

    ./utility/redis_worker.sh
        
<li>Prepare migrations files for guardian library 
(if it already has, nothings happens)</li>
        
    python ./manage.py makemigrations guardian --noinput
        
<li>Execute migrations files</li>
 
    python ./manage.py migrate --noinput

<li>Registering External modules. You must run this command everytime you add or remove an External
Module</li>
        
    python ./manage.py check_external_modules
        
<li>Execute server</li>
 
    python ./manage.py runserver
</ol>

## Run in production.
 Using **surpevisor**, **gunicorn** as server with **RQ worker** (with redis server)
   to deal with the background tasks. In the future we are planning to 
   prepare settings for **nginx**
```bash
cd path/to/project_directory 
python ./manage.py collectstatic --noinput
sudo supervisord -c supervisor-manati.conf -n
```

## Docker Composer
If you don't want to waste time installing ManaTI and you have docker installed,  you can just
 execute docker-compose. First clone the repository and go to the directory project.  
```bash
cd Manati
cp .env.example .env
cp .env-docker.example .env-docker
docker-compose build
docker-compose run web bash -c "python manage.py makemigrations --noinput; python manage.py migrate; python manage.py check_external_modules"
docker-compose run web bash -c "python manage.py createsuperuser2 --username admin --password Password123 --noinput --email 'admin@manatiproject.com'"
docker-compose up # or 'docker-compose up -d' if you don't want to see the logs in the console.
```

After this, just open your browser in [http://localhost:8000/manati_project/manati_ui/new](http://localhost:8000/manati_project/manati_ui/new)
## Backup DB
    pg_dump -U manati_db_user -W -F p manati_db > backup.sql # plain text

## Restore DB
    psql manati_db -f backup.sql -U manati_db_user
    
## Browser supported
| [<img src="https://raw.githubusercontent.com/godban/browsers-support-badges/master/src/images/edge.png" alt="IE / Edge" width="16px" height="16px" />](http://godban.github.io/browsers-support-badges/)</br>IE / Edge | [<img src="https://raw.githubusercontent.com/godban/browsers-support-badges/master/src/images/firefox.png" alt="Firefox" width="16px" height="16px" />](http://godban.github.io/browsers-support-badges/)</br>Firefox | [<img src="https://raw.githubusercontent.com/godban/browsers-support-badges/master/src/images/chrome.png" alt="Chrome" width="16px" height="16px" />](http://godban.github.io/browsers-support-badges/)</br>Chrome | [<img src="https://raw.githubusercontent.com/godban/browsers-support-badges/master/src/images/safari.png" alt="Safari" width="16px" height="16px" />](http://godban.github.io/browsers-support-badges/)</br>Safari | [<img src="https://raw.githubusercontent.com/godban/browsers-support-badges/master/src/images/opera.png" alt="Opera" width="16px" height="16px" />](http://godban.github.io/browsers-support-badges/)</br>Opera |[<img src="https://raw.githubusercontent.com/godban/browsers-support-badges/master/src/images/vivaldi.png" alt="Vivaldi" width="16px" height="16px" />](http://godban.github.io/browsers-support-badges/)</br>Vivaldi |
| --------- | --------- | --------- | --------- | --------- | --------- |
| N/A| 55+ | 60+ | N/A | N/A| N/A

## License

The GPLv3 License (GPLv3). See docs/LICENSE file for more details.

Copyright (c) 2016-2018 Stratosphere Laboratory
