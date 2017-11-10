# Project ManaTI
*Machine Learning for Threat Intuitive Analysis* 

The goal of the ManaTI project is to develop machine learning techniques to assist an intuitive threat analyst to speed the discovery of new security problems. The machine learning will contribute to the analysis by finding new relationships and inferences. The project will include the development of a web interface for the analyst to interact with the data and the machine learning output.

This project is partially supported by Cisco Systems.

## Versions
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
    ([@Piuliss](https://www.twitter.com/Piuliss), <raulbeni@gmail.com>, <rbenitez@uni.edu.py>, <benitrau@fit.cvut.cz>)
- **Sebastian García** ([@eldracote](https://www.twitter.com/eldracote), <sebastian.garcia@agents.fel.cvut.cz>, <eldraco@gmail.com>)

## Installation
ManaTI is a Django project with a Postgres database and it works in Linux and MacOS. We recommend using a virtualenv environment to setup it. The installation steps for linux are:

        sudo apt-get update ; sudo apt-get upgrade -y

1. Clone the repository 

        git clone git@github.com:stratosphereips/Manati.git
      
   or if you don't want to use SSH, use HTTPS
   
        git clone https://github.com/stratosphereips/Manati.git

2. Install Virtualenv to isolate the required python libraries for ManaTI,also will be installed python libraries for development

        sudo apt-get install virtualenv python-pip python-dev libpq-dev build-essential libssl-dev libffi-dev
        
3. Create virtualenv folder 
        
        virtualenv .vmanati
        
4. Active Virtualenv

        source .vmanati/bin/activate
        
5. Install PostgreSQL DB engine

        sudo apt-get install postgresql-server-dev-all postgresql-9.5 postgresql-client-9.5
        
6. Install required python libraries
    
        pip install -r requirements.txt
        
   Maybe you will have some issues with permission in the folder ~/.cache, just perform the next command and problem solved:
        
        sudo chmod 777 ~/.cache
        
7. Start postgresql

        sudo /etc/init.d/postgresql start

## Configure the database
8. As root: (There should be a user postgres after installing the database)

        su - postgres
         
9. Create the database: 

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
10. As the postgres user

        psql -h localhost -d manati_db -U manati_db_user

        (and put the password)

After putting the password you should be logged in in the postgres.

You can change the password of the manati_db_user in the database and the in the code in the file manati/settings.py
11. Install redis-server

    apt-get install redis-server
        
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

        
12. Run migrate files
        
        python ./manage.py makemigrations guardian
        python ./manage.py migrate
        
13. Registering External modules. You must run this command everytime you add or remove a  External
Module

         python ./manage.py check_external_modules

14. Execute redis_worker.sh file (in background or another console). 
 
        ./redis_worker.sh
        
15. Create super user for login in the web system if you need 

        python manage.py createsuperuser

## How to run it
It is not recommended to run the server as root, but since only root can open ports numbers less than 1024, it is up to you which user you use. By default it opens the port 8000, so you can run it as root:

    python ./manage.py runserver

After this, just open your browser in [http://localhost:8000/manati_project/manati_ui](http://localhost:8000/manati_project//manati_ui)

If you want to open the server in the network, you can do it with:

    python ./manage.py runserver <ip-address>:8000

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

    pip install -r requirements.txt
        
<li>Install redis-server and execute redis_worker.sh 
file (in background or another console)</li>

    ./redis_worker.sh
        
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

## Docker Compose
If you don't want to waste time installing ManaTI and you have docker installed,  you can just
 execute docker-compose. 
```bash
cd path/manati/project
docker-compose build
docker-compose run web bash -c "python manage.py makemigrations --noinput && python manage.py migrate"
docker-compose run web bash -c "python manage.py check_external_modules && python manage.py createsuperuser"
docker-compose up # or 'docker-compose up -d' if you don't want to see the logs in the console.
```
## Backup DB
    pg_dump -U manati_db_user -W -F p manati_db > backup.sql # plain text

## Restore DB
    psql manati_db -f backup.sql -U manati_db_user
