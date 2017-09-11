# Project ManaTI. Machine Learning for Threat Intuitive Analysis
The goal of the ManaTI project is to develop machine learning techniques to assist an intuitive threat analyst to speed the discovery of new security problems. The machine learning will contribute to the analysis by finding new relationships and inferences. The project will include the development of a web interface for the analyst to interact with the data and the machine learning output.

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

## Settings: Installation for development in master
ManaTI is a Django project with a Postgres database and it works in Linux and MacOS. We recommend using a virtualenv environment to setup it. The installation steps for linux are:

1. Clone the repository 

        git clone git@bitbucket.org:stratosphereips/project_manati.git

2. Install Virtualenv to isolate the required python libraries for ManaTI

        apt-get install virtualenv
        
3. Create virtualenv folder 
        
        virtualenv vmanati
        
4. Active Virtualenv

        source vmanati/bin/activate
        
5. Install PostgreSQL DB engine

        sudo apt-get install postgresql-server-dev-all
        
6. Install required python libraries
    
        pip install -r requirements.txt
        
7. Start postgresql

        /etc/init.d/postgresql start

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

13. Execute redis_worker.sh file (in background or another console). 
 
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
1. Open project directory

        cd path/to/project_directory
        
2. Pull the last changes from master

        git pull origin master

3. Install las libraries installed

        pip install -r requirements.txt
        
4. Install redis-server and execute redis_worker.sh file (in background or another console)

        ./redis_worker.sh
        
5. Prepare migrations files for guardian library (if it already has, nothings happens)
        
        python ./manage.py makemigrations guardian --noinput
        
6. Execute migrations files
 
        python ./manage.py migrate --noinput

7. Execute server
 
        python ./manage.py runserver

## Run in production.
 Using **surpevisor**, **gunicorn** as server with **RQ worker** (with redis server)
   to deal with the background tasks. In the future we are planning to 
   prepare settings for **nginx**
    
    cd path/to/project_directory 
    python ./manage.py collectstatic --noinput
    sudo supervisord -c supervisor-manati.conf -n

## Backup DB
    pg_dump -U manati_db_user -W -F p manati_db > backup.sql # plain text

## Restore DB
    psql manati_db -f backup.sql -U manati_db_user
