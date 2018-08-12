web: bin/start-nginx bin/start-pgbouncer-stunnel uwsgi heroku_uwsgi.ini
worker: python manage.py rqworker high default low
