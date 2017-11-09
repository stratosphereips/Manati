web: bin/start-nginx bin/start-pgbouncer-stunnel uwsgi heroku_uwsgi.ini
worker: bin/start-pgbouncer-stunnel python manage.py qcluster
worker: python manage.py rqworker high default low &