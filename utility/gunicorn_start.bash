#!/bin/bash

NAME="manati"                                       # Name of the application
DJANGODIR=.                                         # Django project directory
NUM_WORKERS=10                                      # how many worker processes should Gunicorn spawn
DJANGO_SETTINGS_MODULE=config.settings.local        # which settings file should Django use
DJANGO_WSGI_MODULE=config.wsgi                      # WSGI module name
PORT=8000

echo "Starting $NAME as `whoami`"

export DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE
export PYTHONPATH=$DJANGODIR:$PYTHONPATH

# Create the run directory if it doesn't exist
RUNDIR=$(dirname $SOCKFILE)
test -d $RUNDIR || mkdir -p $RUNDIR

# Start your Django Unicorn
# Programs meant to be run under supervisor should not daemonize themselves (do not use --daemon)
exec gunicorn ${DJANGO_WSGI_MODULE}:application \
  --name $NAME \
  --workers $NUM_WORKERS \
  --bind=127.0.0.1:$PORT \
  --log-level=info \
  --log-file=-
