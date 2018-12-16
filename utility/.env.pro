# PostgreSQL
POSTGRES_PASSWORD=password
POSTGRES_USER=manati_db_user
POSTGRES_DB=manati_db
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
DATABASE_URL=postgres://manati_db_user:password@postgres:5432/manati_db
DATABASE_TEST_URL=postgres://manati_db_user:password@postgres:5432/manati_db_test
CONN_MAX_AGE=60

# Domain name, used by caddy
DOMAIN_NAME=manatiproject.com

# General settings
# DJANGO_READ_DOT_ENV_FILE=True
DJANGO_ADMIN_URL=
DJANGO_SETTINGS_MODULE=config.settings.production
DJANGO_SECRET_KEY=ZkZas*1kYc0@xyGC4oh8_+/%EEyUVkrpR2=dq1eyh62zgledwH
DJANGO_ALLOWED_HOSTS=*


# AWS Settings
DJANGO_AWS_ACCESS_KEY_ID=
DJANGO_AWS_SECRET_ACCESS_KEY=
DJANGO_AWS_STORAGE_BUCKET_NAME=

# Used with email
DJANGO_MAILGUN_API_KEY=
DJANGO_SERVER_EMAIL=
MAILGUN_SENDER_DOMAIN=

# Security! Better to use DNS for this task, but you can use redirect
DJANGO_SECURE_SSL_REDIRECT=False

# django-allauth
DJANGO_ACCOUNT_ALLOW_REGISTRATION=True

# django debug
DJANGO_DEBUG=True

# Redis Settings
REDIS_URL=redis://redis:6379
