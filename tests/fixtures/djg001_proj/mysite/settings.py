"""Minimal Django settings for DJG001 integration test (DEBUG=True)."""

DEBUG = True
SECRET_KEY = "test-secret-key-for-django_security_hunter-tests-not-for-production"
ALLOWED_HOSTS = ["testserver", "127.0.0.1"]
INSTALLED_APPS: list[str] = []
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
USE_TZ = True


