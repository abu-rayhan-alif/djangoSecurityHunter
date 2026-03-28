"""CI integration scan: DEBUG off so DJG001 (CRITICAL) does not fire."""

DEBUG = False
SECRET_KEY = "django-security-hunter-ci-settings-not-secret-32b!"
ALLOWED_HOSTS = ["example.com", "127.0.0.1"]
INSTALLED_APPS: list[str] = []
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
USE_TZ = True
