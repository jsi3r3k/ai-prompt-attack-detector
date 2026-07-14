import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def get_env_value(name, default=None):
    value = os.getenv(name)

    if value is None:
        return default

    value = value.strip()

    if value == "":
        return default

    return value


DEFAULT_DETECTION_METHOD = get_env_value(
    "DEFAULT_DETECTION_METHOD",
    "rules",
)

GEMINI_API_KEY = get_env_value("GEMINI_API_KEY")

GEMINI_MODEL = get_env_value(
    "GEMINI_MODEL",
    "gemini-2.5-flash-lite",
)

OPENAI_API_KEY = get_env_value("OPENAI_API_KEY")
OPENAI_MODEL = get_env_value("OPENAI_MODEL")