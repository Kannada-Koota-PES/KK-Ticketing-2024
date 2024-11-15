from os import getenv

from dotenv import load_dotenv

load_dotenv()

class Config:
    DEBUG = True if getenv('DEBUG') == 'True' else False
    SECRET_KEY = getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = getenv('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
