from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv()

#mongo cloud url
MONGO_URL = os.getenv("MONGO_URL")

#create client
client = MongoClient(MONGO_URL)     

#create databse
db = client["register_login"]

#create collection
user_collection = db["register_users"]

#check for connection is done or not
def check_db():
    try:
        client.admin.command('ping')
        print('connected')
    except Exception as e:
        print(f'something wrong to connect: {e}')


if __name__ == "__main__":
    check_db()