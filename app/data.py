from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

db =  {
    "ali": {
        "username": "ali",
        "fullname": "Ali Muiz",
        "email": "ali@gmail.com",
        "hashed_password": pwd_context.hash("my_password"),
        "disabled": False
    },
    "user1": {
        "username": "user1",
        "fullname": "User 1",
        "email": "user1@gmail.com",
        "hashed_password": pwd_context.hash("123"),
        "disabled": False
    }
}

