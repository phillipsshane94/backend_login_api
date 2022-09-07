# ArrayTest ReadMe



## Startup

This app can be started via "docker compose up -d" with a default docker installation.  
If errors come up due to docker, it can also be run via a simple "go run main.go" in powershell after navigating to the repo.  

## Postman Collection Link

https://www.postman.com/phillipsshane94/workspace/arraytest/collection/23024815-58e7585a-c18c-443f-8c70-57f36de7db73?action=share&creator=23024815

Fork the postman request to view the updated collection.  

## Design Decisions

For the database, I went with sqlite; it's super lightweight and easy to throw into a project with minimal effort.  
The server side is very quick to setup, and since the database is contained within a file, there is no setup required on the client side.  

The database has two tables: ArrayTestTable, the primary table which contains user info, and Session, which contains a token for current logged in users.  The token in the Session table determines if a user can reach the /user/home endpoint.  Upon logout, the token is deleted from the session table, and that user must login again if they want to get to the home page again.   

### External Modules

I used gorilla/mux for handling the endpoints.  After some research, it felt like it was pretty straight forward and widely recommended.  I ended up only using it for the endpoints in the final product, but earlier iterations used it for parsing variables from user input.  

I used mattn/go-sqlite3 for the sqlite driver.  After some research, it appears to be the go-to driver for applications using sqlite.  Again, since sqlite is so lightweight, I only needed this driver for opening the database file.  This driver is built on CGo, so there has to be an installation of gcc available within the path to use it.  <b>This shouldn't cause problems</b>, but if it does, just add your installation of gcc into your windows user environment variables.  For me, the tdm gcc worked.  

The jwt module was used for authentication purposes and does a great job handling tokens and claims.  

Crypto/bcrypt was imported simply for hashing provided passwords.  

### Endpoints

POST http://localhost:8080/user/signup

The signup endpoint allows a user to sign up providing an email, password, first name, and last name.  The json structure for sending these requests is as follows:
```
{
    "email": "example@place.com",
    "password": "notPassword",
    "firstname": "Jon",
    "lastname": "Doe"
}
```
This endpoint will respond with a very similar json structure, but with an encoded password.
```
{
    "email": "example@place.com",
    "password": "$2a$04$gyekJg9HwAC9iARcjR145uFII3/NTQZuuPjZ4ApFE2/cD/Iy7gsUG",
    "firstname": "Jon",
    "lastname": "Doe"
}
```

GET http://localhost:8080/user/login

The login endpoint allows a user to log in by providing an email and password.  The json for sending requests is as follows:
```
{
    "email": "test1@place.com",
    "password": "123456"
}
```
Upon successful login:
```
{
    "login": "success"
}
```
Upon failed login, it will respond with "wrong password" or "account not found."

GET http://localhost:8080/user/info

The info endpoint will display the current logged in user's first and last name.  Requires user to be logged in (the cookie for that user must be set), but no json is necessary.  The response from this endpoint is as follows:
```
{
    "user": "Shane Phillips"
}
``` 

GET http://localhost:8080/user/logout

The logout endpoint will remove the user's token from the active session, revoking access from the info endpoint.  The user must be logged in again to create a new token for the session.  Requires the user to be logged in (cookie for that user must be set), but no json is necessary.  The response from this endpoint on successful logout is as follows: 
```
{
    "logout": "success"
}
```