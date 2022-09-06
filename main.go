package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email     string `json:"email"`
	Password  string `json:"password"` //length is 32 in database
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

var secretToken = "112233445566"

// All handlers take an http.ResponseWriter and an *http.Request for fulfilling the requirements
// of mux.HandleFunc and for getting user input from web forms.

// SignupHandler will display the signup page that allows a user to enter an email and password
// that will be logged into the database, allowing that user to login to the website.
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	newUser := User{}
	json.NewDecoder(r.Body).Decode(&newUser)
	newUser.Password = hash([]byte(newUser.Password))
	fmt.Println(newUser)

	//check if the email is already in the db
	_, err := db.Query("SELECT email FROM ArrayTestTable WHERE email = ?", newUser.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	_, err = db.Exec("INSERT INTO ArrayTestTable Values(?, ?, ?, ?)", newUser.Email, newUser.Password, newUser.FirstName, newUser.LastName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(newUser)

}

// LoginHandler will display the login page that allows a user to enter an email and password
// to log in to the website.  Redirects to the home page upon successful login.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user := User{}
	json.NewDecoder(r.Body).Decode(&user)
	login := validate(user.Email, user.Password, w)
	if login["login"] == "good" {
		response := login
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, login["message"].(string), http.StatusBadRequest)
	}
}

func validate(email string, pass string, w http.ResponseWriter) map[string]interface{} {
	dbUser := User{}

	row := db.QueryRow("SELECT email, password, firstname, lastname FROM ArrayTestTable WHERE email = ?", email)
	err = row.Scan(&dbUser.Email, &dbUser.Password, &dbUser.FirstName, &dbUser.LastName)
	if err != nil {
		return map[string]interface{}{"message": "account not found"}
	}

	userPass := []byte(pass)
	dbPass := []byte(dbUser.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)
	if passErr != nil {
		return map[string]interface{}{"message": "wrong password"}
	}

	expiration := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: dbUser.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secretToken))
	if err != nil {
		return map[string]interface{}{"message": "problem generating token"}
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expiration,
	})

	// _, err = db.Exec("INSERT INTO ArrayTestTable (token) VALUES (?) WHERE email=?", token, email)
	// if err != nil {
	// 	return map[string]interface{}{"message": "problem inserting token"}
	// }

	var response = map[string]interface{}{"login": "good"}
	response["jwt"] = token
	response["data"] = dbUser
	return response
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenString := c.Value
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims,
		func(token *jwt.Token) (interface{}, error) {
			return secretToken, nil
		})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !token.Valid {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("Welcome home, %s!", claims.Email)))
}

func hash(pass []byte) string {
	hashed, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		panic(err.Error())
	}
	return string(hashed)
}

var db *sql.DB
var err error

func main() {
	r := mux.NewRouter().StrictSlash(true)
	// r.Use(setContentType)
	db, err = sql.Open("sqlite3", "ArrayTestDb.db")
	if err != nil {
		log.Printf("problem opening the database: %s", err)
		return
	}
	defer db.Close()

	r.HandleFunc("/user/home", HomeHandler).Methods("GET")
	r.HandleFunc("/user/signup", SignupHandler).Methods("POST")
	r.HandleFunc("/user/login", LoginHandler).Methods("GET")
	r.HandleFunc("/user/logout", LogoutHandler).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}
