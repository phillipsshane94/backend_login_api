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

// Type User is used to store the info for each individual user in the database.
type User struct {
	Email     string `json:"email"`
	Password  string `json:"password"` //length is 32 in database
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
}

// Type Claims is used for evaluating claims for tokens on a user's email.
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

var secretToken = []byte("112233445566")

// All handlers take an http.ResponseWriter and an *http.Request for fulfilling the requirements
// of mux.HandleFunc.

// SignupHandler takes the decoded json data from the POST request, checks if the email is already
// in the database, and inserts into the database if it was not already found.
func SignupHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	newUser := User{}
	json.NewDecoder(r.Body).Decode(&newUser)
	newUser.Password = hash([]byte(newUser.Password))
	fmt.Println(newUser)

	//check if the email is already in the db
	_, err := db.Query("SELECT email FROM User WHERE email = ?", newUser.Email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	_, err = db.Exec("INSERT INTO User Values(?, ?, ?, ?)", newUser.Email, newUser.Password, newUser.FirstName, newUser.LastName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(newUser)

}

// LoginHandler decodes the json data from the GET request and calls the validate function on
// the provided email and password to check if the info provided was correct.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	user := User{}
	json.NewDecoder(r.Body).Decode(&user)
	login := validate(user.Email, user.Password, w)
	if login["login"] == "success" {
		response := login
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, login["message"].(string), http.StatusBadRequest)
	}

}

// validate checks to see if the provided email is in the database, then compares the provided
// password with the stored database password.  It creates a Claims object with the email and
// a 5 minute expiration.  The claim is used to create and sign a token to be set in a cookie
// for caching the user's session until logout.
func validate(email string, pass string, w http.ResponseWriter) map[string]interface{} {
	dbUser := User{}

	row := db.QueryRow("SELECT email, password, firstname, lastname FROM User WHERE email = ?", email)
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
	tokenString, err := token.SignedString(secretToken)
	if err != nil {
		return map[string]interface{}{"message": "problem generating token"}
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expiration,
	})

	_, err = db.Exec("INSERT INTO Session VALUES(?)", tokenString)
	if err != nil {
		return map[string]interface{}{"message": "problem inserting token into session"}
	}

	var response = map[string]interface{}{"login": "success"}
	return response
}

// LogoutHandler checks the cookie of the logged in user, pulls the token value from the session's cookie,
// and deletes that entry from the Session table.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
	}

	//pull claim to get token
	tokenString := c.Value

	//inserts token with expiration time
	_, err = db.Exec("DELETE FROM Session WHERE token=?", tokenString)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	m := map[string]string{"logout": "success"}
	json.NewEncoder(w).Encode(m)
}

// InfoHandler checks the cookie of the logged in user then generates a Claims object from the
// token info in the cookie and checks the validity of the token.  This function queries the Session
// table to make sure the user's token is in the table.  It queries the User for
// the user's first name and last name to write back to the client.
func InfoHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		// For any other type of error, return a bad request status
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//token checking
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

	//check if key is in session table
	var key string
	row := db.QueryRow("SELECT token FROM Session WHERE token=?", tokenString)
	err = row.Scan(&key)
	if err != nil { //the key was found in Session table
		http.Error(w, "need new login token", http.StatusUnauthorized)
		return
	}

	if key != tokenString {
		http.Error(w, "need new login token", http.StatusUnauthorized)
		return
	}

	var fname string
	var lname string
	row = db.QueryRow("SELECT firstname, lastname FROM User WHERE email=?", claims.Email)
	err = row.Scan(&fname, &lname)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	m := map[string]string{"user": fmt.Sprintf("%s %s", fname, lname)}
	json.NewEncoder(w).Encode(m)
}

// hash is used to generate an encrypted password from what was provided by the user.
func hash(pass []byte) string {
	hashed, err := bcrypt.GenerateFromPassword(pass, bcrypt.MinCost)
	if err != nil {
		panic(err.Error())
	}
	return string(hashed)
}

// clearSession deletes any token remnants from the session table on startup.
func clearSession() {
	_, _ = db.Exec("DELETE FROM Session")
}

var db *sql.DB
var err error

func main() {
	r := mux.NewRouter().StrictSlash(true)
	db, err = sql.Open("sqlite3", "ArrayTestDb.db")
	if err != nil {
		log.Printf("problem opening the database: %s", err)
		return
	}
	defer db.Close()

	r.HandleFunc("/user/info", InfoHandler).Methods("GET")
	r.HandleFunc("/user/signup", SignupHandler).Methods("POST")
	r.HandleFunc("/user/login", LoginHandler).Methods("GET")
	r.HandleFunc("/user/logout", LogoutHandler).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	clearSession()

	go log.Fatal(srv.ListenAndServe())
}
