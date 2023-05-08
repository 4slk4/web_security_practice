'use strict'

// Import express
const  express = require('express');

// Import client sessions
const sessions = require('client-sessions');

// Import UUID
const { v4: uuidv4 } = require('uuid');

// Import body parser
const bodyParser = require("body-parser");

// Import mysql library
const mysql = require('mysql');

// Import bcrypt library
const bcrypt = require('bcrypt');

// Import check-password-strength library
const { passwordStrength } = require('check-password-strength');

// Instantiate an express app
const app = express();

// Set the view engine
app.set('view engine', 'ejs');

// Connect to the database
const mysqlConn = mysql.createConnection({
	host: "localhost",
	user: "appaccount",
	password: "apppass",
	multipleStatements: true
});
mysqlConn.connect((err) => {
	if (err) throw err;
	console.log("Connected to MariaDB!");
});


// Needed to parse the request body
// Note that in version 4 of express, express.bodyParser() was
// deprecated in favor of a separate 'body-parser' module.
app.use(bodyParser.urlencoded({ extended: true })); 

// The session settings middleware	
app.use(sessions({
	secret: "hellokitty",
	cookieName: 'session',
	cookie: { httpOnly: true, 
			  secure: false, 
			  maxAge: null },
	resave: false,
	duration: 30 * 60 * 1000,
	activeDuration: 5 * 60 * 1000,
})); 

/**
 * The default page 
 * @param req - the request 
 * @param res - the response
 */

app.get("/", function(req, res){
	
	// Is this user logged in?
	if(req.session.username)
	{
		// Yes!
		res.redirect('/dashboard');
	}
	else
	{
		// No!
		res.render('loginpage.ejs', { message: null });
	}

});

/**
 * The dashboard page
 * @param req - the request
 * @param res - the response
 */
app.get('/dashboard', function(req, res){
	
	// Is this user logged in? Then show the dashboard
	if(req.session.username)
	{
		res.render('dashboard.ejs', {username: req.session.username});
	}
	//Not logged in! Redirect to the mainpage
	else
	{
		res.redirect('/');
	}

});

/**
 * The login script
 * @param req - the request
 * @param res - the response
 */
app.post('/login', function(req, res){
	
	// Get the username data from the form
	const userName = req.body.username;

	// Get the password data from the form and hash with bcrypt
	const password = req.body.password;
	
	
	// Construct the query
	let query = "USE users;SELECT username,password FROM appusers WHERE username=?"; 
	// Query the DB for the user
	mysqlConn.query(query, [userName], function(err, qResult){				
		if(err) throw err;
		
		if (qResult[1].length <= 0) {
			res.render('loginpage.ejs', { message: 'Username does not exist!' });
		}
		else {
			// Check password
			// Get the hashed password from the DB
			const hashedPassDB = qResult[1][0]['password'];
	
			// Hash and compare the password with the hashed password in DB
			bcrypt.compare(password, hashedPassDB, (err, result) => {
				if (err) throw err;
				
				// Passwords matched
				if (result) {
					// Set the session variable 
					req.session.username = userName;
					req.session.id = uuidv4();
					
					// Update the session ID in the database
					const updateSessionQuery = "UPDATE appusers SET session='" + req.session.id + "' WHERE username='" + req.session.username + "'";
					mysqlConn.query(updateSessionQuery, function(err) {
						if (err) throw err;
					});
					res.redirect('/dashboard');
				}
				// Passwords not matched
				else {
					res.render('loginpage.ejs', { message: 'Incorrect password!' });
				}
			});
		}
		
		
	});
	
});

/**
 * The register page
 * @param req - the request
 * @param res - the response
 */
app.get('/register', function(req, res){
	res.render('register.ejs', { message: null });
});

/**
 * The register script
 * @param req - the request
 * @param res - the response
 */
app.post('/register', function(req, res){
	const { username, new_password, confirm_password, info } = req.body;

	// Check if username has been taken
	const queryCheckUsername = "USE users;SELECT COUNT(*) AS count FROM appusers WHERE username=?";
	mysqlConn.query(queryCheckUsername, [username], (err, qResult) => {
		if (err) throw err;
		if (qResult[1][0]['count'] !== 0){
			return res.render('register.ejs', { message: "Your username has been taken!" });
		}
		else {
			// Check password strength
			const passwordStrengthResult = passwordStrength(new_password);
			if (passwordStrengthResult.value !== "Medium") {
				res.render('register.ejs', 
					{ message: 'Your password is not strong enough'}
				);
			}
			else {
				// Check if password confirmation is correct
				if (new_password !== confirm_password) {
					res.render('register.ejs', 
						{ message: "New password and confirm password do not match."});
				}
				else {
					// Store the new credentials into MariaDB
					
					// Hash the new password
					bcrypt.hash(new_password, 10, (err, hashedPassword) => {
						if (err) throw err;
						// Create a query to store the credentials
						const queryCreateNewAcct = "INSERT INTO appusers VALUES(?,?,?,?)";
						mysqlConn.query(queryCreateNewAcct, [username, hashedPassword, info, null], (err) => {
							if (err) {
								throw err;
							}
							else {
								res.render("loginpage.ejs", { message: "New account has been created" });
								//"Asd1234!"
							}
						})
					});
				}
			}
		}
	});






})

/**
 * The logout function
 * @param req - the request
 * @param res - the response
 */
app.get('/logout', function(req, res){
	
	// Clear the session from user
	const clearSessionQuery = "USE users;UPDATE appusers SET session='not logged in' WHERE username='" + req.session.username + "'";
	mysqlConn.query(updateSessionQuery, function(err) {
		if (err) throw err;
		console.log("Clear user session")
	});
	
	// Disconnect MariaDB
	mysqlConn.end((err) => {
		if (err) throw err;
		console.log("Disconnected from MariaDB!");
	});
	
	// Kill the session
	req.session.reset();
	res.redirect('/');
});

app.listen(3000);


