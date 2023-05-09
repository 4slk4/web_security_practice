'use strict'

// Import express
const  express = require('express');

// Import client sessions
const sessions = require('client-sessions');

// Import UUID to generate session ID
const { v4: uuidv4 } = require('uuid');

// Import body parser
const bodyParser = require("body-parser");

// Import HTTPS wrapper
const https = require('https');

// Import helmet(Content Security Policy - CSP)
const helmet = require('helmet');

// Import fs for reading files
const fs = require('fs');

// Import mysql library
const mysql = require('mysql');

// Import bcrypt library
const bcrypt = require('bcrypt');

// Import check-password-strength library
const { passwordStrength } = require('check-password-strength');

// Instantiate an express app
const app = express();

// Set Content Security Policy
app.use(
	helmet({
		contentSecurityPolicy: {
			directives: {
				defaultSrc: ["'self'"],
				scriptSrc: ["'self'"],
				styleSrc: ["'self'"],
				imgSrc: ["'self'"],
				connectSrc: ["'self'"],
				fontSrc: ["'self'"],
				objectSrc: ["'none'"],
				mediaSrc: ["'self'"],
				frameSrc: ["'none'"],
			},
		},
	})
);

// Set the view engine
app.set('view engine', 'ejs');

// Database information
const DB_HOST = "localhost";
const DB_NAME = "users";
const TABLE_NAME = "appusers";
const DB_USERNAME = "appaccount";
const DB_PASSWORD = "apppass"; 

// Connect to the database
const mysqlConn = mysql.createConnection({
	host: DB_HOST,
	user: DB_USERNAME,
	password: DB_PASSWORD,
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
	secret: "hello_kitty",
	cookieName: 'session',
	cookie: { httpOnly: true, 
			  secure: true,
			  ephemeral: false, // when set True, cookie expires when the browser close
			  maxAge: 60000 },
	resave: false,
	duration: 10 * 60 * 1000, // Close session after 10mins of inactivity
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
		res.render('dashboard.ejs', 
					{ username: req.session.username, 
					  info: req.session.info });
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
	
	// Get the username and password data from the form
	const { username, password } = req.body;
	
	// Construct the query
	let query = "USE "+ DB_NAME +";SELECT username,password,info FROM "+ TABLE_NAME +" WHERE username=?"; 
	// Query the DB for the user
	mysqlConn.query(query, [username], function(err, qResult){				
		if(err) throw err;
		
		if (qResult[1].length <= 0) {
			res.render('loginpage.ejs', { message: 'Username does not exist!' });
		}
		else {
			// Get the info message
			const info = qResult[1][0]['info'];
			
			// Get the hashed password from the DB
			const hashedPassDB = qResult[1][0]['password'];
	
			// Hash and compare the password with the hashed password in MariaDB
			bcrypt.compare(password, hashedPassDB, (err, result) => {
				if (err) throw err;
				
				// Passwords matched
				if (result) {
					// Set the session variable 
					req.session.username = username;
					req.session.info = info;
					req.session.id = uuidv4();
					
					// Update the session ID in the database
					const updateSessionQuery = "UPDATE "+ TABLE_NAME +" SET session='" + req.session.id + "' WHERE username='" + req.session.username + "'";
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
	if (req.session.username){
		res.redirect('/');
	}
	else {
		res.render('register.ejs', { message: null });
	}
	
});

/**
 * The register script
 * @param req - the request
 * @param res - the response
 */
app.post('/register', function(req, res){
	const { username, new_password, confirm_password, info } = req.body;

	// Check if username has been taken
	const queryCheckUsername = "USE "+ DB_NAME +";SELECT COUNT(*) AS count FROM "+ TABLE_NAME +" WHERE username=?";
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
						const queryCreateNewAcct = "INSERT INTO "+ TABLE_NAME +" VALUES(?,?,?,?)";
						mysqlConn.query(queryCreateNewAcct, [username, hashedPassword, info, null], (err) => {
							if (err) {
								throw err;
							}
							else {
								res.render("loginpage.ejs", { message: "New account has been created" });

							}
						})
					});
				}
			}
		}
	});
});

/**
 * The logout function
 * @param req - the request
 * @param res - the response
 */
app.get('/logout', function(req, res){
	
	// Clear the session from user
	const clearSessionQuery = "USE "+ DB_NAME +";UPDATE "+ TABLE_NAME +" SET session='not logged in' WHERE username='" + req.session.username + "'";
	mysqlConn.query(clearSessionQuery, function(err) {
		if (err) throw err;
		console.log("Clear user session")
	});
	
	// Disconnect MariaDB
	// mysqlConn.end((err) => {
	// 	if (err) throw err;
	// 	console.log("Disconnected from MariaDB!");
	// });
	
	// Kill the session
	req.session.reset();

	console.log('Redirect to the index page');
	res.redirect('/');
});

// Key data for certificates
let privateKey  = fs.readFileSync('./mykey.key', 'utf8');
let certificate = fs.readFileSync('./mycert.crt', 'utf8');
let credentials = { key: privateKey, cert: certificate };

// Wrap the express communications inside https
let httpsServer = https.createServer(credentials, app);
httpsServer.listen(3000);


