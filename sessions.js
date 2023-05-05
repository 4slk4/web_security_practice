'use strict'

// Import express
const  express = require('express');

// Import client sessions
const sessions = require('client-sessions');

// The body parser
const bodyParser = require("body-parser");

// The mysql library
const mysql = require('mysql');

// Instantiate an express app
const app = express();

// Set the view engine
app.set('view engine', 'ejs');

// Connect to the database
const  mysqlConn = mysql.createConnection({
	host: "localhost",
	user: "appaccount",
	password: "apppass",
	multipleStatements: true
	
});


// Needed to parse the request body
// Note that in version 4 of express, express.bodyParser() was
// deprecated in favor of a separate 'body-parser' module.
app.use(bodyParser.urlencoded({ extended: true })); 

// The session settings middleware	
app.use(sessions({
  cookieName: 'session',
  secret: 'random_string_goes_here',
  duration: 30 * 60 * 1000,
  activeDuration: 5 * 60 * 1000,
})); 

// The default page
// @param req - the request
// @param res - the response
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
		res.render('loginpage');
	}

});

// The login page
// @param req - the request
// @param res - the response
app.get('/dashboard', function(req, res){
	
	// Is this user logged in? Then show the dashboard
	if(req.session.username)
	{
		res.render('dashboard', {username: req.session.username});
	}
	//Not logged in! Redirect to the mainpage
	else
	{
		res.redirect('/');
	}

});

// The login script
// @param req - the request
// @param res - the response
app.post('/login', function(req, res){
	
	// Get the username and password data from the form
	let userName = req.body.username;
	let password = req.body.password;
	
			
	// Construct the query
	let query = "USE users; SELECT username,password from appusers where username='" + userName + "' AND password='" + password + "'"; 
	console.log(query);
			
				
	// Query the DB for the user
	mysqlConn.query(query, function(err, qResult){
					
		if(err) throw err;
					
		console.log(qResult[1]);	
		
		// Does the password match?
		let match = false;
			
		// Go through the results of the second query
		for(let account of qResult[1])
		{
			
			if(account['username'] == userName && account['password'] == password)
			{
				console.log("Match!");
				
				// We have a match!
				match = true;
				
				//break;
				
			}
		};

		// Login succeeded! Set the session variable and send the user
		// to the dashboard
		if(match)
		{
			req.session.username = userName;
			res.redirect('/dashboard');
		}
		else
		{
			// If no matches have been found, we are done
			res.send("<b>Wrong</b>");				
		}
	});
	
	
	
	/**
	if(correctPass && correctPass === password)
	{
		// Set the session
		req.session.username = userName;

		res.redirect('/dashboard');
	}
	else
	{
		res.send("Wrong!");
	}
	
	res.send("Wrong");

**/
});

// The logout function
// @param req - the request
// @param res - the response
app.get('/logout', function(req, res){

	// Kill the session
	req.session.reset();
	
	res.redirect('/');
});

app.listen(3000);


