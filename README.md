# Web Security Practice
## Requirement
`Node.js >= v18.0`

## Objectives

1. Add a "session" attribute to the appusers table.
2. When the user logs in, store the session ID in the "session" attribute of the user's record.  Please do not make any other changes to the database.
3. When the user navigates to the site, the back-end (1) checks if the user is logged in and has an active session; and (2) if so, the back-end looks up the user record based on the session ID and shows a simple welcome page showing the user's name and the contents of the "info" column.   Otherwise, the user is directed to a login/create account page.
4. When the user logs out, the session ID is deleted from the user's record (or is replaced with some place holder value such as "not logged in".
5. Add an option to allow users to register (i.e., add their user name and password)
Use the node.js's bcrypt package to securely store and verify passwords (in the SQL dabatabse). 
6. Use node.js's password strength checker package to check whether the user's password is strong according to OWASP 10 requirements covered in class.
7. Add a self-signed HTTPs certificate.
8. Configure the client-sessions package to have the session expire after 10 mins inactivity (which the program already uses).
9. Add CSP protection and make session cookies HTTPOnly to ensure some protection against XSS.
10. Make sure that the webapp has a privilege-restricted database account.

## How to run
1. Create a MySQL database `users` with hostname: `localhost`
2. Create `appusers` table with following schemas: `username`, `password`, `info`, `session`
3. Create user `appaccount` with password `apppass`
4. Run query `GRANT SELECT, INSERT, UPDATE ON users.appusers TO 'appaccount'@'localhost';`
to grant `SELECT, INSERT, UPDATE` privileges to `appaccount`.
5. Navigate to the main directory of `web_security_practice` and run `npm install` to install dependencies
6. Run `node sessions.js` and then open browser enter address `https://localhost:3000/`

## Group members
- Khang Ta
- Ethan Bartlett
- Edmond Tongyou
- Sebastian Reyes
- Miranda Smith
