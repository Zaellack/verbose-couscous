const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'QUIZZSITE',
});

//Middleware
app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({ secret: 'your_secret_key', resave: true, saveUninitialized: true }));
// ... (other middleware setup)


// Serve static files from the 'public' directory
app.use(express.static('public'));

// Root route to render the index.html file
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/views/index.html');
});

// Register route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if the username already exists in the database
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).send('Error checking username availability');
      return;
    }

    if (results.length > 0) {
      // Username already exists
      res.status(409).send('Username already in use');
    } else {
      // Hash the password using bcrypt
      const hashedPassword = await bcrypt.hash(password, 10);

      // Insert user into the database
      db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
        if (err) {
          console.error(err);
          res.status(500).send('Error registering user');
        } else {
          // Redirect to the main page after successful registration
          res.redirect('/main');
        }
      });
    }
  });
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Retrieve user from the database
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).send('Error retrieving user');
    } else if (results.length > 0) {
      // Compare the entered password with the hashed password from the database
      const match = await bcrypt.compare(password, results[0].password);

      if (match) {
        // Generate a JWT token
        const token = jwt.sign({ username }, 'secret_key', { expiresIn: '1h' });

        // Set the token in a cookie (you might want to store it securely in production)
        res.cookie('token', token);

        // Redirect to the main page
        res.redirect('/main');
      } else {
        res.status(401).send('Incorrect password');
      }
    } else {
      res.status(404).send('User not found');
    }
  });
});

// Main page route
app.get('/main', (req, res) => {
  // Check if the user has a valid token
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, 'secret_key');
    const username = decoded.username;

    // Render the main page with the authenticated user's information
    res.sendFile(__dirname + '/views/main.html');
  } catch (err) {
    console.error(err);
    res.clearCookie('token'); // Clear the token cookie on unauthorized access
    res.status(401).send('Unauthorized');
  }
});

// ... (other routes and configurations)

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});