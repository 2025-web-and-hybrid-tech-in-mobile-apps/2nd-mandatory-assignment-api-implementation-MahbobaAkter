const express = require("express");
const app = express();
const port = process.env.PORT || 3002;
const jwt = require('jsonwebtoken');
const Ajv = require('ajv');
const ajvFormats = require('ajv-formats');
const crypto = require('crypto');
const passport = require('passport');
const passportJWT = require('passport-jwt');

app.use(express.json()); // Enable JSON parsing

// Secret key for JWT
const SECRET_KEY = "my_secret-key";

// In-memory storage (replace with a database in production)
const users = [];
let highScores = [];

// Set up AJV for schema validation
const ajv = new Ajv();
ajvFormats(ajv);

const userSchema = {
  type: "object",
  properties: {
    userHandle: { type: "string", minLength: 6 },
    password: { type: "string", minLength: 6 }
  },
  required: ["userHandle", "password"],
  additionalProperties: false,
};

// Hash password using crypto
const hashPassword = (password) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
  return { hash, salt };
};

// Verify password
const verifyPassword = (password, salt, hash) => {
  const newHash = crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex");
  return newHash === hash;
};

// Signup route
app.post('/signup', (req, res) => {
  const validate = ajv.compile(userSchema);

  if (!validate(req.body)) {
    return res.status(400).json({ error: validate.errors });
  }

  const { userHandle, password } = req.body;

  // Check if user already exists
  if (users.some(user => user.userHandle === userHandle)) {
    return res.status(400).json({ error: "User already exists" });
  }

  // Hash and save user
  const { hash, salt } = hashPassword(password);
  users.push({ userHandle, hash, salt });

  res.status(201).json({ message: "User Registered Successfully" });
});

// Passport JWT strategy setup
passport.use(new passportJWT.Strategy(
  {
    secretOrKey: SECRET_KEY,
    jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
  },
  (jwtPayload, done) => {
    const user = users.find(user => user.userHandle === jwtPayload.userHandle);
    return done(null, user || false);
  }
));



// Login route
app.post('/login', (req, res) => {
  const { userHandle, password } = req.body;

  if (typeof userHandle !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: "Invalid input data type" });
  }

  if (!userHandle || !password) {
    return res.status(400).json({ message: "Missing userHandle or password" });
  }

 
  


  // Check for extra fields
  const allowedFields = ['userHandle', 'password'];
  const receivedFields = Object.keys(req.body);
  const extraFields = receivedFields.filter(field => !allowedFields.includes(field));

  if (extraFields.length > 0) {
    return res.status(400).json({ message: `Invalid fields: ${extraFields.join(', ')}` });
  }

  const user = users.find(u => u.userHandle === userHandle);
  if (!user) {
    return res.status(401).json({ message: "Incorrect username" });
  }

  if (!verifyPassword(password, user.salt, user.hash)) {
    return res.status(401).json({ message: "Incorrect password" });
  }

  // Generate JWT
  const token = jwt.sign({ userHandle }, SECRET_KEY, { expiresIn: "1h" });

  res.status(200).json({ jsonWebToken: token });
});

// Middleware to protect routes using JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Missing authentication token" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// POST high scores
app.post('/high-scores', authenticateJWT, (req, res) => {
  const { level, userHandle, score, timestamp } = req.body;

  if (!userHandle || !level || !score || !timestamp) {
    return res.status(400).json({ error: "Missing required fields: level, userHandle, score, or timestamp" });
  }

  // Save high score
  const newHighScore = { level, userHandle, score, timestamp };
  highScores.push(newHighScore);

  res.status(201).json(newHighScore);
});

// GET high scores
app.get('/high-scores', async (req, res) => {
  const { level, page } = req.query;

  if (!level) {
    return res.status(400).json({ error: "Level query parameter is required" });
  }

  const filteredScores = highScores
    .filter(score => score.level === level)
    .sort((a, b) => b.score - a.score);

  const pageNumber = parseInt(page, 10) || 1;
  const limit = 20;
  const startIndex = (pageNumber - 1) * limit;
  const paginatedScores = filteredScores.slice(startIndex, startIndex + limit);

  res.status(200).json(paginatedScores);
});

// Start & stop server for tests
let serverInstance = null;
module.exports = {
  start: function () {
    if (!serverInstance) {
      serverInstance = app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
      });
    }
  },
  close: function () {
    if (serverInstance) {
      serverInstance.close();
      serverInstance = null;
    }
  },
};

// Start the server only if not in test mode
if (require.main === module) {
  module.exports.start();
}
