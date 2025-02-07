const express = require("express");
const app = express();
const port = process.env.PORT || 3002;
const jwt = require('jsonwebtoken')
const Ajv = require('ajv')
const ajvFormats = require('ajv-formats')
const crypto = require('crypto')
const passport = require('passport')
const passportJWT = require('passport-jwt')

app.use(express.json()); // for parsing application/json

// ------ WRITE YOUR SOLUTION HERE BELOW ------//
const SECRET_KEY = "my_secret-key";
//to store the users
const users = [];
//to store the highest scores
let highScores = [];

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

//hash password using crypto
const hashPassword = (password) => {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, "sha512")
    .toString("hex");
  return { hash, salt }; 
}

//verify password using saved hash and salt
const verifyPassword = (password, salt, hash) => {
  const newHash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, "sha512")
    .toString("hex");
return newHash === hash;    
  
};

app.post('/signup', (req, res) => {
  const validate = ajv.compile(userSchema);

  if (!validate(req.body)) {
    return res.status(400).json({ error: validate.errors});
  }

  const { userHandle, password } = req.body;


  //Hash the password before storing
  const { hash, salt } = hashPassword(password);

  //save the user
  users.push({ userHandle, hash, salt });
  res.status(201).json({ message: " User Registered Successfully" })

});

//passport JWT strategy setup
passport.use(new passportJWT.Strategy(
  {
    secretOrKey: SECRET_KEY,
    jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
  },
  (jwtPayload, done) => {
    const user = users.find((user) => user.userHandle === jwtPayload.userHandle);
    return done(null, user || false);

  }
)
);

//Login route
app.post('/login', (req, res) => {
  const { userHandle, password } = req.body;

  if (typeof userHandle !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: "Invalid input data type"});
  }

  
  if (!userHandle || !password) {
    return res.status(400).json({ message: "Missing userHandle or password"});
  }

  // Check for extra fields in the request body
  const allowedFields = ['userHandle', 'password'];
  const receivedFields = Object.keys(req.body);
  const extraFields = receivedFields.filter(field => !allowedFields.includes(field));

  if (extraFields.length > 0) {
    return res.status(400).json({ message: `Invalid fields: ${extraFields.join(', ')}` });
  }

  const user = users.find((u) =>u.userHandle === userHandle);

  //if the user does not exist
  if (!user) {
    return res.status(401).json({ message: "Incorrect uesrname"})
  }

  //check the password
  if (!verifyPassword(password, user.salt, user.hash)) {
    return res.status(401).json({ message: "Incorrect password"});
  }


  //generate the JWT token 
  const token = jwt.sign({ userHandle }, SECRET_KEY, { expiresIn: "1h"});

  res.status(200).json({ jsonWebToken: token});

});

//middleware to protect routes using JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
   return res.status(401).json({ message: "Missing authentication token"});
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(401).json({message: "Invalid token"});
    }
    req.user = user;
    next();
  });
};

//post high-scores endpoint
app.post('/high-scores', authenticateJWT, (req, res) => {
    const { level, userHandle, score, timestamp } = req.body;
  
    //validate request body fields
    if (!userHandle || !level || !score || !timestamp) {
    
      return res.status(400).json({ error: "Missing required fields: level, score or timestamp" });
    }
   
    //save the new high score
    const newHighScore = {
      level,
      userHandle,
      score,
      timestamp
    };
    highScores.push(newHighScore);

    //Return a success response
    return res.status(201).json(newHighScore);

});

//Create a endpoint for get the high-score
app.get('/high-scores', async (req, res) => {
    const { level, page } = req.query;

    if (!level) {
        return res.status(400).json({ error: 'Level query parameter is required'});
    }

    const filteredScores = highScores
        .filter(score => score.level === level)
        .sort((a, b) => b.score - a.score);


    const pageNumber = parseInt(page, 10) || 1;
    const limit = 20;
    const startIndex = (pageNumber - 1) * limit;
    const paginatedScores = filteredScores.slice(startIndex, startIndex + limit);

   return res.status(200).json(paginatedScores);

});



// Your solution should be written here

//------ WRITE YOUR SOLUTION ABOVE THIS LINE ------//

let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};
