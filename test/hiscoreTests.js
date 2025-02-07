const chai = require("chai");
const expect = require("chai").expect;
chai.use(require("chai-http"));
chai.use(require("chai-json-schema-ajv"));
const server = require("../server");
const { response } = require("express");
const apiAddress = "http://localhost:" + (process.env.PORT || 3002);
/*
OPEN API Spoeification
openapi: 3.0.0
x-stoplight:
  id: kprm5u5uf4b5q
info:
  title: Game High Scores API
  description: "An API for managing high scores for different levels in a game. \r\nPlayers of the game will create an account when they start playing the game. \r\nThe game client will receive a JWT after successful login operation and then use \r\nthe JWT to post high scores."
  version: 1.0.0
  contact:
    name: Lasse Haverinen
    email: lasse.haverinen@oamk.fi
paths:
  /signup:
    post:
      description: Client signup
      summary: Register a new user
      operationId: signup
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserLoginSignup'
      responses:
        '201':
          description: User registered successfully
        '400':
          description: Invalid request body
      x-stoplight:
        id: o5myz60cmwc7a
  /login:
    post:
      description: Login with client
      summary: Login with username and password to receive JWT token
      operationId: login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserLoginSignup'
      responses:
        '200':
          description: 'Login successful, JWT token provided'
          content:
            application/json:
              schema:
                type: object
                required:
                  - jsonWebToken
                properties:
                  jsonWebToken:
                    type: string
                    x-stoplight:
                      id: s0zm8lfctp2we
        '400':
          description: Bad Request
        '401':
          description: 'Unauthorized, incorrect username or password'
      x-stoplight:
        id: yr2q2tls2bkff
  /high-scores:
    post:
      operationId: hiscorepost
      description: Submit high score
      summary: Post a high score for a specific level (Protected with JWT authentication)
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/HighScore'
      responses:
        '201':
          description: High score posted successfully
        '400':
          description: Invalid request body
        '401':
          description: 'Unauthorized, JWT token is missing or invalid'
      x-stoplight:
        id: emdp3h3a8pjxr
      security:
        - JSONWebToken: []
    get:
      summary: Get high scores
      tags: []
      responses:
        '200':
          description: OK
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/HighScore'
              examples:
                Example 1:
                  value:
                    - level: A4
                      userHandle: DukeNukem
                      score: 34555
                      timestamp: '2019-08-24T14:15:22Z'
      operationId: get-high-scores
      x-stoplight:
        id: oxhgpak9sjnd9
      description: 'Get high scores with pagination support. High scores should be ordered from biggest to smallest. '
      parameters:
        - schema:
            type: string
          in: query
          name: level
          description: Id of the level which to search
          required: true
        - schema:
            type: integer
          in: query
          name: page
          description: Page number for pagination (one page will have max 20 scores)
          required: true
components:
  schemas:
    HighScore:
      type: object
      properties:
        level:
          type: string
          description: The level for which the high score is posted
        userHandle:
          type: string
          description: The user's handle associated with the high score
        score:
          type: integer
          description: The high score achieved by the user
        timestamp:
          type: string
          format: date-time
          description: The timestamp when the high score was posted
      required:
        - level
        - userHandle
        - score
      x-stoplight:
        id: 08c8ilcn1g7f8
    UserLoginSignup:
      title: UserLoginSignup
      x-stoplight:
        id: bqztrjz4at4n7
      type: object
      required:
        - userHandle
        - password
      properties:
        userHandle:
          type: string
          x-stoplight:
            id: yzm8aw44c3mbg
          minLength: 6
        password:
          type: string
          x-stoplight:
            id: rbuhul3ps38uj
          minLength: 6
      x-examples:
        Example 1:
          userHandle: DukeNukem
          password: '123456'
  securitySchemes:
    JSONWebToken:
      type: http
      scheme: bearer
      description: JWT

*/

let JWT = null;

describe("Testing hiscores", function () {
  before(async function () {
    // start the server
    server.start();

    // sign in a user
    await chai
      .request(apiAddress)
      .post("/signup")
      .send({
        userHandle: "DukeNukem",
        password: "123456",
      })
      .then((response) => {
        console.log("signup success");
        expect(response.status).to.equal(201);
      })
      .catch((error) => {
        throw error;
      });

    // login user to get JWT
    await chai
      .request(apiAddress)
      .post("/login")
      .send({
        userHandle: "DukeNukem",
        password: "123456",
      })
      .then((response) => {
        console.log("login success with JWT");
        console.log(response.body.jsonWebToken);
        JWT = response.body.jsonWebToken;
      });
  });

  after(function () {
    // close the server
    server.close();
  });

  it("should respond OK 201 to an successful hiscore post", async function () {
    await chai
      .request(apiAddress)
      .post("/high-scores")
      .set("Authorization", "Bearer " + JWT)
      .send({
        level: "A1",
        userHandle: "DukeNukem",
        score: 12345,
        timestamp: "2021-04-01T12:00:00Z",
      })
      .then((response) => {
        console.log(response.status);
        console.log(response.body);
        expect(response.status).to.equal(201);
      })
      .catch((error) => {
        throw error;
      });
  });
  it("should respond with status 401 if JWT token is missing", async function () {
    await chai
      .request(apiAddress)
      .post("/high-scores")
      .send({
        level: "A1",
        userHandle: "DukeNukem",
        score: 12345,
        timestamp: "2021-04-01T12:00:00Z",
      })
      .then((response) => {
        expect(response.status).to.equal(401);
      })
      .catch((error) => {
        throw error;
      });
  });
  it("should respond with status 401 if JWT token is invalid", async function () {
    await chai
      .request(apiAddress)
      .post("/high-scores")
      .set("Authorization", "Bearer " + "invalidJWT")
      .send({
        level: "A1",
        userHandle: "DukeNukem",
        score: 12345,
        timestamp: "2021-04-01T12:00:00Z",
      })
      .then((response) => {
        expect(response.status).to.equal(401);
      })
      .catch((error) => {
        throw error;
      });
  });
  it("should respond with status 400 if level is missing", async function () {
    await chai
      .request(apiAddress)
      .post("/high-scores")
      .set("Authorization", "Bearer " + JWT)
      .send({
        userHandle: "DukeNukem",
        score: 12345,
        timestamp: "2021-04-01T12:00:00Z",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });
  it("should respond with status 400 if userHandle is missing", async function () {
    await chai
      .request(apiAddress)
      .post("/high-scores")
      .set("Authorization", "Bearer " + JWT)
      .send({
        level: "A1",
        score: 12345,
        timestamp: "2021-04-01T12:00:00Z",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });
  it("should respond with status 400 if score is missing", async function () {
    await chai
      .request(apiAddress)
      .post("/high-scores")
      .set("Authorization", "Bearer " + JWT)
      .send({
        level: "A1",
        userHandle: "DukeNukem",
        timestamp: "2021-04-01T12:00:00Z",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });
  it("should respond with status 400 if timestamp is missing", async function () {
    await chai
      .request(apiAddress)
      .post("/high-scores")
      .set("Authorization", "Bearer " + JWT)
      .send({
        level: "A1",
        userHandle: "DukeNukem",
        score: 12345,
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should respond with an array of highscores for a specific level", async function () {
    await chai
      .request(apiAddress)
      .get("/high-scores")
      .query({ level: "A1" })
      .then((response) => {
        expect(response.status).to.equal(200);
        expect(response.body).to.be.an("array");
        expect(response.body.length).to.be.greaterThan(0);
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should respond with an empty array if level is not found", async function () {
    await chai
      .request(apiAddress)
      .get("/high-scores")
      .query({ level: "A100" })
      .then((response) => {
        expect(response.status).to.equal(200);
        expect(response.body).to.be.an("array");
        expect(response.body.length).to.equal(0);
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should respond with array of highscores for a specific level and page, scores should be ordered from biggest to smallest", async function () {
    // first add thirty high scores for level A2
    for (let i = 0; i < 30; i++) {
      const minutes = i < 10 ? "0" + i.toString() : i.toString();
      // construct timestamp in the format of 2021-04-01T12:00:00Z
      const timestamp = `2021-04-01T12:${minutes}:00Z`;
      await chai
        .request(apiAddress)
        .post("/high-scores")
        .set("Authorization", "Bearer " + JWT)
        .send({
          level: "A2",
          userHandle: "DukeNukem",
          score: Math.floor(Math.random() * 100000),
          timestamp: timestamp,
        });
    }

    // get the first page without page parameter, should return 20 high scores
    await chai
      .request(apiAddress)
      .get("/high-scores")
      .query({ level: "A2" })
      .then((response) => {
        expect(response.status).to.equal(200);
        expect(response.body).to.be.an("array");
        expect(response.body.length).to.equal(20);

        // Check that high scores are ordered from biggest to smallest
        let lastScore = response.body[0].score;
        for (let i = 1; i < response.body.length; i++) {
          expect(response.body[i].score).to.be.lte(lastScore);
          lastScore = response.body[i].score;
        }

        expect(response.body[0].level).to.equal("A2");
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should give correct page of highscores for a specific level", async function () {
    // get the second page with page parameter 2, should return 10 high scores
    await chai
      .request(apiAddress)
      .get("/high-scores")
      .query({ level: "A2", page: 2 })
      .then((response) => {
        expect(response.status).to.equal(200);
        expect(response.body).to.be.an("array");
        expect(response.body.length).to.equal(10);
      })
      .catch((error) => {
        throw error;
      });
  });
});
