const chai = require("chai");
const expect = require("chai").expect;
chai.use(require("chai-http"));
chai.use(require("chai-json-schema-ajv"));
const server = require("../server");
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
              type: object
              required:
                - userHandle
                - password
              properties:
                userHandle:
                  type: string
                  x-stoplight:
                    id: zgorhkr0z4utb
                password:
                  type: string
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
              type: object
              required:
                - userHandle
                - password
              properties:
                userHandle:
                  type: string
                  x-stoplight:
                    id: omis9wao4n8df
                password:
                  type: string
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
      summary: Your GET endpoint
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
      description: Get high scores with pagination support
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
  securitySchemes:
    JSONWebToken:
      type: http
      scheme: bearer
      description: JWT
*/

describe("Testing signup", function () {
  before(function () {
    // start the server
    server.start();
  });

  after(function () {
    // close the server
    server.close();
  });

  it("should reject (status 400) the request if fields are missing", async function () {
    await chai
      .request(apiAddress)
      .post("/signup")
      .send({
        userHandle: "foo",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });

    await chai
      .request(apiAddress)
      .post("/signup")
      .send({
        password: "foo",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should reject (status 400) the request if userHandle is empty", async function () {
    await chai
      .request(apiAddress)
      .post("/signup")
      .send({
        userHandle: "",
        password: "123456",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should reject if userHandle is shorter than 6 chars", async function () {
    await chai
      .request(apiAddress)
      .post("/signup")
      .send({
        userHandle: "foo",
        password: "123456",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should reject if password is shorter than 6 chars", async function () {
    await chai
      .request(apiAddress)
      .post("/signup")
      .send({
        userHandle: "foobar",
        password: "12345",
      })
      .then((response) => {
        expect(response.status).to.equal(400);
      })
      .catch((error) => {
        throw error;
      });
  });

  it("should response with status 201 if all information is correct", async function () {
    await chai
      .request(apiAddress)
      .post("/signup")
      .send({
        userHandle: "foobar",
        password: "123456",
      })
      .then((response) => {
        expect(response.status).to.equal(201);
      })
      .catch((error) => {
        throw error;
      });
  });
});
