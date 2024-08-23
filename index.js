const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const server_instance = express();
const sqlite3 = require("sqlite3");
const path = require("path");
const { open } = require("sqlite");
const dbPath = path.join(__dirname, "blog_detail.db");
let dataBase = null;
server_instance.use(cors());
server_instance.use(express.json());

const initialize_DataBase_and_Server = async () => {
  try {
    dataBase = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    server_instance.listen(3000, () => {
      console.log("sever is running on http://localhost:3000");
    });
  } catch (error) {
    console.log(`DataBase Error ${error.message}`);
    process.exit(1);
  }
};

initialize_DataBase_and_Server();

// Token Authorization (Middleware Function)
const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.header["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
    if (!jwtToken) {
      response.status(401).send("Unauthorized Access Token");
    } else {
      jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
        if (error) {
          response.status(403).send("Invalid Token");
        } else {
          request.email = payload.email;
          next();
        }
      });
    }
  }
};
// User Registration
server_instance.post("/user_registration/", async (request, response) => {
  const { id, firstName, lastName, email, password } = request.body;
  const hashPassword = await bcrypt.hash(password, 10);
  const checkUser = `SELECT * FROM user_detail WHERE email ='${email}'`;
  const dbUser = await dataBase.get(checkUser);
  if (dbUser === undefined) {
    const registerUserQuery = `INSERT INTO user_detail (id, first_name, last_name, email, password) VALUES (
          '${id}','${firstName}','${lastName}','${email}','${password}'
      )`;
    await dataBase.run(registerUserQuery);
    response.status(201).send("User created successfully");
  } else {
    response.status(400).send("User already exist");
  }
});

// User Login
server_instance.post("/user_login/", async (request, response) => {
  const { email, password } = request.body;
  const isUserExistQuery = `SELECT * FROM user_detail WHERE email = '${email}'`;
  const isUserExist = await dataBase.get(isUserExistQuery);
  if (isUserExist === undefined) {
    response.status(400).send("Invalid user not exist");
  } else {
    const isPasswordMatch = await bcrypt.compare(
      password,
      isUserExist.password
    );
    if (isPasswordMatch === true) {
      const payload = { email: email };
      const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
      const tokenDetail = { token: jwtToken, email: email };
      response.status(200).send(tokenDetail);
    } else {
      response.status(400).send("Invalid password");
    }
  }
});
