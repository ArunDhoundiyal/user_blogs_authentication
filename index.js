const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const sqlite3 = require("sqlite3");
const path = require("path");
const { open } = require("sqlite");

const server_instance = express();
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
      console.log("Server is running on http://localhost:3000");
    });
  } catch (error) {
    console.log(`Database Error: ${error.message}`);
    process.exit(1);
  }
};

initialize_DataBase_and_Server();

// Token Authorization (Middleware Function)
const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
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
  } else {
    response.status(401).send("Authorization header missing");
  }
};

// User Registration
server_instance.post("/user_registration/", async (request, response) => {
  const { firstName, lastName, email, password } = request.body;
  const hashPassword = await bcrypt.hash(password, 10);
  const checkUserQuery = `SELECT * FROM user WHERE email = ?`;
  try {
    const dbUser = await dataBase.get(checkUserQuery, [email]);
    if (dbUser === undefined) {
      const registerUserQuery = `
      INSERT INTO user (first_name, last_name, email, password) 
      VALUES (?, ?, ?, ?)
    `;
      await dataBase.run(registerUserQuery, [
        firstName,
        lastName,
        email,
        hashPassword,
      ]);
      response.status(201).send("User created successfully");
    } else {
      response.status(400).send("User already exists");
    }
  } catch (error) {
    console.error("Error while user registration:", error);
    response.status(500).send("Server Error");
  }
});

// User Login
server_instance.post("/user_login/", async (request, response) => {
  const { email, password } = request.body;

  const isUserExistQuery = `SELECT * FROM user WHERE email = ?`;

  try {
    const isUserExist = await dataBase.get(isUserExistQuery, [email]);

    if (isUserExist === undefined) {
      response.status(400).send("Invalid user does not exist");
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
  } catch (error) {
    console.error("Error login user:", error);
    response.status(500).send("Server Error");
  }
});

// User Create Blog
server_instance.post(
  "/create_blog/",
  authenticateToken,
  async (request, response) => {
    const { blogId, title, content } = request.body;
    const { email } = request;
    const userQuery = `SELECT * FROM user WHERE email = ?`;

    try {
      const checkUserQuery = await dataBase.get(userQuery, [email]);
      const createBlogQuery = `INSERT INTO blogs(blog_id, title, content, user_id) VALUES (?,?,?,?)`;
      const createBlog = dataBase.run(createBlogQuery, [
        blogId,
        title,
        content,
        checkUserQuery.id,
      ]);
      response.status(201).send("Server created a new resource successfully");
    } catch (error) {
      console.error("Error while creating blog:", error);
      response.status(500).send("Server Error");
    }
  }
);

// User Update Blog
server_instance.put(
  "/update_blog/:blogId/",
  authenticateToken,
  async (request, response) => {
    const { blogId } = request.params;
    const checkUserQuery = `SELECT * FROM blogs WHERE blog_id = ?;`;

    try {
      const checkUser = await dataBase.get(checkUserQuery, [blogId]);
      if (!checkUser) {
        response.status(404).send("Blog not found");
      } else {
        const {
          title = checkUser.title,
          content = checkUser.content,
        } = request.body;
        const updateBlogQuery = `UPDATE blogs SET title = ?, content = ? WHERE blog_id = ?`;
        const updateBlog = await dataBase.run(updateBlogQuery, [
          title,
          content,
          blogId,
        ]);
        response.status(200).send("Blog Updated Successfully");
      }
    } catch (error) {
      console.error("Error updating blog:", error);
      response.status(500).send("Server Error");
    }
  }
);

// Get all blogs
server_instance.get("/blogs", authenticateToken, async (request, response) => {
  try {
    const getAllBlogsQuery = `SELECT * FROM blogs`;
    const blogs = await dataBase.all(getAllBlogsQuery);

    if (blogs.length === 0) {
      response.status(404).send("No blogs found");
    } else {
      response.status(200).json(blogs);
    }
  } catch (error) {
    console.error("Error retrieving blogs:", error);
    response.status(500).send("Server Error");
  }
});

// Get blog
server_instance.get(
  "/blog/:blogId/",
  authenticateToken,
  async (request, response) => {
    const { blogId } = request.params;
    try {
      const getDataQuery = `SELECT * FROM blogs WHERE blog_id = ?;`;
      const getData = await dataBase.get(getDataQuery, [blogId]);
      if (getData.length === 0) {
        response.status(404).send("No blogs found");
      } else {
        response.status(200).send(getData);
      }
    } catch (error) {
      console.error("Error retrieving blogs:", error);
      response.status(500).send("Server Error");
    }
  }
);

// Delete blog
server_instance.delete(
  "/delete_blog/:blogId/",
  authenticateToken,
  async (request, response) => {
    const { blogId } = request.params;
    const getDataQuery = `SELECT * FROM blogs WHERE blog_id =?;`;

    try {
      const dataQuery = await dataBase.get(getDataQuery, [blogId]);
      if (!dataQuery) {
        response.status(404).send("Blog not found");
      } else {
        const deleteBlogQuery = `DELETE FROM blogs WHERE blog_id = ?;`;
        await dataBase.run(deleteBlogQuery, [blogId]);
        response.status(200).send("Blog deleted successfully");
      }
    } catch (error) {
      console.error("Error deleting blog:", error);
      response.status(500).send("Server Error");
    }
  }
);

// Create Comment
server_instance.post(
  "/create_comment/:blogId/",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    const { blogId } = request.params;
    const { commentId, userComment } = request.body;
    const emailExistQuery = `SELECT * FROM user WHERE email = ?`;
    try {
      const emailExist = await dataBase.get(emailExistQuery, [email]);
      const postCommentQuery = `INSERT INTO comment(comment_id,blog_id,user_id, user_comment) VALUES(?,?,?,?);`;
      await dataBase.run(postCommentQuery, [
        commentId,
        blogId,
        emailExist.id,
        userComment,
      ]);
      response.status(201).send("Server created new comment successfully");
    } catch (error) {
      console.error("Error while creating comment:", error);
      response.status(500).send("Server Error");
    }
  }
);

// Get all comments
server_instance.get(
  "/comments/:blogId/",
  authenticateToken,
  async (request, response) => {
    const { blogId } = request.params;

    try {
      if (!blogId) {
        response.status(404).send("Invalid blog id or blog not found");
      } else {
        const getAllCommentsQuery = `SELECT * FROM comment INNER JOIN user ON comment.user_id = user.id WHERE comment.blog_id = ?;`;
        const getAllComments = await dataBase.all(getAllCommentsQuery, [
          blogId,
        ]);
        response.status(200).send(getAllComments);
      }
    } catch (error) {
      console.error("Error while getting comments:", error);
      response.status(500).send("Server Error");
    }
  }
);
