const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const app = express();
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');
const port = process.env.PORT || 3000;

app.use(express.json());

const uri = "mongodb+srv://7naa:1234@infosec.v4tpw.mongodb.net/?retryWrites=true&w=majority&appName=InfoSec";
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${port} is already in use.`);
  } else {
    console.error(err);
  }
});

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Welcome to Our Game",
      version: "1.0.0",
      description: "This is the best game in the world",
    },
  },
  apis: ["./index.js"], // Path to your API documentation in the code
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));
let selectedMap = null;
let playerPosition = null;


// Function to verify JWT token
function verifyToken(req, res, next) { 

  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "manabolehbagi", (err, decoded) => {
    console.log(err);

    if (err) return res.sendStatus(403);

    req.identity = decoded;

    next();
  });
}

// Middleware to verify admin role
function verifyAdmin(req, res, next) {
  if (req.identity.role !== 'admin') {
    return res.status(403).send('Forbidden: Admins only.');
  }
  next();
}

// Initialize the first admin (one-time use)
app.post('/initialize-admin', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing admin username or password");
  }

  if (password.length < 8) {
    return res.status(400).send("Password must be at least 8 characters long.");
  }

  try {
    // Check if any admin already exists
    const existingAdmin = await client.db("game").collection("admin").findOne({});
    if (existingAdmin) {
      return res.status(403).send("An admin already exists. Initialization is not allowed.");
    }

    // Hash the password
    const hash = bcrypt.hashSync(password, 10);

    // Insert the new admin
    const result = await client.db("game").collection("admin").insertOne({
      username,
      password: hash
    });

    res.send({ message: "Admin initialized successfully", adminId: result.insertedId });
  } catch (error) {
    console.error("Error during admin initialization:", error);
    res.status(500).send("Internal Server Error");
  }
});

/**
 * @swagger
 * /admin/register:
 *   post:
 *     summary: Register a new admin
 *     description: Allows authorized users to register a new admin by providing a unique username and a secure password.
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       description: Admin registration details.
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The admin's unique username.
 *                 example: admin123
 *               password:
 *                 type: string
 *                 description: A secure password for the admin (at least 8 characters long).
 *                 example: P@ssw0rd!
 *             required:
 *               - username
 *               - password
 *     responses:
 *       200:
 *         description: Admin registered successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Admin registered successfully
 *                 adminId:
 *                   type: string
 *                   description: The unique ID of the newly created admin.
 *                   example: 64b67e59fc13ae1c2400003c
 *       400:
 *         description: Bad request due to missing or invalid inputs.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     missing_fields:
 *                       summary: Missing fields
 *                       value: Missing admin username or password
 *                     short_password:
 *                       summary: Password too short
 *                       value: Password must be at least 8 characters long.
 *                     username_exists:
 *                       summary: Username exists
 *                       value: Admin username already exists.
 *       500:
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 *     security:
 *       - bearerAuth: []
 */

// Admin registration
app.post('/admin/register', verifyToken, verifyAdmin, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing admin username or password");
  }

  if (password.length < 8) {
    return res.status(400).send("Password must be at least 8 characters long.");
  }

  try {
    const existingAdmin = await client.db("game").collection("admin").findOne({ username });
    if (existingAdmin) {
      return res.status(400).send("Admin username already exists.");
    }

    const hash = bcrypt.hashSync(password, 15);

    const result = await client.db("game").collection("admin").insertOne({
      username,
      password: hash
    });

    res.send({ message: "Admin registered successfully", adminId: result.insertedId });
  } catch (error) {
    console.error("Error during admin registration:", error);
    res.status(500).send("Internal Server Error");
  }
});

/**
 * @swagger
 * /admin/login:
 *   post:
 *     summary: Admin login
 *     description: Allows an admin to log in by providing valid credentials (username and password).
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       description: Admin login credentials.
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: Admin's username.
 *                 example: admin123
 *               password:
 *                 type: string
 *                 description: Admin's password.
 *                 example: P@ssw0rd!
 *             required:
 *               - username
 *               - password
 *     responses:
 *       200:
 *         description: Login successful, returns admin details and JWT token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   description: The unique ID of the admin.
 *                   example: 64b67e59fc13ae1c2400003c
 *                 token:
 *                   type: string
 *                   description: JWT token for authentication.
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *                 role:
 *                   type: string
 *                   description: Role of the user.
 *                   example: admin
 *       400:
 *         description: Bad request due to missing credentials.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Missing admin username or password
 *       401:
 *         description: Unauthorized access due to invalid username or password.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   examples:
 *                     username_not_found:
 *                       summary: Username not found
 *                       value: Admin username not found
 *                     wrong_password:
 *                       summary: Wrong password
 *                       value: Wrong password! Try again
 *       500:
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 */

// Admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing admin username or password");
  }

  try {
    const admin = await client.db("game").collection("admin").findOne({ username });

    if (!admin) {
      return res.status(401).send("Admin username not found");
    }

    const isPasswordValid = bcrypt.compareSync(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).send("Wrong password! Try again");
    }

    const token = jwt.sign(
      { _id: admin._id, username: admin.username, role: "admin" },
      'manabolehbagi'
    );

    res.send({ _id: admin._id, token, role: "admin" });
  } catch (error) {
    console.error("Error during admin login:", error);
    res.status(500).send("Internal Server Error");
  }
});

/**
 * @swagger
 * /admin/users:
 *   get:
 *     summary: Retrieve all users
 *     description: Allows an admin to fetch a list of all users in the database. This endpoint requires admin privileges.
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully retrieved all users.
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   _id:
 *                     type: string
 *                     description: The unique ID of the user.
 *                     example: 64b67e59fc13ae1c2400003c
 *                   name:
 *                     type: string
 *                     description: The name of the user.
 *                     example: John Doe
 *                   email:
 *                     type: string
 *                     description: The email of the user.
 *                     example: johndoe@example.com
 *                   role:
 *                     type: string
 *                     description: The role of the user.
 *                     example: user
 *       401:
 *         description: Unauthorized access due to invalid or missing token, or insufficient permissions.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized Access
 *       500:
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 */

// Get all user profiles (Admin only)
app.get('/admin/users', verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await client.db("game").collection("userdetail").find({}).toArray();
    res.send(users);
  } catch (error) {
    console.error("Error fetching all users:", error);
    res.status(500).send("Internal Server Error");
  }
});

/**
 * @swagger
 * /admin/user/{id}:
 *   delete:
 *     summary: Delete a user by ID
 *     description: Allows an admin to delete a user by their unique ID. This action requires admin privileges.
 *     tags:
 *       - Admin
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the user to be deleted.
 *         schema:
 *           type: string
 *           example: 64b67e59fc13ae1c2400003c
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully deleted the user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: User deleted successfully
 *       404:
 *         description: User not found.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       401:
 *         description: Unauthorized access due to invalid or missing token, or insufficient permissions.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized Access
 *       500:
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 */

// Delete user profile (Admin only)
app.delete('/admin/user/:id', verifyToken, verifyAdmin, async (req, res) => {
  const userId = req.params.id;

  try {
    const result = await client.db("game").collection("userdetail").deleteOne({ _id: new ObjectId(userId) });

    if (result.deletedCount === 0) {
      return res.status(404).send("User not found");
    }

    res.send("User deleted successfully");
  } catch (error) {
    console.error("Error deleting user profile:", error);
    res.status(500).send("Internal Server Error");
  }
});

/*User registration
app.post('/user', async (req, res) => {
  const { username, password, name, email } = req.body;

  if (!username || !password || !name || !email) {
    return res.status(400).send("All fields are required");
  }

  if (password.length < 8) {
    return res.status(400).send("Password must be at least 8 characters long.");
  }

  try {
    const existingUser = await client.db("game").collection("userdetail").findOne({ username });
    if (existingUser) {
      return res.status(400).send("Username already exists.");
    }

    const hash = bcrypt.hashSync(password, 15);

    const result = await client.db("game").collection("userdetail").insertOne({
      username,
      password: hash,
      name,
      email
    });
    res.send(result);
  } catch (error) {
    console.error("Error during user registration:", error);
    res.status(500).send("Internal Server Error");
  }
});*/

/**
 * @swagger
 * /registerUser:
 *   post:
 *     summary: Register a new user
 *     description: Register a new user with all required details. Ensures username uniqueness and validates password policy.
 *     tags:
 *       - User
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: Unique username for the user.
 *               password:
 *                 type: string
 *                 description: Password for the user (minimum 8 characters).
 *               name:
 *                 type: string
 *                 description: Full name of the user.
 *               email:
 *                 type: string
 *                 format: email
 *                 description: Email address of the user.
 *               phoneNumber:
 *                 type: string
 *                 description: Phone number of the user.
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '201':
 *         description: User registered successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message.
 *                 userId:
 *                   type: string
 *                   description: ID of the newly registered user.
 *       '400':
 *         description: Bad request due to missing or invalid fields.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message.
 *       '500':
 *         description: Internal Server Error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Generic error message.
 *                 details:
 *                   type: string
 *                   description: Specific error details for debugging.
 */

app.post('/registerUser', async (req, res) => {
  const { username, password, name, email, phoneNumber } = req.body;

  // Check for missing fields
  if (!username || !password || !name || !email || !phoneNumber) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Validate password length
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters long." });
  }

  try {
    // Check database connection
    if (!client.isConnected()) {
      console.log("Database client not connected. Attempting to connect...");
      await client.connect();
      console.log("Database connection established.");
    }

    // Check if the username already exists
    console.log(`Checking if username "${username}" already exists...`);
    const existingUser = await client.db("game").collection("userdetail").findOne({ username });
    if (existingUser) {
      console.log("Username already exists:", existingUser);
      return res.status(400).json({ error: "Username already exists." });
    }

    // Hash the password for security
    console.log("Hashing password...");
    const hash = bcrypt.hashSync(password, 10);
    console.log("Password hashed successfully.");

    // Insert the user into the database
    console.log("Inserting user into the database...");
    const result = await client.db("game").collection("userdetail").insertOne({
      username,
      password: hash,
      name,
      email,
      phoneNumber,
    });

    console.log("User inserted successfully:", result.insertedId);

    // Respond with success
    res.status(201).json({
      message: "User registered successfully",
      userId: result.insertedId,
    });
  } catch (error) {
    console.error("Error during user registration:", error.message, error.stack);
    res.status(500).json({
      error: "Internal Server Error",
      details: error.message,
    });
  }
});


/**
 * @swagger
 * /login:
 *   post:
 *     summary: User login
 *     description: Authenticates a user by validating the provided username and password. Returns a JWT token upon successful login.
 *     tags:
 *       - User
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: johndoe
 *               password:
 *                 type: string
 *                 example: mysecurepassword
 *             required:
 *               - username
 *               - password
 *     responses:
 *       200:
 *         description: Successfully logged in and a JWT token is returned.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   example: 64b67e59fc13ae1c2400003c
 *                 token:
 *                   type: string
 *                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NWIxYjY2MzNkZDZkNzEyMDg2MzNlZDMyMiIsIm5hbWUiOiJKb2huIERvZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNjYzMjE5OTYzLCJleHBpcmVkX3N0YWNrYXRhdXNiLmdodGN6dS5UAAc.5ew6pkURxgf80KwBdZI6uOSb9Eq_fYr-9sgWwr4QdTw
 *                 role:
 *                   type: string
 *                   example: user
 *       400:
 *         description: Missing username or password.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Missing username or password
 *       401:
 *         description: Unauthorized due to invalid username or password.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Wrong password! Try again
 *       500:
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 */
// User login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing username or password");
  }

  try {
    const user = await client.db("game").collection("userdetail").findOne({ username });

    if (!user) {
      return res.status(401).send("Username not found");
    }

    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send("Wrong password! Try again");
    }

    const token = jwt.sign(
      { _id: user._id, username: user.username, name: user.name, role: "user" },
      'manabolehbagi'
    );

    res.send({ _id: user._id, token, role: "user" });
  } catch (error) {
    console.error("Error during user login:", error);
    res.status(500).send("Internal Server Error");
  }
});

/**
 * @swagger
 * /user/{id}:
 *   get:
 *     summary: Get user profile by ID
 *     description: Retrieves the profile of the user based on their ID. Only authorized users (matching the ID in the token) can access their own profile.
 *     tags:
 *       - User
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The unique identifier of the user whose profile is to be fetched.
 *         schema:
 *           type: string
 *           example: 64b67e59fc13ae1c2400003c
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successfully fetched the user profile.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                   example: 64b67e59fc13ae1c2400003c
 *                 username:
 *                   type: string
 *                   example: johndoe
 *                 name:
 *                   type: string
 *                   example: John Doe
 *                 email:
 *                   type: string
 *                   example: johndoe@example.com
 *       401:
 *         description: Unauthorized access if the token is invalid or the user does not match the requested ID.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Unauthorized access
 *       404:
 *         description: User not found if no user with the provided ID exists.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found
 *       500:
 *         description: Internal server error if something goes wrong with the database or server.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 * 
 * /buy:
 *   post:
 *     summary: Buy operation
 *     description: A POST endpoint for initiating a buy operation. Requires the user to send a valid authorization token in the header.
 *     tags:
 *       - Purchase
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Successful buy operation. Returns user details after successful verification of the token.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Buy operation successfully initiated.
 *       400:
 *         description: Bad Request if the token is not provided in the Authorization header.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Authorization token is missing
 *       401:
 *         description: Unauthorized if the token is invalid.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid token
 *       500:
 *         description: Internal server error if something goes wrong during the buy operation or token verification.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Internal Server Error
 */

// Get user profile
app.get('/user/:id', verifyToken, async (req, res) => {
  if (req.identity._id != req.params.id) {
    return res.status(401).send('Unauthorized access');
  }

  let result = await client.db("game").collection("userdetail").findOne({
    _id: new ObjectId(req.params.id)
  });
  res.send(result);
});

app.post('/buy', async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  var decoded = jwt.verify(token, 'manabolehbagi');
  console.log(decoded);
});
const fs = require('fs');
const path = require('path');

/**
 * @swagger
 * /choose-map:
 *   post:
 *     summary: Choose a map to play
 *     description: Authenticated route to select a map for the game. The map must exist as a `.json` file in the server directory.
 *     tags:
 *       - Map Selection
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               selectedMap:
 *                 type: string
 *                 description: The name of the map to select (without the `.json` extension).
 *                 example: map1
 *     responses:
 *       200:
 *         description: Map successfully selected and game initiated.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "You chose map1. Let's start playing!\n\nRoom 1 Message:\nWelcome to Room 1!"
 *       404:
 *         description: The specified map file does not exist.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Map \"map1\" not found."
 *       500:
 *         description: Internal server error if there is an issue reading or parsing the map file.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Error reading the map file."
 */

// Choose map - Authenticated route
app.post('/choose-map', verifyToken, (req, res) => {
  const selectedMapName = req.body.selectedMap;
  const mapJsonPath = path.join(__dirname, `${selectedMapName}.json`);

  // Check if the map file exists
  if (fs.existsSync(mapJsonPath)) {
    try {
      const mapData = JSON.parse(fs.readFileSync(mapJsonPath, 'utf-8')); // Read and parse the JSON file
      req.identity.selectedMap = selectedMapName;
      req.identity.playerPosition = mapData.playerLoc;

      const room1Message = mapData.map.room1.message;
      res.send(`You chose ${selectedMapName}. Let's start playing!\n\nRoom 1 Message:\n${room1Message}`);
    } catch (error) {
      res.status(500).send('Error reading the map file.');
    }
  } else {
    res.status(404).send(`Map "${selectedMapName}" not found.`);
  }
});

/**
 * @swagger
 * /move:
 *   patch:
 *     summary: Move the player to a different room in the selected map.
 *     description: Authenticated route that allows the player to move in a specified direction in the currently selected map.
 *     tags:
 *       - Map Movement
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               direction:
 *                 type: string
 *                 description: The direction in which the player wants to move (e.g., "north", "south", "east", "west").
 *                 example: north
 *     responses:
 *       200:
 *         description: The player successfully moved to a new room.
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 *               example: "You moved north. Welcome to the next room!"
 *       400:
 *         description: Bad request due to an invalid direction, missing map selection, or invalid player position.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Invalid direction: north"
 *       404:
 *         description: The selected map file was not found on the server.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Map \"map1\" not found."
 *       500:
 *         description: Internal server error due to issues reading or parsing the map file.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Error reading or parsing the map file."
 */

// Move - Authenticated route
app.patch('/move', verifyToken, (req, res) => {
  const direction = req.body.direction;

  if (!req.identity.selectedMap) {
    res.status(400).send("No map selected.");
    return;
  }

  const selectedMapName = req.identity.selectedMap;
  const mapJsonPath = path.join(__dirname, `${selectedMapName}.json`);

  if (!fs.existsSync(mapJsonPath)) {
    res.status(404).send(`Map "${selectedMapName}" not found.`);
    return;
  }

  try {
    const mapData = JSON.parse(fs.readFileSync(mapJsonPath, 'utf-8'));
    const playerPosition = req.identity.playerPosition;
    const currentRoom = mapData.map[playerPosition];

    if (!currentRoom) {
      res.status(400).send("Invalid player position.");
      return;
    }

    const nextRoom = currentRoom[direction];
    if (!nextRoom) {
      res.status(400).send(`Invalid direction: ${direction}`);
      return;
    }

    const nextRoomMessage = mapData.map[nextRoom].message;
    req.identity.playerPosition = nextRoom; // Update player position

    res.send(`You moved ${direction}. ${nextRoomMessage}`);
  } catch (error) {
    res.status(500).send('Error reading or parsing the map file.');
  }
});

async function run() {
  try {
    await client.connect();
    await client.db("game").command({ ping: 1 });
    await client.db("user").command({ ping: 1 });
    console.log("Connected to MongoDB successfully!");
  } catch (err) {
    console.error("Failed to connect to MongoDB:", err);
    process.exit(1); // Exit the app if connection fails
  }
}

/* MongoDB connection setup
async function run() {
  try {
    await client.connect();
    console.log('Connected to MongoDB successfully!');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
  }
}*/
run().catch(console.dir);

/*run().catch(console.error);*/
