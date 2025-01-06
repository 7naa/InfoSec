const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(express.json());

// MongoDB setup
const uri = "mongodb+srv://7naa:perempuancantik@infosecurity.zvukc.mongodb.net/";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Swagger setup
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Welcome to Our Game",
      version: "1.0.0",
      description: "This is the best game in the world",
    },
  },
  apis: ["./index.js"],
};
const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// JWT middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, "hurufasepuluhkali", (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.identity = decoded; // Attach decoded user data to the request
    next();
  });
}

// Role verification middleware
function verifyAdmin(req, res, next) {
  if (req.identity.role !== 'admin') {
    return res.status(403).send('Forbidden: Admins only.');
  }
  next();
}

// Initialize the first admin
/**
 * @swagger
 * /initialize-admin:
 *   post:
 *     summary: Initialize the first admin
 *     description: Create the first admin (one-time use only).
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 example: superadmin
 *               password:
 *                 type: string
 *                 example: StrongPass123!
 *     responses:
 *       200:
 *         description: Admin initialized successfully.
 *       403:
 *         description: Initialization not allowed if admin exists.
 *       500:
 *         description: Internal server error.
 */
app.post('/initialize-admin', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing admin username or password");
  }

  if (password.length < 8) {
    return res.status(400).send("Password must be at least 8 characters long.");
  }

  try {
    const existingAdmin = await client.db("user").collection("admin").findOne({});
    if (existingAdmin) {
      return res.status(403).send("An admin already exists. Initialization not allowed.");
    }

    const hash = bcrypt.hashSync(password, 15);
    const result = await client.db("user").collection("admin").insertOne({ username, password: hash });

    res.send({ message: "Admin initialized successfully", adminId: result.insertedId });
  } catch (error) {
    console.error("Error during admin initialization:", error);
    res.status(500).send("Internal Server Error");
  }
});

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
    const existingAdmin = await client.db("user").collection("admin").findOne({ username });
    if (existingAdmin) {
      return res.status(400).send("Admin username already exists.");
    }

    const hash = bcrypt.hashSync(password, 15);
    const result = await client.db("user").collection("admin").insertOne({ username, password: hash });

    res.send({ message: "Admin registered successfully", adminId: result.insertedId });
  } catch (error) {
    console.error("Error during admin registration:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send("Missing admin username or password");
  }

  try {
    const admin = await client.db("user").collection("admin").findOne({ username });

    if (!admin) {
      return res.status(401).send("Admin username not found");
    }

    const isPasswordValid = bcrypt.compareSync(password, admin.password);
    if (!isPasswordValid) {
      return res.status(401).send("Wrong password! Try again");
    }

    const token = jwt.sign(
      { _id: admin._id, username: admin.username, role: "admin" },
      'hurufasepuluhkali'
    );

    res.send({ _id: admin._id, token, role: "admin" });
  } catch (error) {
    console.error("Error during admin login:", error);
    res.status(500).send("Internal Server Error");
  }
});

// User endpoints omitted for brevity...
// Add user-related routes and other game-related logic here...

// Connect to MongoDB and start the server
async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB successfully!");
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error);
    process.exit(1); // Exit if MongoDB connection fails
  }
}
run();
