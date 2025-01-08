const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const app = express();
/*const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');*/
const port = process.env.PORT || 3000;

app.use(express.json());

const uri = "mongodb+srv://7naa:perempuancantik@infosec.v4tpw.mongodb.net/?retryWrites=true&w=majority&appName=InfoSec";
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

/*const swaggerOptions = {
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
let playerPosition = null;*/


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
    const hash = bcrypt.hashSync(password, 15);

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

// User registration
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
});

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