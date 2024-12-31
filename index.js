const express = require('express');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const app = express();
const port = process.env.PORT || 3000;

// MongoDB connection URI
const uri = "mongodb+srv://7naa:perempuancantik@infosecurity.zvukc.mongodb.net/";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let selectedMap = null;
let playerPosition = null;

// Middleware to parse JSON request bodies
app.use(express.json());

// Function to verify JWT token
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, "manabolehbagi", (err, decoded) => {
    if (err) return res.sendStatus(403);
    req.identity = decoded;
    next();
  });
}

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("You successfully connected to MongoDB!");

    // Define routes inside the `run` function to ensure MongoDB is connected
    app.get('/', (req, res) => {
      res.send('Welcome to the Security Management System');
    });

    // User registration
    app.post('/user', async (req, res) => {
      const hash = bcrypt.hashSync(req.body.password, 10);

      let result = await client.db("user").collection("userdetail").insertOne({
        username: req.body.username,
        password: hash,
        name: req.body.name,
        email: req.body.email,
      });
      res.send(result);
    });

    // User login
    app.post('/login', async (req, res) => {
      if (req.body.username != null && req.body.password != null) {
        let result = await client.db("user").collection("userdetail").findOne({
          username: req.body.username,
        });

        if (result) {
          if (bcrypt.compareSync(req.body.password, result.password) == true) {
            var token = jwt.sign(
              { _id: result._id, username: result.username, name: result.name },
              'manabolehbagi'
            );
            res.send(token);
          } else {
            res.status(401).send('WRONG PASSWORD! TRY AGAIN');
          }
        } else {
          res.status(401).send("USERNAME NOT FOUND");
        }
      } else {
        res.status(400).send("MISSING USERNAME OR PASSWORD");
      }
    });

    // Get user profile
    app.get('/user/:id', verifyToken, async (req, res) => {
      if (req.identity._id != req.params.id) {
        res.status(401).send('Unauthorized Access');
      } else {
        let result = await client.db("user").collection("userdetail").findOne({
          _id: new ObjectId(req.params.id),
        });
        res.send(result);
      }
    });

    // Delete user account
    app.delete('/user/:id', verifyToken, async (req, res) => {
      let result = await client.db("user").collection("userdetail").deleteOne({
        _id: new ObjectId(req.params.id),
      });
      res.send(result);
    });

    // Map selection
    app.post('/choose-map', (req, res) => {
      const selectedMapName = req.body.selectedMap;

      function mapJsonPathExists(mapPath) {
        try {
          fs.accessSync(mapPath, fs.constants.F_OK);
          return true;
        } catch (err) {
          return false;
        }
      }

      const mapJsonPath = `./${selectedMapName}.json`;

      if (mapJsonPathExists(mapJsonPath)) {
        const mapData = require(mapJsonPath);
        selectedMap = selectedMapName;
        playerPosition = mapData.playerLoc; // Set initial player position
        const room1Message = mapData.map.room1.message;

        res.send(`You choose ${selectedMapName}. Let's start playing!\n\nRoom 1 Message:\n${room1Message}`);
      } else {
        res.status(404).send(`Map "${selectedMapName}" not found.`);
      }
    });

    // Movement in the map
    app.patch('/move', (req, res) => {
      const direction = req.body.direction;

      if (!selectedMap) {
        res.status(400).send("No map selected.");
        return;
      }

      const mapData = require(`./${selectedMap}.json`);
      const currentRoom = mapData.map[playerPosition];

      const nextRoom = currentRoom[direction];
      if (!nextRoom) {
        res.status(400).send(`Invalid direction: ${direction}`);
        return;
      }

      const nextRoomMessage = mapData.map[nextRoom].message;
      playerPosition = nextRoom;

      res.send(`You moved ${direction}. ${nextRoomMessage}`);
    });

    // Start the server after all routes are defined
    app.listen(port, () => {
      console.log(`Example app listening on port ${port}`);
    });
  } catch (err) {
    console.error("Error starting the application:", err);
  }
}

run();
