const express = require('express');
const { MongoClient, ServerApiVersion } = require('mongodb');
const app = express();
const swaggerUi = require('swagger-ui-express');
const swaggerJsDoc = require('swagger-jsdoc');
const port = process.env.PORT || 3000;

app.use(express.json());

const uri = "mongodb+srv://7naa:perempuancantik@infosecurity.zvukc.mongodb.net/?retryWrites=true&w=majority&appName=InfoSecurity";
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    await client.db("user").command({ ping: 1 });
    console.log("Connected to MongoDB successfully!");
  } catch (err) {
    console.error("Failed to connect to MongoDB:", err);
    process.exit(1); // Exit the app if connection fails
  }
}

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${port} is already in use.`);
  } else {
    console.error(err);
  }
});

//const uri = "mongodb+srv://7naa:perempuancantik@infosecurity.zvukc.mongodb.net/?retryWrites=true&w=majority&appName=InfoSecurity";



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


async function run() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  console.log("You successfully connected to MongoDB!");

  app.use(express.json());
  /*app.listen(port, () => {
    console.log(`Server listening at http://localSecurity:${port}`);
  });*/

  app.get('/', (req, res) => {
    res.send('Welcome to the Security Management System');
  });
}

/**
 * @swagger
 * /user:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user account with a hashed password.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the user.
 *                 example: johndoe
 *               password:
 *                 type: string
 *                 description: The password for the user account.
 *                 example: Password123!
 *               name:
 *                 type: string
 *                 description: The full name of the user.
 *                 example: John Doe
 *               email:
 *                 type: string
 *                 description: The email address of the user.
 *                 example: johndoe@example.com
 *     responses:
 *       200:
 *         description: User successfully registered.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 acknowledged:
 *                   type: boolean
 *                   example: true
 *                 insertedId:
 *                   type: string
 *                   description: The unique ID of the newly created user.
 *                   example: 60b8d295f9d5b90012e3f3e5
 *       400:
 *         description: Bad Request - Missing or invalid data.
 *       500:
 *         description: Internal Server Error - Failed to save user to the database.
 */


app.post('/user', async (req, res) => {
  try {
    const hash = bcrypt.hashSync(req.body.password, 15);

    let result = await client.db("user").collection("userdetail").insertOne({
      username: req.body.username,
      password: hash,
      name: req.body.name,
      email: req.body.email
    });

    res.status(200).send(result); // Send the result with status code 200
  } catch (err) {
    console.error("Error inserting user:", err);
    res.status(500).send({ error: "Internal Server Error" });
  }
});


/**
 * @swagger
 * /login:
 *   post:
 *     summary: User login
 *     description: Authenticates a user with a username and password and returns a JWT token on successful login.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the user.
 *                 example: johndoe
 *               password:
 *                 type: string
 *                 description: The password of the user.
 *                 example: Password123!
 
 */
// User login
app.post('/login', async (req, res) => {
  if (req.body.username != null && req.body.password != null) {
    let result = await client.db("user").collection("userdetail").findOne({
      username: req.body.username
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
      _id: new ObjectId(req.params.id)
    });
    res.send(result);
  }
});


// Delete user account
app.delete('/user/:id', verifyToken, async (req, res) => {
  let result = await client.db("user").collection("userdetail").deleteOne({
    _id: new ObjectId(req.params.id)
  });
  res.send(result);
});

app.post('/buy', async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];
  var decoded = jwt.verify(token, 'deletepulak');
  console.log(decoded);
});

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
    selectedMap = selectedMapName; // Store the selected map globally
    playerPosition = mapData.playerLoc; // Set initial player position
    const room1Message = mapData.map.room1.message;

    res.send(`You choose ${selectedMapName}. Let's start playing!\n\nRoom 1 Message:\n${room1Message}`);
  } else {
    res.status(404).send(`Map "${selectedMapName}" not found.`);
  }
});

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

/*app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});*/





run().catch(console.error);
