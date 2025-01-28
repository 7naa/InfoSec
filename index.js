const express = require('express');
const app = express();
const port = process.env.PORT || 6000;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const uri = "mongodb+srv://7naa:1234@infosec.v4tpw.mongodb.net/?retryWrites=true&w=majority&appName=InfoSec";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

app.use(express.json());

app.get('/',(req,res) => {
  res.send('hello')
});

//Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

//MongoDB connection setup
async function run() {
  try {
    await client.connect();
    console.log('Connected to MongoDB successfully!');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
  }
}
run().catch(console.dir);