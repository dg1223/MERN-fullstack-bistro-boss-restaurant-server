const express = require("express");
const app = express();
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 5000;

//middleware
app.use(cors());
app.use(express.json());

// JWT middleware (to be reused to secure authentication)
const verifyJWT = (req, res, next) => {
  const authorization = req.headers.authorization;
  // console.log("authorization: ", authorization);
  if (!authorization) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized access: !authorization" });
  }

  // bearer token
  const token = authorization.split(" ")[1];

  jwt.verify(token, process.env.ACCES_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ error: true, message: "Unauthorized access: err" });
    }
    // decoded: payload from jwt.sign(user, ...) (user information)
    req.decoded = decoded;
    // needs to be added to ensure that next middleware is called
    next();
  });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@dg1223.za2ri3i.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    const userCollection = client.db("bistroDB").collection("users");
    const menuCollection = client.db("bistroDB").collection("menu");
    const reviewCollection = client.db("bistroDB").collection("reviews");
    const cartCollection = client.db("bistroDB").collection("carts");

    // JWT; not an async operation
    app.post("/jwt", (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCES_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    // Verify admin only after being connected to database
    // Warning: use verifyJWT before using verifyAdmin
    // To be reused to secure admin authorization
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }
      next();
    };

    /**
     * How to secure admin privileges
     * 0. Do not show secure links to those who should not
     *    see the links
     * 1. use JWT: verifyJWT
     * 2. use verifyAdmin middleware
     */

    // users related API
    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const result = await userCollection.find().toArray();
      res.send(result);
    });

    app.post("/users", async (req, res) => {
      const user = req.body;
      // console.log(user);
      // if user is found, skip social login
      const query = { email: user.email };
      const existingUser = await userCollection.findOne(query);
      // console.log("existing user: ", existingUser);
      if (existingUser) {
        return res.send({ message: "User already exists" });
      }

      // if user is new, insert user data into DB
      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    // check if user is an admin
    /**
     * Security layers:
     * First layer: verifyJWT
     * Second layer: check if email is the same
     * Third layer: cehck if admin
     */
    app.get("/users/admin/:email", verifyJWT, async (req, res) => {
      const email = req.params.email; // params is on the line above

      // second layer of security
      if (req.decoded.email !== email) {
        res.send({ admin: false });
      }

      // first layer of security
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const result = { admin: user?.role === "admin" };
      res.send(result);
    });

    // update a user's role to admin
    app.patch("/users/admin/:id", async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          role: "admin",
        },
      };
      const result = await userCollection.updateOne(filter, updateDoc);
      res.send(result);
    });

    // menu related APIs
    app.get("/menu", async (req, res) => {
      const result = await menuCollection.find().toArray();
      res.send(result);
    });

    app.post("/menu", verifyJWT, verifyAdmin, async (req, res) => {
      const newItem = req.body;
      const result = await menuCollection.insertOne(newItem);
      res.send(result);
    });

    // Items that were manually added to the database won't get deleted
    // because their _id are not of ObjectId type.
    // When items are added to MongoDB via API, it automatically adds an
    // _id of type ObjectId to each item.
    app.delete("/menu/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await menuCollection.deleteOne(query);
      res.send(result);
    });

    // reviews related APIs
    app.get("/reviews", async (req, res) => {
      const result = await reviewCollection.find().toArray();
      res.send(result);
    });

    // Cart collection APIs
    app.get("/carts", verifyJWT, async (req, res) => {
      const email = req.query.email;
      // console.log("email: ", email);
      if (!email) {
        res.send([]);
      }

      // if someone is trying to access API using someone
      // else's email, forbid access to API
      const decodedEmail = req.decoded.email;
      // console.log("decoded email: ", decodedEmail);
      if (email !== decodedEmail) {
        return res
          .status(403)
          .send({ error: true, message: "Forbidden access" });
      }

      const query = { email: email };
      const result = await cartCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/carts", async (req, res) => {
      const item = req.body;
      const result = await cartCollection.insertOne(item);
      res.send(result);
    });

    app.delete("/carts/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await cartCollection.deleteOne(query);
      res.send(result);
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Bistro Boss server is running...");
});

app.listen(port, () => {
  console.log(`Bistro Boss server is running on port ${port}`);
});
