const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const { connectToDB } = require("./db/db.connect");
const User = require("./models/user.model");
const Article = require("./models/article.model");
const Comment = require("./models/comment.model");
const Tag = require("./models/tag.model");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());
app.use(cors({ credentials: true, origin: "http://localhost:5173" }));
app.use(cookieParser());

connectToDB();

app.get("/", (req, res) => {
  res.json("Blogify! Knowledge creation at best");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
