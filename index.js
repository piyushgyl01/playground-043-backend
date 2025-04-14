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

function verifyToken(req, res, next) {
  const token = req.cookies.access_token;

  if (!token) {
    return res
      .status(401)
      .json({ message: "You need to sign in or sign up before continuing." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token.", error: error.message });
  }
}

app.post("/auth/register", async (req, res) => {
  const { username, name, password, email } = req.body;

  if (!username || !name || !password || !email) {
    return res
      .status(400)
      .json({ message: "Please fill in all required fields." });
  }

  try {
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      name,
      password: hashedPassword,
      email,
    });

    await user.save();
    res.status(201).json({ message: "User registered successfully", user });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res
      .status(400)
      .json({ message: "Please fill in all required fields." });
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.cookie("access_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ message: "Logged in successfully", user });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("access_token");
  res.json({ message: "Logged out successfully" });
});

app.post("/articles", verifyToken, async (req, res) => {
  const { title, description, body, tagList } = req.body;

  if (!title || !description || !body) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const id = req.user.id;

  try {
    const newArticle = new Article({
      title,
      description,
      body,
      tagList,
      author: id,
    });

    const savedArticle = await newArticle.save();

    res
      .status(201)
      .json({ message: "Article created successfully", article: savedArticle });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.delete("/articles/:id", verifyToken, async (req, res) => {
  const id = req.user.id;

  try {
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    if (article.author.toString() !== id) {
      return res
        .status(403)
        .json({ message: "Only the author can delete this article" });
    }

    await Article.findByIdAndDelete(req.params.id);

    res
      .status(200)
      .json({ message: "Article deleted successfully", article: article });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.put("/articles/:id", verifyToken, async (req, res) => {
  const id = req.user.id;

  try {
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    if (article.author.toString() !== id) {
      return res
        .status(403)
        .json({ message: "Only the author can edit this article" });
    }

    const updatedArticle = await Article.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );

    res.status(200).json({
      message: "Article updated successfully",
      article: updatedArticle,
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.get("/articles", async (req, res) => {
  try {
    const articles = await Article.find().populate(
      "author",
      "name username image"
    );

    res.status(200).json({ articles });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.get("/articles/:id", async (req, res) => {
  try {
    const article = await Article.findById(req.params.id).populate(
      "author",
      "name username image"
    );

    res.status(200).json({ article });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.put("/articles/:id/favorite", verifyToken, async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    const user = await User.findById(req.user.id);

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const isAlreadyFavorited =
      user.favouriteArticles && user.favouriteArticles.includes(article._id);

    if (isAlreadyFavorited) {
      user.favouriteArticles = user.favouriteArticles.filter(
        (id) => id.toString() !== article._id.toString()
      );
      article.favouritesCount = Math.max(0, article.favouritesCount - 1);
    } else {
      if (!user.favouriteArticles) {
        user.favouriteArticles = [];
      }

      user.favouriteArticles.push(article._id);

      article.favouritesCount = (article.favouritesCount || 0) + 1;
    }

    await user.save();
    await article.save();

    res.status(200).json({
      message: "Favorite toggled",
      article: {
        ...article.toObject(),
        favorited: !isAlreadyFavorited,
      },
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
