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
      return res.status(404).json({ message: "User not found" });
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

app.get("/auth/user", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password -__v");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(user);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.put("/auth/user", verifyToken, async (req, res) => {
  try {
    const id = req.user.id;

    const user = await User.findById(id);

    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }

    const updatedUser = await User.findByIdAndUpdate(id, req.body, {
      new: true,
    });

    res.status(200).json({ message: "User updated", user: updatedUser });
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

app.post("/articles/:id/comments", verifyToken, async (req, res) => {
  try {
    const id = req.user.id;

    const commenter = await User.findById(id);

    if (!commenter) {
      return res.status(404).json({ message: "User not found" });
    }

    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    const { body } = req.body;

    const newComment = new Comment({
      body,
      author: commenter._id,
      article: article._id,
    });

    await newComment.save();

    article.comments.push(newComment._id);
    await article.save();

    res.status(200).json({ message: "Comment added", comment: newComment });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.get("/articles/:id/comments", async (req, res) => {
  try {
    const article = await Article.findById(req.params.id).populate({
      path: "comments",
      populate: {
        path: "author",
        select: "username name image",
      },
    });

    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    res.status(200).json({ comments: article.comments });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.delete(
  "/articles/:id/comments/:commentId",
  verifyToken,
  async (req, res) => {
    try {
      const article = await Article.findById(req.params.id);

      if (!article) {
        return res.status(404).json({ message: "Article not found" });
      }

      const comment = await Comment.findById(req.params.commentId);

      if (!comment) {
        return res.status(404).json({ message: "Comment not found" });
      }

      if (comment.author.toString() !== req.user.id) {
        return res.status(403).json({
          message: "Only the author of the comment can delete the comment",
        });
      }

      article.comments = article.comments.filter(
        (id) => id.toString() !== comment._id.toString()
      );

      await article.save();

      await Comment.findByIdAndDelete(req.params.commentId);

      res
        .status(200)
        .json({ message: "Comment has been successfully deleted", comment });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Internal server error", error: error.message });
    }
  }
);

app.put("/articles/:id/comments/:commentId", verifyToken, async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article) {
      return res.status(404).json({ message: "Article not found" });
    }

    const comment = await Comment.findById(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ message: "Comment not found" });
    }

    if (comment.author.toString() !== req.user.id) {
      return res.status(403).json({
        message: "Only the author of the comment can edit the comment",
      });
    }

    const { body } = req.body;
    if (!body) {
      return res.status(400).json({ message: "Comment body is required" });
    }

    const updatedComment = await Comment.findByIdAndUpdate(
      req.params.commentId,
      { body },
      { new: true }
    );

    res.status(200).json({
      message: "Comment has been successfully edited",
      comment: updatedComment,
    });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.get("/profile/:username", verifyToken, async (req, res) => {
  try {
    const { username } = req.params;

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: "User Not Found" });
    }

    const profile = {
      username: user.username,
      name: user.name,
      bio: user.bio || "",
      image: user.image,
      following: false,
    };

    if (req.user) {
      const currentUser = await User.findById(req.user.id);
      if (currentUser && currentUser.followingUsers) {
        profile.following = currentUser.followingUsers.includes(user._id);
      }
    }

    res.status(200).json({ profile });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.put("/profile/:username/follow", verifyToken, async (req, res) => {
  try {
    const { username } = req.params;

    const currentUser = await User.findById(req.user.id);
    const targetUser = await User.findOne({ username });

    if (!targetUser) {
      return res.status(404).json({ message: "User Not Found" });
    }

    const isFollowing = currentUser.followingUsers.some(
      (id) => id.toString() === targetUser._id.toString()
    );

    if (isFollowing) {
      currentUser.followingUsers = currentUser.followingUsers.filter(
        (id) => id.toString() !== targetUser._id.toString()
      );
    } else {
      currentUser.followingUsers.push(targetUser._id);
    }

    await currentUser.save();

    const profile = {
      username: targetUser.username,
      name: targetUser.name,
      bio: targetUser.bio || "",
      image: targetUser.image,
      following: !isFollowing,
    };

    res.status(200).json({ message: "Toggled follow", profile });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.get("/tags", async (req, res) => {
  try {
    const tags = await Article.find().distinct('tagList').exec();

    res.status(200).json({ tags });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
