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
app.use(
  cors({
    origin: ["https://playground-043.vercel.app", "http://localhost:5173"],
    credentials: true,
    optionsSuccessStatus: 200,
  })
);
app.use(cookieParser());

connectToDB();

app.get("/", (req, res) => {
  res.json("Blogify! Knowledge creation at best");
});

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

function verifyToken(req, res, next) {
  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res
      .status(403)
      .json({ message: "You need to sign in before continuing" });
  }

  try {
    const decoded = jwt.verify(accessToken, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res
      .status(403)
      .json({ message: "Invalid token", error: error.message });
  }
}

// Auth helper functions
function generateTokens(user) {
  const payload = {
    id: user._id,
    username: user.username || user.email,
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });
  const refreshToken = jwt.sign({ id: user._id }, REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  return { accessToken, refreshToken };
}

function setAuthCookies(res, accessToken, refreshToken) {
  res.cookie("access_token", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 15 * 60 * 1000,
  });

  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/auth/refresh-token",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearAuthCookies(res) {
  res.cookie("access_token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 0,
  });

  res.cookie("refresh_token", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/auth/refresh-token",
    maxAge: 0,
  });
}

app.post("/auth/register", async (req, res) => {
  const { username, name, email, password } = req.body;

  if (!username || !name || !email || !password) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields" });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (email && !emailRegex.test(email)) {
    return res
      .status(400)
      .json({ message: "Please provide a valid email address" });
  }

  if (password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters long" });
  }

  try {
    const existingUser = await User.findOne({
      $or: [{ username }, { email: email || null }],
    });

    if (existingUser) {
      return res.status(400).json({
        message:
          existingUser.username === username
            ? "Username already exists"
            : "Email already exists",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      name,
      email: email || null,
      password: hashedPassword,
    });

    await newUser.save();

    const { accessToken, refreshToken } = generateTokens(newUser);

    setAuthCookies(res, accessToken, refreshToken);

    const userResponse = {
      _id: newUser._id,
      username: newUser.username,
      name: newUser.name,
      email: newUser.email,
    };

    res
      .status(201)
      .json({ message: "User registered successfully", user: userResponse });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error registering user", error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Please provide all required fields" });
  }

  try {
    const user = await User.findOne({
      $or: [{ username }, { email: username }],
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.password) {
      return res.status(401).json({
        message:
          "This account uses social login. Please sign in with the appropriate provider.",
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const { accessToken, refreshToken } = generateTokens(user);

    setAuthCookies(res, accessToken, refreshToken);

    const userResponse = {
      _id: user._id,
      username: user.username,
      name: user.name,
      email: user.email,
    };

    res
      .status(200)
      .json({ message: "Logged in successfully", user: userResponse });
  } catch (error) {
    console.log(error);
    res
      .status(500)
      .json({ message: "Error logging in user", error: error.message });
  }
});

app.post("/auth/logout", (req, res) => {
  clearAuthCookies(res);
  res.status(200).json({ message: "Logged out successfully" });
});

app.post("/auth/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token provided" });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const tokens = generateTokens(user);
    setAuthCookies(res, tokens.accessToken, tokens.refreshToken);

    res.status(200).json({ message: "Token refreshed successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Invalid refresh token", error: error.message });
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
    const tags = await Article.find().distinct("tagList").exec();

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
