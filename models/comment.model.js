const mongoose = require("mongoose");

const commentSchema = new mongoose.Schema(
  {
    body: {
      type: String,
      required: true,
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "pg43User",
    },
    article: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "pg43Article",
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("pg43Comment", commentSchema);
