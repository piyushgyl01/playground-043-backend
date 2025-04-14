const mongoose = require("mongoose");

const tagSchema = new mongoose.Schema(
  {
    tagName: {
      type: String,
      required: true,
      unique: true,
    },
    articles: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "pg43Article",
      },
    ],
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("pg43Tag", tagSchema);
