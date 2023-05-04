require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const app = express();

app.use(express.json());

const dbURI =
  process.env.DB_URL || "mongodb://localhost:27017/junior-backend-assessment";

mongoose.connect(dbURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

app.post("/api/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "testcoding3000@gmail.com",
        pass: "pogkyvjtzczkgzce",
      },
    });

    const mailOptions = {
      from: "testcoding3000@gmail.com",
      to: email,
      subject: "Email Confirmation",
      text: "Your account has been successfully created!",
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.log(error);
      } else {
        console.log("Email sent: " + info.response);
      }
    });

    res.status(204).send();
  } catch (error) {
    res.status(500).send({ error: "User creation failed" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send({ error: "Invalid password" });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || "SECRET123",
      {
        expiresIn: "1h",
      }
    );
    res.status(200).send({ Token: token });
  } catch (error) {
    res.status(500).send({ error: "Login failed" });
  }
});

app.post("/api/actions/changepassword", async (req, res) => {
  const { old_password, new_password } = req.body;
  const token = req.headers.authorization.split(" ")[1];

  try {
    const decoded = jwt.verify(token, "SECRET_KEY");
    const user = await User.findById(decoded.userId);

    const passwordMatch = await bcrypt.compare(old_password, user.password);
    if (!passwordMatch) {
      return res.status(401).send({ error: "Invalid old password" });
    }

    const hashedNewPassword = await bcrypt.hash(new_password, 10);
    user.password = hashedNewPassword;
    await user.save();
    res.status(200).send({ message: "Password changed successfully" });
  } catch (error) {
    res.status(500).send({ error: "Password change failed" });
  }
});

app.get("/api/profiles", async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "SECRET123");
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(404).send({ error: "User not found" });
    }

    res.status(200).send({ username: user.username, email: user.email });
  } catch (error) {
    res.status(500).send({ error: "Fetching profile failed" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
