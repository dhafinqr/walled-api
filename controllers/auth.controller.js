const db = require("../models");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = db.user;

exports.register = async (req, res) => {
  try {
    const { fullName, email, password, avatar } = req.body;

    const userExists = await User.findOne({ where: { email } });
    if (userExists) {
      return res.status(400).send({ message: "Email already exists!" });
    }

    const hashedPassword = await bcrypt.hash(password, 8);

    const user = await User.create({
      fullName,
      email,
      password: hashedPassword,
      avatar,
      balance: 0, // default balance
    });

    const userResponse = {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      avatar: user.avatar,
      balance: user.balance,
    };

    res
      .status(201)
      .send({ message: "User registered successfully!", user: userResponse });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user) return res.status(404).send({ message: "User not found!" });

    const passwordIsValid = await bcrypt.compare(password, user.password);
    if (!passwordIsValid)
      return res.status(401).send({ message: "Invalid Password!" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: 86400, // 24 hours
    });

    const userResponse = {
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      avatar: user.avatar,
      balance: user.balance,
    };

    res.status(200).send({ user: userResponse, accessToken: token });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};

exports.me = async (req, res) => {
  try {
    const user = await User.findByPk(req.userId); // Mengambil data user berdasarkan userId dari token

    if (!user) {
      return res.status(404).send({ message: "User not found!" });
    }

    res.status(200).send({
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      avatar: user.avatar,
      balance: user.balance,
    });
  } catch (err) {
    res.status(500).send({ message: err.message });
  }
};
