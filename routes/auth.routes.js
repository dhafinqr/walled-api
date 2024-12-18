const express = require("express");
const router = express.Router();
const authController = require("../controllers/auth.controller");
const { verifyToken } = require("../middleware/authJwt");

router.post("/register", authController.register);
router.post("/login", authController.login);
router.get("/me", verifyToken, authController.me);

module.exports = router;
