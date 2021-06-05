const express = require("express");

const angelsController = require("../controllers/AngelsController");
const login = require("../middleware/login");

const router = express.Router();

router.post("/register", login, angelsController.registerAngel);

module.exports = router;
