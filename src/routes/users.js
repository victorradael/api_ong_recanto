const express = require("express");

const usersController = require("../controllers/UsersController");

const router = express.Router();

router.post("/signUp", usersController.registerUser);

router.post("/signIn", usersController.userLogin);

module.exports = router;
