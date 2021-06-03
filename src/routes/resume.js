const express = require("express");

const resumeController = require("../controllers/ResumeController");
const login = require("../middleware/login");

const router = express.Router();

router.get("/radael", login, resumeController.showResume);

module.exports = router;
