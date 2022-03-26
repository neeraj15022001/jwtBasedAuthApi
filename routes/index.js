const express = require("express");
const router = express.Router();
const mainController = require("../controllers/mainController");
//GET
router.get("/", mainController.verifyJWT, mainController.root);
router.post("/login", mainController.login);
router.post("/token", mainController.token);
router.delete("/logout", mainController.logout);
module.exports = router;