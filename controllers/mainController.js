const User = require('../models/User');
const jwt = require("jsonwebtoken");
let refreshTokens = [];
module.exports.root = (req, res) => {
    return res.json("Hit Root!!")
}
module.exports.login = (req, res) => {
    const user = {
        email: req.body.email,
        password: req.body.password
    }
    const accessToken = generateToken(user, "NeerajJWT", {expiresIn: '30s'});
    const refreshToken = generateToken(user, "NeerajRefreshJWT");
    refreshTokens.push(refreshToken);

    return res.json({accessToken: accessToken, refreshToken: refreshToken});
}

module.exports.token = (req, res) => {
    const refreshToken = req.body.token;
    if(refreshToken == null) return res.sendStatus(401);
    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, "NeerajRefreshJWT", (err, user) => {
        if(err) return res.sendStatus(403);
        const newTokenUser = {
            email: user.email,
            password: user.password
        }
        const accessToken = generateToken(newTokenUser, "NeerajJWT", {expiresIn: "30s"});
        return res.json(accessToken);
    })

}

module.exports.verifyJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const authToken = authHeader && authHeader.split(" ")[1];
    if (authToken == null) return res.sendStatus(401);
    jwt.verify(authToken, "NeerajJWT", (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    })
}

module.exports.logout = (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.sendStatus(204);
}

const generateToken = (user, secret, options) => {
    return jwt.sign(user, secret, options)
}