const jwt = require("jsonwebtoken");

module.exports = (request, response, next) => {
  try {
    const userToken = request.headers.authorization.split(" ")[1];
    const decode = jwt.verify(userToken, process.env.JWT_KEY);
    request.user = decode;
    next();
  } catch (error) {
    return response.status(401).send({ message: "Authentication Failed!" });
  }
};
