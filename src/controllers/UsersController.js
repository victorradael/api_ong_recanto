const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const db = require("../db/mysql").pool;

exports.registerUser = (request, response) => {
  db.getConnection((err, conn) => {
    if (err) return response.status(500).json({ error: err });

    const allUsersQuery = "SELECT * FROM users WHERE email = ?";
    conn.query(allUsersQuery, [request.body.email], (error, results) => {
      if (error) {
        return response.status(500).json({
          error: error,
          response: null,
        });
      }

      if (results.length > 0) {
        return response.status(401).json({
          message: "This email already exists!",
        });
      } else {
        bcrypt.hash(request.body.password, 10, (errBcrypt, hash) => {
          if (errBcrypt) return response.status(500).json({ error: errBcrypt });
          const registerUserQuery =
            "INSERT INTO users (name, email, password, session) VALUES (?,?,?,?)";
          conn.query(
            registerUserQuery,
            [request.body.name, request.body.email, hash, request.body.session],
            (error, result, field) => {
              conn.release();

              if (error) {
                return response.status(500).json({
                  error: error,
                  response: null,
                });
              }

              return response.status(201).json({
                message: "Created!",
                user_id: result.insertId,
                email: request.body.email,
              });
            }
          );
        });
      }
    });
  });
};

exports.userLogin = (request, response) => {
  console.log(request.body);
  db.getConnection((error, conn) => {
    if (error) return response.status(500).json({ error: error });

    const loginEmailQuery = "SELECT * FROM users WHERE email = ?";
    conn.query(
      loginEmailQuery,
      [request.body.email],
      (error, results, fields) => {
        conn.release();
        if (error) return response.status(500).json({ error: error });
        if (results.length < 1) {
          return response
            .status(401)
            .json({ message: "Authentication Failed!" });
        }
        bcrypt.compare(
          request.body.password,
          results[0].password,
          (error, bcryptResult) => {
            if (error) {
              return response
                .status(401)
                .json({ message: "Authentication Failed!" });
            }
            if (bcryptResult) {
              let userToken = jwt.sign(
                {
                  user_id: results[0].id,
                  email: results[0].email,
                },
                process.env.JWT_KEY
              );

              const user = {
                userName: results[0].name,
                userEmail: results[0].email,
              };
              return response.status(200).json({
                message: "Authentication Success!",
                token: userToken,
                user,
              });
            }
            return response
              .status(401)
              .json({ message: "Authentication Failed!" });
          }
        );
      }
    );
  });
};
