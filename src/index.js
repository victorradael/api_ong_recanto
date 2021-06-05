require("dotenv").config({
  path: !(process.env.NODE_ENV === undefined)
    ? `.env.${process.env.NODE_ENV}`
    : ".env",
});
const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const usersRoutes = require("./routes/users");
const angelsRoutes = require("./routes/angels");

const port = process.env.PORT || 3000;

const app = express();

app.use(morgan("dev"));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cors());

app.use("/user", usersRoutes);
app.use("/angels", angelsRoutes);

app.use((request, response, next) => {
  const error = new Error("Route not found!");
  error.status = 404;
  next(error);
});

app.use((error, request, response, next) => {
  return response.status(error.status || 500).json({ error: error.message });
});

app.listen(port, () => {
  console.log(
    `API Online on http://localhost:${port} - ENV: ${
      process.env.NODE_ENV || "Prod"
    }!`
  );
});
