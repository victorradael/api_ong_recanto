const resume = require("../docs/resume.json");

exports.showResume = (request, response) => {
  return response.status(200).json(resume);
};
