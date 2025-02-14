const mongoose = require("mongoose")

const ProfileSchema = new mongoose.Schema({
    name : String,
    email : String,
    password : String
})

const ProfileModel = mongoose.model("account", ProfileSchema)

module.exports = ProfileModel
