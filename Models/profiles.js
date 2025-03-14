const mongoose = require("mongoose")

const ProfileSchema = new mongoose.Schema({
    name : String,
    email : String,
    password : String,
    // User preferences and fitness data
    weight: { type: Number, default: 0 }, // in kg
    height: { type: Number, default: 0 }, // in cm
    age: { type: Number, default: 0 },
    gender: { type: String, enum: ['male', 'female', 'other'], default: 'other' },
    activityLevel: { 
        type: String, 
        enum: ['sedentary', 'lightly active', 'moderately active', 'very active', 'extremely active'],
        default: 'moderately active'
    },
    dietType: { type: String, enum: ['vegetarian', 'non-vegetarian', 'vegan'], default: 'non-vegetarian' },
    fitnessGoals: { type: [String], default: ['weight maintenance'] },
    // Calculated values
    dailyCalorieNeeds: { type: Number, default: 0 },
    dailyProteinNeeds: { type: Number, default: 0 },
    dailyCarbsNeeds: { type: Number, default: 0 },
    dailyFatsNeeds: { type: Number, default: 0 }
})

const ProfileModel = mongoose.model("account", ProfileSchema)

module.exports = ProfileModel
