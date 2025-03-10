const mongoose = require("mongoose")

const ExerciseSchema = new mongoose.Schema({
    id: String,
    name: String,
    muscle: String,
    gif_url: String,
    description1: String,
    description2: String,
    sets: Number,
    reps: Number
})

const DaySchema = new mongoose.Schema({
    name: String,
    exercises: [ExerciseSchema]
})

const WorkoutPlanSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'account',
        required: true
    },
    name: {
        type: String,
        required: true
    },
    description: String,
    days: [DaySchema],
    createdAt: {
        type: Date,
        default: Date.now
    }
})

const WorkoutPlanModel = mongoose.model("workoutplan", WorkoutPlanSchema)

module.exports = WorkoutPlanModel 