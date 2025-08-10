import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name:{ type: String, required: true},
    email:{ type: String, required: true, unique: true},
    password:{ type: String, required: true},
    verifyotp:{ type: String, default: "0"},
    verifyotpExpiry:{ type: Number, default: "0"},
    isVerified:{ type: Boolean, default: false},
    reserotp:{ type: String, default: "0"},
    resetotpExpiry:{ type: Number, default: "0"},
});

const usermodel = mongoose.models.user|| mongoose.model("users", userSchema);

export default usermodel;