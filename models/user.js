const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

//added an authentication level system (authLevel) incase a multi-tier clearance level system is needed.


const userSchema = mongoose.Schema({
    username:{
        type: String,
        require: true
    },
    email:{
        type: String,
        require: true
    },
    password:{
        type: String,
        require: true
    },
    authLevel:{
        type: Number
    }

});

const user = module.exports = mongoose.model('user', userSchema);

module.exports.addUser = function(newUser, callback){
    bcrypt.genSalt(10, (err, salt)=>{
        if (err) throw err;
        bcrypt.hash(newUser.password, salt, (err, hash)=>{
            newUser.password = hash;
            newUser.save(callback);
        });
    });
}

module.exports.getUserById = function(id, callback){
    user.findOne({_id: id}, callback);
}

module.exports.getUserByName = function(username, callback){
    user.findOne({username: username}, callback);
}

module.exports.comparePassword = function(recieved, hash, callback){
    bcrypt.compare(recieved, hash, callback);
}