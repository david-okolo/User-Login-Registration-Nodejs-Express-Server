const express =  require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const cors = require("cors");
const bodyParser = require("body-parser");
const config = require("./config/database");

mongoose.connect(config.database, {useNewUrlParser: true});
mongoose.connection.on('connected', ()=>{
    console.log('Database connected')
});
mongoose.connection.on('error', (err)=>{
    console.log('Database error '+err)
});

const app = express();
const port = 3000; //specify what port to run on 

//middleware
app.use(cors());
app.use(bodyParser.json({type: "*/*"}));
app.use(passport.initialize());
app.use(passport.session());
require('./config/passport')(passport);

//add route files
const users = require('./routes/users');

app.use("/users", users);


//static folder
//app.use(express.static('../public'));

//index route
app.get('/', (req, res) => {
    res.send('index route');
});

app.listen(port, ()=>{
    console.log("Started on port " +port);
});
