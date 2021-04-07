//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");




const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));


app.use(session({
    secret: "our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
//////////to avoidwarning and errors///////////
mongoose.set("useCreateIndex", true);


const userSchema = new mongoose.Schema({
    email: String,
    password: String
});
///////////for using cookie and session we are using multiple passport packages and plugins////////////
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.get("/", function(req,res){
    res.render("home");
});

app.get("/login", function(req,res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});

app.get("/secrets", function(req,res){
    //////////to remove the cookie from browser once the user logout////////////////////
    res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stal   e=0, post-check=0, pre-check=0');
    if(req.isAuthenticated()){
        res.render("secrets");
    } else{
        res.redirect("/login");
    }

});




app.post("/register", function(req, res){

   User.register({username: req.body.username}, req.body.password, function(err, user){
       if(err){
           console.log(err);
           res.redirect("/register");
       }else{
           passport.authenticate("local")(req,res, function(){
               res.redirect("/secrets");
           });
       }
   });
});

/////// this cant be used because of login vulnerabilites explain below////////////////////////////

// app.post("/login", function(req,res){
   
//     const user = new User({
//         username: req.body.username,
//         password: req.body.password
//     })

//     req.login(user, function(err){
//         if(err){
//             console.log(err);
//         }else{
//                    //////this below code is vulenerable to the use. if you login. then logout and then enter the wrong password to while right email you will be sent an unauthorize text. but if try to visit the secrets route using url , you can stilla access the page.////////////////////////
//             passport.authenticate("local")(req,res, function(){
//                 res.redirect("/secrets");
//             }); 
//         }
//     })

// });

//////////////this is long but working method to avoid any kind of vulnerabilites while using the session. we also solved the problem of logout cookie deletion a bit above being mentioned//////////


app.post("/login", function(req, res){
    //check the DB to see if the username that was used to login exists in the DB
    User.findOne({username: req.body.username}, function(err, foundUser){
      //if username is found in the database, create an object called "user" that will store the username and password
      //that was used to login
      if(foundUser){
      const user = new User({
        username: req.body.username,
        password: req.body.password
      });
        //use the "user" object that was just created to check against the username and password in the database
        //in this case below, "user" will either return a "false" boolean value if it doesn't match, or it will
        //return the user found in the database
        passport.authenticate("local", function(err, user){
          if(err){
            console.log(err);
          } else {
            //this is the "user" returned from the passport.authenticate callback, which will be either
            //a false boolean value if no it didn't match the username and password or
            //a the user that was found, which would make it a truthy statement
            if(user){
              //if true, then log the user in, else redirect to login page
              req.login(user, function(err){
              res.redirect("/secrets");
              });
            } else {
              res.redirect("/login");
            }
          }
        })(req, res);
      //if no username is found at all, redirect to login page.
      } else {
        //user does not exists
        res.redirect("/login")
      }
    });
  });






app.get("/logout", function(req,res){
    req.logout();
    res.redirect("/");
});







app.listen(3000, function(){
    console.log("server started at port 3000.");
});
