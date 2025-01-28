const User = require("../models/User");

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const jwtSecret = process.env.JWT_SECRET;

// Gerando o token do usuário
const generateToken = (id) => {
    return jwt.sign({ id }, jwtSecret, {
        expiresIn: "7d",
    });
};

// Registre o usuário e faça login
const register = async (req, res) => {
   const {name, email, password} = req.body 

   //check if user exists
   const user = await User.findOne({email})

   if(user){
        res.status(422).json({errors: ["Por favor, utilize outro e-mail"]})
        return
   }

   // Generate password hash
   const salt = await bcrypt.genSalt()
   const passwordHash = await bcrypt.hash(password, salt)

   // Create user
   const newUser = await User.create({
        name,
        email,
        password: passwordHash
   })

   // If user was created successfully, return the token
   if(!newUser){
        res.status(422).json({erros: ["Houve um erro, por favor tente mais tarde."]})
        return
   }

   res.status(201).json({
        _id: newUser._id,
        token: generateToken(newUser._id),
   });
};

module.exports = {
    register,
};
